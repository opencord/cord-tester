/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ciena.xconnect;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.mastership.MastershipService;
import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.ImmutableSet;
import org.apache.felix.scr.annotations.*;
import org.onlab.packet.MacAddress;
import org.onlab.packet.VlanId;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.*;
import org.onosproject.net.flow.criteria.Criteria;
import org.onlab.util.KryoNamespace;
import org.onosproject.store.serializers.KryoNamespaces;
import org.onosproject.store.service.ConsistentMap;
import org.onosproject.store.service.Serializer;
import org.onosproject.store.service.StorageService;
import org.onosproject.net.config.ConfigFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private static final String NOT_MASTER = "Not master controller";

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    public FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected StorageService storageService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    public NetworkConfigRegistry networkConfig;

    private InternalNetworkConfigListener configListener =
            new InternalNetworkConfigListener();

    private ApplicationId appId;

    private KryoNamespace.Builder xConnectKryo;

    private ConsistentMap<XConnectStoreKey, NextObjective> xConnectNextObjStore;

    private static final Class<XConnectTestConfig> XCONNECT_TEST_CONFIG_CLASS = XConnectTestConfig.class;

    private ConfigFactory<ApplicationId, XConnectTestConfig> xconnectTestConfigFactory =
            new ConfigFactory<ApplicationId, XConnectTestConfig>(
                    SubjectFactories.APP_SUBJECT_FACTORY, XCONNECT_TEST_CONFIG_CLASS, "xconnectTestConfig") {
                @Override
                public XConnectTestConfig createConfig() {
                    return new XConnectTestConfig();
                }
            };

    @Activate
    protected void activate() {
        log.info("Started");
        appId = coreService.registerApplication("org.ciena.xconnect");

        xConnectKryo = new KryoNamespace.Builder()
                .register(KryoNamespaces.API)
                .register(XConnectStoreKey.class)
                .register(NextObjContext.class);

        xConnectNextObjStore = storageService
                .<XConnectStoreKey, NextObjective>consistentMapBuilder()
                .withName("cordtester-xconnect-nextobj-store")
                .withSerializer(Serializer.using(xConnectKryo.build()))
                .build();

        networkConfig.addListener(configListener);
        networkConfig.registerConfigFactory(xconnectTestConfigFactory);

        XConnectTestConfig config = networkConfig.getConfig(appId, XConnectTestConfig.class);

        if (config != null) {
            config.getXconnects().forEach(key -> {
                    populateXConnect(key, config.getPorts(key));
                });
        }
    }

    @Deactivate
    protected void deactivate() {
        log.info("Stopped");
        networkConfig.removeListener(configListener);
        XConnectTestConfig config = networkConfig.getConfig(appId, XConnectTestConfig.class);
        //remove flows on app deactivate
        if (config != null) {
            config.getXconnects().forEach(key -> {
                    revokeXConnect(key, config.getPorts(key));
                });
        }
        networkConfig.unregisterConfigFactory(xconnectTestConfigFactory);
    }

    /**
     * Populates XConnect groups and flows for given key.
     *
     * @param key XConnect key
     * @param ports a set of ports to be cross-connected
     */
    private void populateXConnect(XConnectStoreKey key, Set<PortNumber> ports) {
        if (!mastershipService.isLocalMaster(key.deviceId())) {
            log.info("Abort populating XConnect {}: {}", key, NOT_MASTER);
            return;
        }
        populateFilter(key, ports);
        populateFwd(key, populateNext(key, ports));
    }

    private void populateFilter(XConnectStoreKey key, Set<PortNumber> ports) {
        ports.forEach(port -> {
            FilteringObjective.Builder filtObjBuilder = filterObjBuilder(key, port);
            ObjectiveContext context = new DefaultObjectiveContext(
                    (objective) -> log.debug("XConnect FilterObj for {} on port {} populated",
                            key, port),
                    (objective, error) ->
                            log.warn("Failed to populate XConnect FilterObj for {} on port {}: {}",
                                    key, port, error));
            flowObjectiveService.filter(key.deviceId(), filtObjBuilder.add(context));
        });
    }

    private FilteringObjective.Builder filterObjBuilder(XConnectStoreKey key, PortNumber port) {
        FilteringObjective.Builder fob = DefaultFilteringObjective.builder();
        fob.withKey(Criteria.matchInPort(port))
                .addCondition(Criteria.matchVlanId(key.vlanId()))
                .addCondition(Criteria.matchEthDst(MacAddress.NONE))
                .withPriority(1234);
        return fob.permit().fromApp(appId);
    }

    private NextObjective populateNext(XConnectStoreKey key, Set<PortNumber> ports) {
        NextObjective nextObj = null;
        if (xConnectNextObjStore.containsKey(key)) {
            nextObj = xConnectNextObjStore.get(key).value();
            log.debug("NextObj for {} found, id={}", key, nextObj.id());
        } else {
            NextObjective.Builder nextObjBuilder = nextObjBuilder(key, ports);
            ObjectiveContext nextContext = new NextObjContext(Objective.Operation.ADD, key);
            nextObj = nextObjBuilder.add(nextContext);
            flowObjectiveService.next(key.deviceId(), nextObj);
            xConnectNextObjStore.put(key, nextObj);
            log.info("NextObj for {} not found. Creating new NextObj with id={}", key, nextObj.id());
        }
        return nextObj;
    }

    private NextObjective.Builder nextObjBuilder(XConnectStoreKey key, Set<PortNumber> ports) {
        int nextId = flowObjectiveService.allocateNextId();
        TrafficSelector metadata =
                DefaultTrafficSelector.builder().matchVlanId(key.vlanId()).build();
        NextObjective.Builder nextObjBuilder = DefaultNextObjective
                .builder().withId(nextId)
                .withType(NextObjective.Type.BROADCAST).fromApp(appId)
                .withMeta(metadata);
        ports.forEach(port -> {
            TrafficTreatment.Builder tBuilder = DefaultTrafficTreatment.builder();
            tBuilder.setOutput(port);
            nextObjBuilder.addTreatment(tBuilder.build());
        });
        return nextObjBuilder;
    }

    private void populateFwd(XConnectStoreKey key, NextObjective nextObj) {
        ForwardingObjective.Builder fwdObjBuilder = fwdObjBuilder(key, nextObj.id());
        ObjectiveContext fwdContext = new DefaultObjectiveContext(
                (objective) -> log.debug("XConnect FwdObj for {} populated", key),
                (objective, error) ->
                        log.warn("Failed to populate XConnect FwdObj for {}: {}", key, error));
        flowObjectiveService.forward(key.deviceId(), fwdObjBuilder.add(fwdContext));
    }

    private ForwardingObjective.Builder fwdObjBuilder(XConnectStoreKey key, int nextId) {
        /*
         * Driver should treat objectives with MacAddress.NONE and !VlanId.NONE
         * as the VLAN cross-connect broadcast rules
         */
        TrafficSelector.Builder sbuilder = DefaultTrafficSelector.builder();
        sbuilder.matchVlanId(key.vlanId());
        sbuilder.matchEthDst(MacAddress.NONE);

        ForwardingObjective.Builder fob = DefaultForwardingObjective.builder();
        fob.withFlag(ForwardingObjective.Flag.SPECIFIC)
                .withSelector(sbuilder.build())
                .nextStep(nextId)
                .withPriority(32768)
                .fromApp(appId)
                .makePermanent();
        return fob;
    }

    /**
     * Processes Segment Routing App Config added event.
     *
     * @param event network config added event
     */
    protected void processXConnectConfigAdded(NetworkConfigEvent event) {
        log.info("Processing XConnect CONFIG_ADDED");
        XConnectTestConfig config = (XConnectTestConfig) event.config().get();
        config.getXconnects().forEach(key -> {
            populateXConnect(key, config.getPorts(key));
        });
    }

    /**
     * Processes Segment Routing App Config removed event.
     *
     * @param event network config removed event
     */
    protected void processXConnectConfigRemoved(NetworkConfigEvent event) {
        log.info("Processing XConnect CONFIG_REMOVED");
        XConnectTestConfig prevConfig = (XConnectTestConfig) event.prevConfig().get();
        prevConfig.getXconnects().forEach(key -> {
            revokeXConnect(key, prevConfig.getPorts(key));
        });
    }

    /**
     * Revokes filtering objectives for given XConnect.
     *
     * @param key XConnect store key
     * @param ports XConnect ports
     */
    private void revokeFilter(XConnectStoreKey key, Set<PortNumber> ports) {
        ports.forEach(port -> {
            FilteringObjective.Builder filtObjBuilder = filterObjBuilder(key, port);
            ObjectiveContext context = new DefaultObjectiveContext(
                    (objective) -> log.debug("XConnect FilterObj for {} on port {} revoked",
                            key, port),
                    (objective, error) ->
                            log.warn("Failed to revoke XConnect FilterObj for {} on port {}: {}",
                                    key, port, error));
            flowObjectiveService.filter(key.deviceId(), filtObjBuilder.remove(context));
        });
    }

    /**
     * Revokes next objectives for given XConnect.
     *
     * @param key XConnect store key
     * @param nextObj next objective
     * @param nextFuture completable future for this next objective operation
     */
    private void revokeNext(XConnectStoreKey key, NextObjective nextObj,
            CompletableFuture<ObjectiveError> nextFuture) {
        ObjectiveContext context = new ObjectiveContext() {
            @Override
            public void onSuccess(Objective objective) {
                log.debug("Previous NextObj for {} removed", key);
                if (nextFuture != null) {
                    nextFuture.complete(null);
                }
            }

            @Override
            public void onError(Objective objective, ObjectiveError error) {
                log.warn("Failed to remove previous NextObj for {}: {}", key, error);
                if (nextFuture != null) {
                    nextFuture.complete(error);
                }
            }
        };
        flowObjectiveService.next(key.deviceId(),
                                  (NextObjective) nextObj.copy().remove(context));
        xConnectNextObjStore.remove(key);
    }

    /**
     * Revokes forwarding objectives for given XConnect.
     *
     * @param key XConnect store key
     * @param nextObj next objective
     * @param fwdFuture completable future for this forwarding objective operation
     */
    private void revokeFwd(XConnectStoreKey key, NextObjective nextObj,
            CompletableFuture<ObjectiveError> fwdFuture) {
        ForwardingObjective.Builder fwdObjBuilder = fwdObjBuilder(key, nextObj.id());
        ObjectiveContext context = new ObjectiveContext() {
            @Override
            public void onSuccess(Objective objective) {
                log.debug("Previous FwdObj for {} removed", key);
                if (fwdFuture != null) {
                    fwdFuture.complete(null);
                }
            }

            @Override
            public void onError(Objective objective, ObjectiveError error) {
                log.warn("Failed to remove previous FwdObj for {}: {}", key, error);
                if (fwdFuture != null) {
                    fwdFuture.complete(error);
                }
            }
        };
        flowObjectiveService
            .forward(key.deviceId(), fwdObjBuilder.remove(context));
    }

    private void revokeXConnect(XConnectStoreKey key, Set<PortNumber> ports) {
        if (!mastershipService.isLocalMaster(key.deviceId())) {
            log.info("Abort populating XConnect {}: {}", key, NOT_MASTER);
            return;
        }
        revokeFilter(key, ports);
        if (xConnectNextObjStore.containsKey(key)) {
            NextObjective nextObj = xConnectNextObjStore.get(key).value();
            revokeFwd(key, nextObj, null);
            revokeNext(key, nextObj, null);
        } else {
            log.warn("NextObj for {} does not exist in the store.", key);
        }
    }

    private final class NextObjContext implements ObjectiveContext {
        Objective.Operation op;
        XConnectStoreKey key;

        private NextObjContext(Objective.Operation op, XConnectStoreKey key) {
            this.op = op;
            this.key = key;
        }

        @Override
        public void onSuccess(Objective objective) {
            log.debug("XConnect NextObj for {} {}ED", key, op);
        }

        @Override
        public void onError(Objective objective, ObjectiveError error) {
            log.warn("Failed to {} XConnect NextObj for {}: {}", op, key, error);
        }
    }

    private class InternalNetworkConfigListener implements NetworkConfigListener {

        @Override
        public void event(NetworkConfigEvent event) {
            if (event.configClass().equals(XCONNECT_TEST_CONFIG_CLASS)) {
                switch (event.type()) {
                    case CONFIG_ADDED:
                        processXConnectConfigAdded(event);
                        break;
                    case CONFIG_UPDATED:
                        log.info("CONFIG UPDATED event is unhandled");
                        break;
                    case CONFIG_REMOVED:
                        processXConnectConfigRemoved(event);
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
