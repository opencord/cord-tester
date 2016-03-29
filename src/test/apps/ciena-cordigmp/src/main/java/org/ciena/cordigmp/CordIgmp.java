/*
 * Copyright 2015-2016 Open Networking Laboratory
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
package org.ciena.cordigmp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Multiset;
import com.google.common.collect.ConcurrentHashMultiset;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Modified;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onlab.packet.IpAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.codec.CodecService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import org.onosproject.net.config.basics.SubjectFactories;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.DefaultFlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.DefaultNextObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.NextObjective;
import org.onosproject.net.flowobjective.Objective;
import org.onosproject.net.flowobjective.ObjectiveContext;
import org.onosproject.net.flowobjective.ObjectiveError;
import org.onosproject.net.mcast.McastEvent;
import org.onosproject.net.mcast.McastListener;
import org.onosproject.net.mcast.McastRoute;
import org.onosproject.net.mcast.McastRouteInfo;
import org.onosproject.net.mcast.MulticastRouteService;
import org.onosproject.olt.AccessDeviceConfig;
import org.onosproject.olt.AccessDeviceData;
import org.onosproject.rest.AbstractWebResource;
import org.osgi.service.component.ComponentContext;
import org.onosproject.net.PortNumber;
import org.onlab.packet.IPv4;
import org.slf4j.Logger;

import java.io.IOException;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;
import java.util.Collection;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Strings.isNullOrEmpty;
import static org.onlab.util.Tools.get;
import static org.slf4j.LoggerFactory.getLogger;

/**
 * CORD multicast provisioning application. Operates by listening to
 * events on the multicast rib and provisioning groups to program multicast
 * flows on the dataplane.
 */
@Component(immediate = true)
public class CordIgmp {


    private static final int DEFAULT_REST_TIMEOUT_MS = 2000;
    private static final int DEFAULT_PRIORITY = 500;
    private static final short DEFAULT_MCAST_VLAN = 4000;
    private static final String DEFAULT_SYNC_HOST = "localhost:8181";
    private static final String DEFAULT_USER = "karaf";
    private static final String DEFAULT_PASSWORD = "karaf";
    private static final boolean DEFAULT_VLAN_ENABLED = true;
    private static final short DEFAULT_INPUT_PORT = 2;
    private static final short DEFAULT_OUTPUT_PORT = 1;
    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected MulticastRouteService mcastService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CodecService codecService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService componentConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected NetworkConfigRegistry networkConfig;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

    protected McastListener listener = new InternalMulticastListener();
    private InternalNetworkConfigListener configListener =
            new InternalNetworkConfigListener();
    private DeviceListener deviceListener = new InternalDeviceListener();

    //Map of IGMP groups to port
    private Map<IpAddress, IgmpPortPair> cordIgmpTranslateTable = Maps.newConcurrentMap();

    //Count of group joins
    private Multiset<IpAddress> cordIgmpCountTable = ConcurrentHashMultiset.create();
    
    //TODO: move this to distributed atomic long
    private AtomicInteger channels = new AtomicInteger(0);

    private ApplicationId appId;

    @Property(name = "mcastVlan", intValue = DEFAULT_MCAST_VLAN,
            label = "VLAN for multicast traffic")
    private int mcastVlan = DEFAULT_MCAST_VLAN;

    @Property(name = "vlanEnabled", boolValue = DEFAULT_VLAN_ENABLED,
            label = "Use vlan for multicast traffic?")
    private boolean vlanEnabled = DEFAULT_VLAN_ENABLED;

    @Property(name = "priority", intValue = DEFAULT_PRIORITY,
            label = "Priority for multicast rules")
    private int priority = DEFAULT_PRIORITY;

    @Property(name = "syncHost", value = DEFAULT_SYNC_HOST,
            label = "host:port to synchronize routes to")
    private String syncHost = DEFAULT_SYNC_HOST;

    @Property(name = "username", value = DEFAULT_USER,
            label = "Username for REST password authentication")
    private String user = DEFAULT_USER;

    @Property(name = "password", value = DEFAULT_PASSWORD,
            label = "Password for REST authentication")
    private String password = DEFAULT_PASSWORD;

    @Property(name = "inputPort", intValue = DEFAULT_INPUT_PORT,
              label = "Input port for OVS multicast traffic")
    private int inputPort = DEFAULT_INPUT_PORT;

    @Property(name = "outputPort", intValue = DEFAULT_OUTPUT_PORT,
              label = "Output port for OVS multicast traffic")
    private int outputPort = DEFAULT_OUTPUT_PORT;

    private String fabricOnosUrl;

    private Map<DeviceId, AccessDeviceData> oltData = new ConcurrentHashMap<>();

    private Map<DeviceId, Boolean> deviceAvailability = new ConcurrentHashMap<>();

    private static final Class<CordIgmpTranslateConfig> CORD_IGMP_TRANSLATE_CONFIG_CLASS =
            CordIgmpTranslateConfig.class;

    private ConfigFactory<ApplicationId, CordIgmpTranslateConfig> cordIgmpTranslateConfigFactory =
            new ConfigFactory<ApplicationId, CordIgmpTranslateConfig>(
                    SubjectFactories.APP_SUBJECT_FACTORY, CORD_IGMP_TRANSLATE_CONFIG_CLASS, "cordIgmpTranslate", true) {
                @Override
                public CordIgmpTranslateConfig createConfig() {
                    return new CordIgmpTranslateConfig();
                }
            };


    @Activate
    public void activate(ComponentContext context) {
        componentConfigService.registerProperties(getClass());
        modified(context);

        appId = coreService.registerApplication("org.ciena.cordigmp");

        networkConfig.registerConfigFactory(cordIgmpTranslateConfigFactory);
        networkConfig.addListener(configListener);

        networkConfig.getSubjects(DeviceId.class, AccessDeviceConfig.class).forEach(
                subject -> {
                    AccessDeviceConfig config = networkConfig.getConfig(subject, AccessDeviceConfig.class);
                    if (config != null) {
                        AccessDeviceData data = config.getOlt();
                        oltData.put(data.deviceId(), data);
                    }
                }
        );

        CordIgmpTranslateConfig cordIgmpTranslateConfig = networkConfig.getConfig(appId, CordIgmpTranslateConfig.class);

        if(cordIgmpTranslateConfig != null) {
            Collection<McastPorts> translations = cordIgmpTranslateConfig.getCordIgmpTranslations();
            for(McastPorts port: translations) {
                cordIgmpTranslateTable.put(port.group(), 
                                           port.portPair());
            }
        }

        mcastService.addListener(listener);

        mcastService.getRoutes().stream()
                .map(r -> new ImmutablePair<>(r, mcastService.fetchSinks(r)))
                .filter(pair -> pair.getRight() != null && !pair.getRight().isEmpty())
                .forEach(pair -> pair.getRight().forEach(sink -> provisionGroup(pair.getLeft(),
                                                                                sink)));

        deviceService.addListener(deviceListener);

        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        componentConfigService.unregisterProperties(getClass(), false);
        deviceService.removeListener(deviceListener);
        mcastService.removeListener(listener);
        networkConfig.unregisterConfigFactory(cordIgmpTranslateConfigFactory);
        networkConfig.removeListener(configListener);
        deviceAvailability.clear();
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();

        try {
            String s = get(properties, "username");
            user = isNullOrEmpty(s) ? DEFAULT_USER : s.trim();

            s = get(properties, "password");
            password = isNullOrEmpty(s) ? DEFAULT_PASSWORD : s.trim();

            s = get(properties, "mcastVlan");
            mcastVlan = isNullOrEmpty(s) ? DEFAULT_MCAST_VLAN : Short.parseShort(s.trim());

            s = get(properties, "vlanEnabled");
            vlanEnabled = isNullOrEmpty(s) ? DEFAULT_VLAN_ENABLED : Boolean.parseBoolean(s.trim());

            s = get(properties, "priority");
            priority = isNullOrEmpty(s) ? DEFAULT_PRIORITY : Integer.parseInt(s.trim());

            s = get(properties, "syncHost");
            syncHost = isNullOrEmpty(s) ? DEFAULT_SYNC_HOST : s.trim();
            log.warn("Sync Host = " + syncHost);

            s = get(properties, "inputPort");
            inputPort = isNullOrEmpty(s) ? DEFAULT_INPUT_PORT : Short.parseShort(s.trim());

            s = get(properties, "outputPort");
            outputPort = isNullOrEmpty(s) ? DEFAULT_OUTPUT_PORT : Short.parseShort(s.trim());

        } catch (Exception e) {
            user = DEFAULT_USER;
            password = DEFAULT_PASSWORD;
            syncHost = DEFAULT_SYNC_HOST;
            mcastVlan = DEFAULT_MCAST_VLAN;
            vlanEnabled = false;
            priority = DEFAULT_PRIORITY;
            inputPort = DEFAULT_INPUT_PORT;
            outputPort = DEFAULT_OUTPUT_PORT;
        }
        fabricOnosUrl = createRemoteUrl(syncHost);
    }

    private static String createRemoteUrl(String remoteHost) {
        return "http://" + remoteHost + "/onos/v1/mcast";
    }

    private class InternalMulticastListener implements McastListener {
        @Override
        public void event(McastEvent event) {
            McastRouteInfo info = event.subject();
            switch (event.type()) {
                case ROUTE_ADDED:
                    break;
                case ROUTE_REMOVED:
                    break;
                case SOURCE_ADDED:
                    break;
                case SINK_ADDED:
                    if (!info.sink().isPresent()) {
                        log.warn("No sink given after sink added event: {}", info);
                        return;
                    }
                    provisionGroup(info.route(), info.sink().get());
                    break;
                case SINK_REMOVED:
                    unprovisionGroup(event.subject());
                    break;
                default:
                    log.warn("Unknown mcast event {}", event.type());
            }
        }
    }
    
    private void provisionFilterIgmp(DeviceId devId, boolean remove) {
        Boolean deviceStatus = deviceAvailability.get(devId);
        if(deviceStatus != null) {
            if(remove == false) {
                return;
            }
        } else if(remove == true) {
            return;
        }
        TrafficSelector.Builder igmp = DefaultTrafficSelector.builder()
            .matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol(IPv4.PROTOCOL_IGMP);
        TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder()
            .setOutput(PortNumber.CONTROLLER);
        FlowEntry.Builder flowEntry = DefaultFlowEntry.builder();
        flowEntry.forDevice(devId);
        flowEntry.withPriority(priority);
        flowEntry.withSelector(igmp.build());
        flowEntry.withTreatment(treatment.build());
        flowEntry.fromApp(appId);
        flowEntry.makePermanent();
        if(remove == false) {
            deviceAvailability.put(devId, true);
            flowRuleService.applyFlowRules(flowEntry.build());
        } else {
            deviceAvailability.remove(devId);
            flowRuleService.removeFlowRules(flowEntry.build());
        }
        log.warn("IGMP flow rule " + ( remove ? "removed" : "added" ) + " for device id " + devId);
    }

    private class InternalDeviceListener implements DeviceListener {
        @Override
        public void event(DeviceEvent event) {
            DeviceId devId = event.subject().id();
            switch (event.type()) {

                case DEVICE_ADDED:
                case DEVICE_UPDATED:
                    provisionFilterIgmp(devId, false);
                    break;
                case DEVICE_AVAILABILITY_CHANGED:
                    if(deviceService.isAvailable(devId)) {
                        provisionFilterIgmp(devId, false);
                    } else {
                        provisionFilterIgmp(devId, true);
                    }
                    break;
                case DEVICE_REMOVED:
                case DEVICE_SUSPENDED:
                    provisionFilterIgmp(devId, true);
                    break;
                case PORT_STATS_UPDATED:
                case PORT_ADDED:
                case PORT_UPDATED:
                case PORT_REMOVED:
                    //log.debug("Got event " + event.type() + " for device " + devId);
                    break;
                default:
                    log.warn("Unknown device event {}", event.type());
                    break;
            }
        }
    }

    private void unprovisionGroup(McastRouteInfo info) {
        if (!info.sink().isPresent()) {
            log.warn("No sink given after sink removed event: {}", info);
            return;
        }
        ConnectPoint loc = info.sink().get();
        AccessDeviceData oltInfo = oltData.get(loc.deviceId());
        if(oltInfo != null) {
            log.warn("Ignoring deprovisioning mcast route for OLT device: " + loc.deviceId());
            return;
        }
        final IgmpPortPair portPair = cordIgmpTranslateTable.get(info.route().group());
        if(portPair == null) {
            log.warn("Ignoring unprovisioning for group " + info.route().group() + " with no port map");
            return;
        }
        if(cordIgmpCountTable.remove(info.route().group(), 1) <= 1) {
            //Remove flow for last channel leave
            final PortNumber inPort = PortNumber.portNumber(portPair.inputPort());
            final PortNumber outPort = PortNumber.portNumber(portPair.outputPort());
            TrafficSelector.Builder mcast = DefaultTrafficSelector.builder()
                .matchInPort(inPort)
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPDst(info.route().group().toIpPrefix());
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            FlowEntry.Builder flowEntry = DefaultFlowEntry.builder();
            treatment.add(Instructions.createOutput(outPort));
            flowEntry.forDevice(loc.deviceId());
            flowEntry.withPriority(priority);
            flowEntry.withSelector(mcast.build());
            flowEntry.withTreatment(treatment.build());
            flowEntry.fromApp(appId);
            flowEntry.makePermanent();
            flowRuleService.removeFlowRules(flowEntry.build());
            log.warn("Flow rule removed for for device id " + loc.deviceId());
        }
    }

    private void provisionGroup(McastRoute route, ConnectPoint sink) {
        checkNotNull(route, "Route cannot be null");
        checkNotNull(sink, "Sink cannot be null");

        AccessDeviceData oltInfo = oltData.get(sink.deviceId());
        if(oltInfo != null) {
            log.warn("Ignoring provisioning mcast route for OLT device: " + sink.deviceId());
            return;
        } 
        final IgmpPortPair portPair = cordIgmpTranslateTable.get(route.group());
        if(portPair == null) {
            log.warn("Ports for Group " + route.group() + " not found in cord igmp map. Skipping provisioning.");
            return;
        }
        if(cordIgmpCountTable.count(route.group()) == 0) {
            //First group entry. Provision the flows
            final PortNumber inPort = PortNumber.portNumber(portPair.inputPort());
            final PortNumber outPort = PortNumber.portNumber(portPair.outputPort());
            TrafficSelector.Builder mcast = DefaultTrafficSelector.builder()
                    .matchInPort(inPort)
                    .matchEthType(Ethernet.TYPE_IPV4)
                    .matchIPDst(route.group().toIpPrefix());
            TrafficTreatment.Builder treatment = DefaultTrafficTreatment.builder();
            FlowEntry.Builder flowEntry = DefaultFlowEntry.builder();
            treatment.add(Instructions.createOutput(outPort));
            flowEntry.forDevice(sink.deviceId());
            flowEntry.withPriority(priority);
            flowEntry.withSelector(mcast.build());
            flowEntry.withTreatment(treatment.build());
            flowEntry.fromApp(appId);
            flowEntry.makePermanent();
            flowRuleService.applyFlowRules(flowEntry.build());
            log.warn("Flow rules applied for device id " + sink.deviceId());
        }
        cordIgmpCountTable.add(route.group());
    }

    private class InternalNetworkConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            switch (event.type()) {

                case CONFIG_ADDED:
                case CONFIG_UPDATED:
                    if (event.configClass().equals(CORD_IGMP_TRANSLATE_CONFIG_CLASS)) {
                        CordIgmpTranslateConfig config =
                                networkConfig.getConfig((ApplicationId) event.subject(),
                                        CORD_IGMP_TRANSLATE_CONFIG_CLASS);
                        if (config != null) {
                            cordIgmpTranslateTable.clear();
                            cordIgmpCountTable.clear();
                            config.getCordIgmpTranslations().forEach(
                                                                     mcastPorts -> cordIgmpTranslateTable.put(mcastPorts.group(), mcastPorts.portPair()));
                        }
                    }
                    break;
                case CONFIG_REGISTERED:
                case CONFIG_UNREGISTERED:
                case CONFIG_REMOVED:
                    break;
                default:
                    break;
            }
        }

        //@Override
        //public boolean isRelevant(NetworkConfigEvent event) {
        //    return event.configClass().equals(CORD_IGMP_TRANSLATE_CONFIG_CLASS);
        //}


    }

}
