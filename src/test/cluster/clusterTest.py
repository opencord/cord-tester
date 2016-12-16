#copyright 2016-present Ciena Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import unittest
from nose.tools import *
from scapy.all import *
from OnosCtrl import OnosCtrl, get_mac
from OltConfig import OltConfig
from socket import socket
from OnosFlowCtrl import OnosFlowCtrl
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from onosclidriver import OnosCliDriver
from CordContainer import Container, Onos, Quagga
from CordTestServer import cord_test_onos_restart, cord_test_onos_shutdown, cord_test_onos_add_cluster, cord_test_quagga_restart, cord_test_restart_cluster
from portmaps import g_subscriber_port_map
from scapy.all import *
import time, monotonic
import threading
from threading import current_thread
from Cluster import *
from EapTLS import TLSAuthTest
from ACL import ACLTest
from OnosLog import OnosLog
from CordLogger import CordLogger
import os
import json
import random
import collections
log.setLevel('INFO')

class cluster_exchange(CordLogger):
    test_path = os.path.dirname(os.path.realpath(__file__))
    onos_config_path = os.path.join(test_path, '..', 'setup/onos-config')
    mac = RandMAC()._fix()
    flows_eth = Ether(src = RandMAC()._fix(), dst = RandMAC()._fix())
    igmp_eth = Ether(dst = '01:00:5e:00:00:16', type = ETH_P_IP)
    igmp_ip = IP(dst = '224.0.0.22')
    ONOS_INSTANCES = 3
    V_INF1 = 'veth0'
    TLS_TIMEOUT = 100
    device_id = 'of:' + get_mac()
    igmp = cluster_igmp()
    igmp_groups = igmp.mcast_ip_range(start_ip = '224.1.8.10',end_ip = '224.1.10.49')
    igmp_sources = igmp.source_ip_range(start_ip = '38.24.29.35',end_ip='38.24.35.56')
    tls = cluster_tls()
    flows = cluster_flows()
    proxyarp = cluster_proxyarp()
    vrouter = cluster_vrouter()
    acl = cluster_acl()
    dhcprelay = cluster_dhcprelay()
    subscriber = cluster_subscriber()
    testcaseLoggers = ('test_cluster_controller_restarts', 'test_cluster_graceful_controller_restarts',
                       'test_cluster_single_controller_restarts', 'test_cluster_restarts')

    def setUp(self):
        if self._testMethodName not in self.testcaseLoggers:
            super(cluster_exchange, self).setUp()

    def tearDown(self):
        if self._testMethodName not in self.testcaseLoggers:
            super(cluster_exchange, self).tearDown()

    def get_controller(self):
        controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
        controller = controller.split(',')[0]
        return controller

    @classmethod
    def get_controllers(cls):
        controllers = os.getenv('ONOS_CONTROLLER_IP') or ''
        return controllers.split(',')

    def cliEnter(self, controller = None):
        retries = 0
        while retries < 30:
            self.cli = OnosCliDriver(controller = controller, connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

    def get_leader(self, controller = None):
        self.cliEnter(controller = controller)
        try:
            result = json.loads(self.cli.leaders(jsonFormat = True))
        except:
            result = None

        if result is None:
            log.info('Leaders command failure for controller %s' %controller)
        else:
            log.info('Leaders returned: %s' %result)
        self.cliExit()
        return result

    def onos_shutdown(self, controller = None):
        status = True
        self.cliEnter(controller = controller)
        try:
            self.cli.shutdown(timeout = 10)
        except:
            log.info('Graceful shutdown of ONOS failed for controller: %s' %controller)
            status = False

        self.cliExit()
        return status

    def log_set(self, level = None, app = 'org.onosproject', controllers = None):
        CordLogger.logSet(level = level, app = app, controllers = controllers, forced = True)

    def get_leaders(self, controller = None):
        result_map = {}
        if controller is None:
            controller = self.get_controller()
        if type(controller) in [ list, tuple ]:
            for c in controller:
                leaders = self.get_leader(controller = c)
                result_map[c] = leaders
        else:
            leaders = self.get_leader(controller = controller)
            result_map[controller] = leaders
        return result_map

    def verify_leaders(self, controller = None):
        leaders_map = self.get_leaders(controller = controller)
        failed = [ k for k,v in leaders_map.items() if v == None ]
        return failed

    def verify_cluster_status(self,controller = None,onos_instances=ONOS_INSTANCES,verify=False):
	tries = 0
	try:
            self.cliEnter(controller = controller)
	    while tries <= 10:
                cluster_summary = json.loads(self.cli.summary(jsonFormat = True))
                if cluster_summary:
	            log.info("cluster 'summary' command output is %s"%cluster_summary)
		    nodes = cluster_summary['nodes']
		    if verify:
		        if nodes == onos_instances:
		            self.cliExit()
		            return True
		        else:
		            tries += 1
		            time.sleep(1)
		    else:
			if nodes >= onos_instances:
                            self.cliExit()
                            return True
                        else:
                            tries += 1
                            time.sleep(1)
	        else:
	            tries += 1
	            time.sleep(1)
	    self.cliExit()
	    return False
        except:
            raise Exception('Failed to get cluster members')
	    return False

    def get_cluster_current_member_ips(self, controller = None, nodes_filter = None):
        tries = 0
	cluster_ips = []
        try:
            self.cliEnter(controller = controller)
            while tries <= 10:
                cluster_nodes = json.loads(self.cli.nodes(jsonFormat = True))
                if cluster_nodes:
                    log.info("cluster 'nodes' output is %s"%cluster_nodes)
                    if nodes_filter:
                        cluster_nodes = nodes_filter(cluster_nodes)
                    cluster_ips = map(lambda c: c['id'], cluster_nodes)
		    self.cliExit()
                    cluster_ips.sort(lambda i1,i2: int(i1.split('.')[-1]) - int(i2.split('.')[-1]))
		    return cluster_ips
		else:
		    tries += 1
	    self.cliExit()
	    return cluster_ips
        except:
            raise Exception('Failed to get cluster members')
            return cluster_ips

    def get_cluster_container_names_ips(self,controller=None):
        onos_names_ips = {}
        controllers = self.get_controllers()
        i = 0
        for controller in controllers:
            if i == 0:
                name = Onos.NAME
            else:
                name = '{}-{}'.format(Onos.NAME, i+1)
            onos_names_ips[controller] = name
            onos_names_ips[name] = controller
            i += 1
        return onos_names_ips
        # onos_ips = self.get_cluster_current_member_ips(controller=controller)
        # onos_names_ips[onos_ips[0]] = Onos.NAME
        # onos_names_ips[Onos.NAME] = onos_ips[0]
        # for i in range(1,len(onos_ips)):
        #     name = '{0}-{1}'.format(Onos.NAME,i+1)
        #     onos_names_ips[onos_ips[i]] = name
        #     onos_names_ips[name] = onos_ips[i]

        # return onos_names_ips

    #identifying current master of a connected device, not tested
    def get_cluster_current_master_standbys(self,controller=None,device_id=device_id):
	master = None
	standbys = []
	tries = 0
	try:
	    cli = self.cliEnter(controller = controller)
	    while tries <= 10:
	        roles = json.loads(self.cli.roles(jsonFormat = True))
	        log.info("cluster 'roles' command output is %s"%roles)
	        if roles:
	            for device in roles:
	                log.info('Verifying device info in line %s'%device)
	                if device['id'] == device_id:
	                    master = str(device['master'])
		            standbys = map(lambda d: str(d), device['standbys'])
		            log.info('Master and standbys for device %s are %s and %s'%(device_id, master, standbys))
			    self.cliExit()
		            return master, standbys
		    self.cliExit()
		    return master, standbys
	        else:
		    tries += 1
		    time.sleep(1)
	    self.cliExit()
	    return master,standbys
	except:
            raise Exception('Failed to get cluster members')
	    return master,standbys

    def get_cluster_current_master_standbys_of_connected_devices(self,controller=None):
	''' returns master and standbys of all the connected devices to ONOS cluster instance'''
        device_dict = {}
        tries = 0
        try:
            cli = self.cliEnter(controller = controller)
            while tries <= 10:
		device_dict = {}
                roles = json.loads(self.cli.roles(jsonFormat = True))
                log.info("cluster 'roles' command output is %s"%roles)
                if roles:
                    for device in roles:
			device_dict[str(device['id'])]= {'master':str(device['master']),'standbys':device['standbys']}
                        for i in range(len(device_dict[device['id']]['standbys'])):
			    device_dict[device['id']]['standbys'][i] = str(device_dict[device['id']]['standbys'][i])
                        log.info('master and standbys for device %s are %s and %s'%(device['id'],device_dict[device['id']]['master'],device_dict[device['id']]['standbys']))
                    self.cliExit()
                    return device_dict
                else:
                    tries += 1
                    time.sleep(1)
            self.cliExit()
            return device_dict
        except:
            raise Exception('Failed to get cluster members')
            return device_dict

    #identify current master of a connected device, not tested
    def get_cluster_connected_devices(self,controller=None):
	'''returns all the devices connected to ONOS cluster'''
        device_list = []
        tries = 0
        try:
            cli = self.cliEnter(controller = controller)
            while tries <= 10:
		device_list = []
                devices = json.loads(self.cli.devices(jsonFormat = True))
                log.info("cluster 'devices' command output is %s"%devices)
                if devices:
                    for device in devices:
			log.info('device id is %s'%device['id'])
			device_list.append(str(device['id']))
                    self.cliExit()
                    return device_list
                else:
                    tries += 1
                    time.sleep(1)
            self.cliExit()
            return device_list
        except:
            raise Exception('Failed to get cluster members')
            return device_list

    def get_number_of_devices_of_master(self,controller=None):
	'''returns master-device pairs, which master having what devices'''
	master_count = {}
	try:
	    cli = self.cliEnter(controller = controller)
	    masters = json.loads(self.cli.masters(jsonFormat = True))
	    if masters:
		for master in masters:
		    master_count[str(master['id'])] = {'size':int(master['size']),'devices':master['devices']}
		return master_count
	    else:
		return master_count
	except:
            raise Exception('Failed to get cluster members')
            return master_count

    def change_master_current_cluster(self,new_master=None,device_id=device_id,controller=None):
	if new_master is None: return False
	self.cliEnter(controller=controller)
        cmd = 'device-role' + ' ' + device_id + ' ' + new_master + ' ' + 'master'
        command = self.cli.command(cmd = cmd, jsonFormat = False)
        self.cliExit()
        time.sleep(60)
        master, standbys = self.get_cluster_current_master_standbys(controller=controller,device_id=device_id)
        assert_equal(master,new_master)
	log.info('Cluster master changed to %s successfully'%new_master)

    def withdraw_cluster_current_mastership(self,master_ip=None,device_id=device_id,controller=None):
	'''current master looses its mastership and hence new master will be elected'''
        self.cliEnter(controller=controller)
        cmd = 'device-role' + ' ' + device_id + ' ' + master_ip + ' ' + 'none'
        command = self.cli.command(cmd = cmd, jsonFormat = False)
        self.cliExit()
        time.sleep(60)
        new_master_ip, standbys = self.get_cluster_current_master_standbys(controller=controller,device_id=device_id)
        assert_not_equal(new_master_ip,master_ip)
	log.info('Device-role of device %s successfully changed to none for controller %s'%(device_id,master_ip))
	log.info('Cluster new master is %s'%new_master_ip)
	return True

    def cluster_controller_restarts(self, graceful = False):
        controllers = self.get_controllers()
        ctlr_len = len(controllers)
        if ctlr_len <= 1:
            log.info('ONOS is not running in cluster mode. This test only works for cluster mode')
            assert_greater(ctlr_len, 1)

        #this call would verify the cluster for once
        onos_map = self.get_cluster_container_names_ips()

        def check_exception(iteration, controller = None):
            adjacent_controller = None
            adjacent_controllers = None
            if controller:
                adjacent_controllers = list(set(controllers) - set([controller]))
                adjacent_controller = adjacent_controllers[0]
            for node in controllers:
                onosLog = OnosLog(host = node)
                ##check the logs for storage exception
                _, output = onosLog.get_log(('ERROR', 'Exception',))
                if output and output.find('StorageException$Timeout') >= 0:
                    log.info('\nStorage Exception Timeout found on node: %s\n' %node)
                    log.info('Dumping the ERROR and Exception logs for node: %s\n' %node)
                    log.info('\n' + '-' * 50 + '\n')
                    log.info('%s' %output)
                    log.info('\n' + '-' * 50 + '\n')
                    failed = self.verify_leaders(controllers)
                    if failed:
                        log.info('Leaders command failed on nodes: %s' %failed)
                        log.error('Test failed on ITERATION %d' %iteration)
                        assert_equal(len(failed), 0)
                    return controller

            try:
                ips = self.get_cluster_current_member_ips(controller = adjacent_controller)
                log.info('ONOS cluster formed with controllers: %s' %ips)
                st = True
            except:
                st = False

            failed = self.verify_leaders(controllers)
            if failed:
                log.error('Test failed on ITERATION %d' %iteration)
            assert_equal(len(failed), 0)
            if st is False:
                log.info('No storage exception and ONOS cluster was not formed successfully')
            else:
                controller = None

            return controller

        next_controller = None
        tries = 10
        for num in range(tries):
            index = num % ctlr_len
            #index = random.randrange(0, ctlr_len)
            controller_name = onos_map[controllers[index]] if next_controller is None else onos_map[next_controller]
            controller = onos_map[controller_name]
            log.info('ITERATION: %d. Restarting Controller %s' %(num + 1, controller_name))
            try:
                #enable debug log for the other controllers before restarting this controller
                adjacent_controllers = list( set(controllers) - set([controller]) )
                self.log_set(controllers = adjacent_controllers)
                self.log_set(app = 'io.atomix', controllers = adjacent_controllers)
                if graceful is True:
                    log.info('Gracefully shutting down controller: %s' %controller)
                    self.onos_shutdown(controller)
                cord_test_onos_restart(node = controller, timeout = 0)
                self.log_set(controllers = controller)
                self.log_set(app = 'io.atomix', controllers = controller)
                time.sleep(60)
            except:
                time.sleep(5)
                continue

            #first archive the test case logs for this run
            CordLogger.archive_results(self._testMethodName,
                                       controllers = controllers,
                                       iteration = 'iteration_{}'.format(num+1))
            next_controller = check_exception(num, controller = controller)

    def test_cluster_controller_restarts(self):
        '''Test the cluster by repeatedly killing the controllers'''
        self.cluster_controller_restarts()

    def test_cluster_graceful_controller_restarts(self):
        '''Test the cluster by repeatedly restarting the controllers gracefully'''
        self.cluster_controller_restarts(graceful = True)

    def test_cluster_single_controller_restarts(self):
        '''Test the cluster by repeatedly restarting the same controller'''
        controllers = self.get_controllers()
        ctlr_len = len(controllers)
        if ctlr_len <= 1:
            log.info('ONOS is not running in cluster mode. This test only works for cluster mode')
            assert_greater(ctlr_len, 1)

        #this call would verify the cluster for once
        onos_map = self.get_cluster_container_names_ips()

        def check_exception(iteration, controller, inclusive = False):
            adjacent_controllers = list(set(controllers) - set([controller]))
            adjacent_controller = adjacent_controllers[0]
            controller_list = adjacent_controllers if inclusive == False else controllers
            storage_exceptions = []
            for node in controller_list:
                onosLog = OnosLog(host = node)
                ##check the logs for storage exception
                _, output = onosLog.get_log(('ERROR', 'Exception',))
                if output and output.find('StorageException$Timeout') >= 0:
                    log.info('\nStorage Exception Timeout found on node: %s\n' %node)
                    log.info('Dumping the ERROR and Exception logs for node: %s\n' %node)
                    log.info('\n' + '-' * 50 + '\n')
                    log.info('%s' %output)
                    log.info('\n' + '-' * 50 + '\n')
                    storage_exceptions.append(node)

            failed = self.verify_leaders(controller_list)
            if failed:
                log.info('Leaders command failed on nodes: %s' %failed)
                if storage_exceptions:
                    log.info('Storage exception seen on nodes: %s' %storage_exceptions)
                    log.error('Test failed on ITERATION %d' %iteration)
                    assert_equal(len(failed), 0)
                    return controller

            for ctlr in controller_list:
                ips = self.get_cluster_current_member_ips(controller = ctlr,
                                                          nodes_filter = \
                                                          lambda nodes: [ n for n in nodes if n['state'] in [ 'ACTIVE', 'READY'] ])
                log.info('ONOS cluster on node %s formed with controllers: %s' %(ctlr, ips))
                if controller in ips and inclusive is False:
                    log.info('Controller %s still ACTIVE on Node %s after it was shutdown' %(controller, ctlr))
                if controller not in ips and inclusive is True:
                    log.info('Controller %s still INACTIVE on Node %s after it was restarted' %(controller, ctlr))

            return controller

        tries = 10
        #chose a random controller for shutdown/restarts
        controller = controllers[random.randrange(0, ctlr_len)]
        controller_name = onos_map[controller]
        ##enable the log level for the controllers
        self.log_set(controllers = controllers)
        self.log_set(app = 'io.atomix', controllers = controllers)
        for num in range(tries):
            log.info('ITERATION: %d. Shutting down Controller %s' %(num + 1, controller_name))
            try:
                cord_test_onos_shutdown(node = controller)
                time.sleep(20)
            except:
                time.sleep(5)
                continue
            #check for exceptions on the adjacent nodes
            check_exception(num, controller)
            #Now restart the controller back
            log.info('Restarting back the controller %s' %controller_name)
            cord_test_onos_restart(node = controller)
            self.log_set(controllers = controller)
            self.log_set(app = 'io.atomix', controllers = controller)
            time.sleep(60)
            #archive the logs for this run
            CordLogger.archive_results('test_cluster_single_controller_restarts',
                                       controllers = controllers,
                                       iteration = 'iteration_{}'.format(num+1))
            check_exception(num, controller, inclusive = True)

    def test_cluster_restarts(self):
        '''Test the cluster by repeatedly restarting the entire cluster'''
        controllers = self.get_controllers()
        ctlr_len = len(controllers)
        if ctlr_len <= 1:
            log.info('ONOS is not running in cluster mode. This test only works for cluster mode')
            assert_greater(ctlr_len, 1)

        #this call would verify the cluster for once
        onos_map = self.get_cluster_container_names_ips()

        def check_exception(iteration):
            controller_list = controllers
            storage_exceptions = []
            for node in controller_list:
                onosLog = OnosLog(host = node)
                ##check the logs for storage exception
                _, output = onosLog.get_log(('ERROR', 'Exception',))
                if output and output.find('StorageException$Timeout') >= 0:
                    log.info('\nStorage Exception Timeout found on node: %s\n' %node)
                    log.info('Dumping the ERROR and Exception logs for node: %s\n' %node)
                    log.info('\n' + '-' * 50 + '\n')
                    log.info('%s' %output)
                    log.info('\n' + '-' * 50 + '\n')
                    storage_exceptions.append(node)

            failed = self.verify_leaders(controller_list)
            if failed:
                log.info('Leaders command failed on nodes: %s' %failed)
                if storage_exceptions:
                    log.info('Storage exception seen on nodes: %s' %storage_exceptions)
                    log.error('Test failed on ITERATION %d' %iteration)
                    assert_equal(len(failed), 0)
                    return

            for ctlr in controller_list:
                ips = self.get_cluster_current_member_ips(controller = ctlr,
                                                          nodes_filter = \
                                                          lambda nodes: [ n for n in nodes if n['state'] in [ 'ACTIVE', 'READY'] ])
                log.info('ONOS cluster on node %s formed with controllers: %s' %(ctlr, ips))
                if len(ips) != len(controllers):
                    log.error('Test failed on ITERATION %d' %iteration)
                assert_equal(len(ips), len(controllers))

        tries = 10
        for num in range(tries):
            log.info('ITERATION: %d. Restarting cluster with controllers at %s' %(num+1, controllers))
            try:
                cord_test_restart_cluster()
                self.log_set(controllers = controllers)
                self.log_set(app = 'io.atomix', controllers = controllers)
                log.info('Delaying before verifying cluster status')
                time.sleep(60)
            except:
                time.sleep(10)
                continue

            #archive the logs for this run before verification
            CordLogger.archive_results('test_cluster_restarts',
                                       controllers = controllers,
                                       iteration = 'iteration_{}'.format(num+1))
            #check for exceptions on the adjacent nodes
            check_exception(num)

    #pass
    def test_cluster_formation_and_verification(self,onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances = onos_instances)
	assert_equal(status, True)
	log.info('Cluster exists with %d ONOS instances'%onos_instances)

    #nottest cluster not coming up properly if member goes down
    def test_cluster_adding_members(self, add = 2, onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances = onos_instances)
	assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
	onos_instances = len(onos_ips)+add
        log.info('Adding %d nodes to the ONOS cluster' %add)
        cord_test_onos_add_cluster(count = add)
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)

    def test_cluster_removing_master(self, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        log.info('Removing cluster current master %s'%(master))
        cord_test_onos_shutdown(node = master)
        time.sleep(60)
        onos_instances -= 1
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=standbys[0])
        assert_equal(status, True)
	new_master, standbys = self.get_cluster_current_master_standbys(controller=standbys[0])
	assert_not_equal(master,new_master)
	log.info('Successfully removed clusters master instance')

    def test_cluster_removing_one_member(self, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
	log.info('Removing cluster member %s'%standbys[0])
        cord_test_onos_shutdown(node = standbys[0])
	time.sleep(60)
	onos_instances -= 1
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=master)
        assert_equal(status, True)

    def test_cluster_removing_two_members(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
       	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
        member2_onos_name = onos_names_ips[standbys[1]]
        log.info('Removing cluster member %s'%standbys[0])
        cord_test_onos_shutdown(node = standbys[0])
        log.info('Removing cluster member %s'%standbys[1])
        cord_test_onos_shutdown(node = standbys[1])
        time.sleep(60)
        onos_instances = onos_instances - 2
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=master)
        assert_equal(status, True)

    def test_cluster_removing_N_members(self,remove = 2, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        for i in range(remove):
	    member_onos_name = onos_names_ips[standbys[i]]
            log.info('Removing onos container with name %s'%standbys[i])
            cord_test_onos_shutdown(node = standbys[i])
        time.sleep(60)
        onos_instances = onos_instances - remove
        status = self.verify_cluster_status(onos_instances = onos_instances, controller=master)
        assert_equal(status, True)

    #nottest test cluster not coming up properly if member goes down
    def test_cluster_adding_and_removing_members(self,onos_instances = ONOS_INSTANCES , add = 2, remove = 2):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
        onos_instances = len(onos_ips)+add
        log.info('Adding %d ONOS instances to the cluster'%add)
        cord_test_onos_add_cluster(count = add)
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        log.info('Removing %d ONOS instances from the cluster'%remove)
        for i in range(remove):
            name = '{}-{}'.format(Onos.NAME, onos_instances - i)
            log.info('Removing onos container with name %s'%name)
            cord_test_onos_shutdown(node = name)
        time.sleep(60)
        onos_instances = onos_instances-remove
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)

    #nottest cluster not coming up properly if member goes down
    def test_cluster_removing_and_adding_member(self,onos_instances = ONOS_INSTANCES,add = 1, remove = 1):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
        onos_instances = onos_instances-remove
        log.info('Removing %d ONOS instances from the cluster'%remove)
        for i in range(remove):
            name = '{}-{}'.format(Onos.NAME, len(onos_ips)-i)
            log.info('Removing onos container with name %s'%name)
            cord_test_onos_shutdown(node = name)
        time.sleep(60)
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        log.info('Adding %d ONOS instances to the cluster'%add)
        cord_test_onos_add_cluster(count = add)
        onos_instances = onos_instances+add
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)

    def test_cluster_restart(self, onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Restarting cluster')
	cord_test_onos_restart()
	status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)

    def test_cluster_master_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        log.info('Restarting cluster master %s'%master)
        cord_test_onos_restart(node = master)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up after master restart as expected')

    #test fail. master changing after restart. Need to check correct behavior.
    def test_cluster_master_ip_after_master_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        master1, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master1]
        log.info('Restarting cluster master %s'%master1)
        cord_test_onos_restart(node = master1)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master2, standbys = self.get_cluster_current_master_standbys()
	assert_equal(master1,master2)
        log.info('Cluster master is same before and after cluster master restart as expected')

    def test_cluster_one_member_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
	member_onos_name = onos_names_ips[standbys[0]]
        log.info('Restarting cluster member %s'%standbys[0])
        cord_test_onos_restart(node = standbys[0])
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting one member')

    def test_cluster_two_members_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
        member2_onos_name = onos_names_ips[standbys[1]]
        log.info('Restarting cluster members %s and %s'%(standbys[0],standbys[1]))
        cord_test_onos_restart(node = standbys[0])
        cord_test_onos_restart(node = standbys[1])
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting two members')

    def test_cluster_state_with_N_members_restart(self, members = 2, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status,True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
	for i in range(members):
            member_onos_name = onos_names_ips[standbys[i]]
	    log.info('Restarting cluster member %s'%standbys[i])
            cord_test_onos_restart(node = standbys[i])

        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting %d members'%members)

    def test_cluster_state_with_master_change(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys),(onos_instances-1))
        log.info('Cluster current master of devices is %s'%master)
	self.change_master_current_cluster(new_master=standbys[0])
        log.info('Cluster master changed successfully')

    #tested on single onos setup.
    def test_cluster_with_vrouter_routes_in_cluster_members(self,networks = 5,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	onos_ips = self.get_cluster_current_member_ips()
        self.vrouter.setUpClass()
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True)
        for onos_ip in onos_ips:
            tries = 0
            flag = False
            try:
                self.cliEnter(controller = onos_ip)
                while tries <= 5:
                    routes = json.loads(self.cli.routes(jsonFormat = True))
                    if routes:
                        assert_equal(len(routes['routes4']), networks)
                        self.cliExit()
                        flag = True
                        break
                    else:
                        tries += 1
                        time.sleep(1)
                assert_equal(flag, True)
            except:
                log.info('Exception occured while checking routes in onos instance %s'%onos_ip)
                raise

    #tested on single onos setup.
    def test_cluster_with_vrouter_and_master_down(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
	master, standbys = self.get_cluster_current_master_standbys()
	onos_names_ips =  self.get_cluster_container_names_ips()
	master_onos_name = onos_names_ips[master]
        self.vrouter.setUpClass()
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
	assert_equal(res,True)
        cord_test_onos_shutdown(node = master)
	time.sleep(60)
	log.info('Verifying vrouter traffic after cluster master is down')
	self.vrouter.vrouter_traffic_verify()

    #tested on single onos setup.
    def test_cluster_with_vrouter_and_restarting_master(self,networks = 5,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
        master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.vrouter.setUpClass()
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True)
        cord_test_onos_restart()
	self.vrouter.vrouter_traffic_verify()

    #tested on single onos setup.
    def test_cluster_deactivating_vrouter_app(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        self.vrouter.setUpClass()
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True)
	self.vrouter.vrouter_activate(deactivate=True)
        time.sleep(15)
	self.vrouter.vrouter_traffic_verify(positive_test=False)
	self.vrouter.vrouter_activate(deactivate=False)

    #tested on single onos setup.
    def test_cluster_deactivating_vrouter_app_and_making_master_down(self,networks = 5,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.vrouter.setUpClass()
	log.info('Verifying vrouter before master down')
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True)
	self.vrouter.vrouter_activate(deactivate=True)
	log.info('Verifying vrouter traffic after app deactivated')
        time.sleep(15) ## Expecting vrouter should work properly if master of cluster goes down
        self.vrouter.vrouter_traffic_verify(positive_test=False)
	log.info('Verifying vrouter traffic after master down')
        cord_test_onos_shutdown(node = master)
	time.sleep(60)
	self.vrouter.vrouter_traffic_verify(positive_test=False)
        self.vrouter.vrouter_activate(deactivate=False)

    #tested on single onos setup.
    def test_cluster_for_vrouter_app_and_making_member_down(self, networks = 5,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
        self.vrouter.setUpClass()
        log.info('Verifying vrouter before cluster member down')
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True) # Expecting vrouter should work properly
        log.info('Verifying vrouter after cluster member down')
        cord_test_onos_shutdown(node = standbys[0])
	time.sleep(60)
	self.vrouter.vrouter_traffic_verify()# Expecting vrouter should work properly if member of cluster goes down

    #tested on single onos setup.
    def test_cluster_for_vrouter_app_and_restarting_member(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[1]]
        self.vrouter.setUpClass()
        log.info('Verifying vrouter traffic before cluster member restart')
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True) # Expecting vrouter should work properly
        cord_test_onos_restart(node = standbys[1])
	log.info('Verifying vrouter traffic after cluster member restart')
        self.vrouter.vrouter_traffic_verify()# Expecting vrouter should work properly if member of cluster restarts

    #tested on single onos setup.
    def test_cluster_for_vrouter_app_restarting_cluster(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        self.vrouter.setUpClass()
        log.info('Verifying vrouter traffic before cluster restart')
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True) # Expecting vrouter should work properly
	cord_test_onos_restart()
        log.info('Verifying vrouter traffic after cluster restart')
        self.vrouter.vrouter_traffic_verify()# Expecting vrouter should work properly if member of cluster restarts


    #test fails because flow state is in pending_add in onos
    def test_cluster_for_flows_of_udp_port_and_making_master_down(self, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
	onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.flows.setUpClass()
        egress = 1
        ingress = 2
        egress_map = { 'ip': '192.168.30.1', 'udp_port': 9500 }
        ingress_map = { 'ip': '192.168.40.1', 'udp_port': 9000 }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            udpSrc = ingress_map['udp_port'],
                            udpDst = egress_map['udp_port'],
			    controller=master
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress UDP port %s, egress UDP port %s' %(pkt[UDP].sport, pkt[UDP].dport))
                self.success = True
            sniff(timeout=2,
             lfilter = lambda p: UDP in p and p[UDP].dport == egress_map['udp_port']
                                and p[UDP].sport == ingress_map['udp_port'], prn = recv_cb, iface = self.flows.port_map[egress])

	for i in [0,1]:
	    if i == 1:
                cord_test_onos_shutdown(node = master)
                log.info('Verifying flows traffic after master killed')
                time.sleep(45)
	    else:
		log.info('Verifying flows traffic before master killed')
            t = threading.Thread(target = mac_recv_task)
            t.start()
            L2 = self.flows_eth #Ether(src = ingress_map['ether'], dst = egress_map['ether'])
            L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'])
            L4 = UDP(sport = ingress_map['udp_port'], dport = egress_map['udp_port'])
            pkt = L2/L3/L4
            log.info('Sending packets to verify if flows are correct')
            sendp(pkt, count=50, iface = self.flows.port_map[ingress])
            t.join()
            assert_equal(self.success, True)

    def test_cluster_state_changing_master_and_flows_of_ecn(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        self.flows.setUpClass()
        egress = 1
        ingress = 2
        egress_map = { 'ip': '192.168.30.1' }
        ingress_map = { 'ip': '192.168.40.1' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ecn = 1,
			    controller=master
                            )
        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s and Type of Service %s' %(pkt[IP].src, pkt[IP].dst, pkt[IP].tos))
                self.success = True
            sniff(count=2, timeout=5,
                  lfilter = lambda p: IP in p and p[IP].dst == egress_map['ip'] and p[IP].src == ingress_map['ip']
                        and int(bin(p[IP].tos).split('b')[1][-2:],2) == 1,prn = recv_cb,
                                iface = self.flows.port_map[egress])
	for i in [0,1]:
	    if i == 1:
		log.info('Changing cluster master to %s'%standbys[0])
		self.change_master_current_cluster(new_master=standbys[0])
		log.info('Verifying flow traffic after cluster master chnaged')
	    else:
		log.info('Verifying flow traffic  before cluster master changed')
            t = threading.Thread(target = mac_recv_task)
            t.start()
            L2 = self.flows_eth # Ether(src = ingress_map['ether'], dst = egress_map['ether'])
            L3 = IP(src = ingress_map['ip'], dst = egress_map['ip'], tos = 1)
            pkt = L2/L3
            log.info('Sending a packet to verify if flows are correct')
            sendp(pkt, count=50, iface = self.flows.port_map[ingress])
            t.join()
            assert_equal(self.success, True)

    #pass
    def test_cluster_flow_for_ipv6_extension_header_and_master_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
	onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.flows.setUpClass()
        egress = 1
        ingress = 2
        egress_map = { 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
        ingress_map = { 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
        flow = OnosFlowCtrl(deviceId = self.device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ipv6_extension = 0,
			    controller=master
                            )

        result = flow.addFlow()
        assert_equal(result, True)
        ##wait for flows to be added to ONOS
        time.sleep(1)
        self.success = False
        def mac_recv_task():
            def recv_cb(pkt):
                log.info('Pkt seen with ingress ip %s, egress ip %s, Extension Header Type %s'%(pkt[IPv6].src, pkt[IPv6].dst, pkt[IPv6].nh))
                self.success = True
            sniff(timeout=2,count=5,
                  lfilter = lambda p: IPv6 in p and p[IPv6].nh == 0, prn = recv_cb, iface = self.flows.port_map[egress])
	for i in [0,1]:
	    if i == 1:
		log.info('Restart cluster current master %s'%master)
                Container(master_onos_name,Onos.IMAGE).restart()
                time.sleep(45)
	        log.info('Verifying flow traffic after master restart')
	    else:
		log.info('Verifying flow traffic before master restart')
            t = threading.Thread(target = mac_recv_task)
            t.start()
            L2 = self.flows_eth
            L3 = IPv6(src = ingress_map['ipv6'] , dst = egress_map['ipv6'], nh = 0)
            pkt = L2/L3
            log.info('Sending packets to verify if flows are correct')
            sendp(pkt, count=50, iface = self.flows.port_map[ingress])
            t.join()
            assert_equal(self.success, True)

    def send_multicast_data_traffic(self, group, intf= 'veth2',source = '1.2.3.4'):
        dst_mac = self.igmp.iptomac(group)
        eth = Ether(dst= dst_mac)
        ip = IP(dst=group,src=source)
        data = repr(monotonic.monotonic())
        sendp(eth/ip/data,count=20, iface = intf)
        pkt = (eth/ip/data)
        log.info('multicast traffic packet %s'%pkt.show())

    def verify_igmp_data_traffic(self, group, intf='veth0', source='1.2.3.4' ):
        log.info('verifying multicast traffic for group %s from source %s'%(group,source))
        self.success = False
        def recv_task():
            def igmp_recv_cb(pkt):
                log.info('multicast data received for group %s from source %s'%(group,source))
                self.success = True
            sniff(prn = igmp_recv_cb,lfilter = lambda p: IP in p and p[IP].dst == group and p[IP].src == source, count=1,timeout = 2, iface='veth0')
        t = threading.Thread(target = recv_task)
        t.start()
        self.send_multicast_data_traffic(group,source=source)
        t.join()
        return self.success

    #pass
    def test_cluster_with_igmp_include_exclude_modes_and_restarting_master(self, onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
	onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
	self.igmp.setUp(controller=master)
        groups = ['224.2.3.4','230.5.6.7']
        src_list = ['2.2.2.2','3.3.3.3']
        self.igmp.onos_ssm_table_load(groups, src_list=src_list, controller=master)
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
        self.igmp.send_igmp_join(groups = [groups[1]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                             iface = self.V_INF1, delay = 2)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        status = self.verify_igmp_data_traffic(groups[1],intf = self.V_INF1,source= src_list[1])
        assert_equal(status,False)
	log.info('restarting cluster master %s'%master)
	Container(master_onos_name,Onos.IMAGE).restart()
	time.sleep(60)
	log.info('verifying multicast data traffic after master restart')
	status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        status = self.verify_igmp_data_traffic(groups[1],intf = self.V_INF1,source= src_list[1])
        assert_equal(status,False)

    #pass
    def test_cluster_with_igmp_include_exclude_modes_and_making_master_down(self, onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.igmp.setUp(controller=master)
        groups = [self.igmp.random_mcast_ip(),self.igmp.random_mcast_ip()]
        src_list = [self.igmp.randomsourceip()]
        self.igmp.onos_ssm_table_load(groups, src_list=src_list,controller=master)
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
        self.igmp.send_igmp_join(groups = [groups[1]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_EXCLUDE,
                             iface = self.V_INF1, delay = 2)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        status = self.verify_igmp_data_traffic(groups[1],intf = self.V_INF1,source= src_list[0])
        assert_equal(status,False)
        log.info('Killing cluster master %s'%master)
        Container(master_onos_name,Onos.IMAGE).kill()
        time.sleep(60)
	status = self.verify_cluster_status(onos_instances=onos_instances-1,controller=standbys[0])
        assert_equal(status, True)
        log.info('Verifying multicast data traffic after cluster master down')
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        status = self.verify_igmp_data_traffic(groups[1],intf = self.V_INF1,source= src_list[0])
        assert_equal(status,False)

    def test_cluster_with_igmp_include_mode_checking_traffic_recovery_time_after_master_is_down(self, onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.igmp.setUp(controller=master)
        groups = [self.igmp.random_mcast_ip()]
        src_list = [self.igmp.randomsourceip()]
        self.igmp.onos_ssm_table_load(groups, src_list=src_list,controller=master)
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        log.info('Killing clusters master %s'%master)
        Container(master_onos_name,Onos.IMAGE).kill()
	count = 0
	for i in range(60):
            log.info('Verifying multicast data traffic after cluster master down')
            status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
	    if status:
		break
	    else:
		count += 1
	        time.sleep(1)
	assert_equal(status, True)
	log.info('Time taken to recover traffic after clusters master down is %d seconds'%count)


    #pass
    def test_cluster_state_with_igmp_leave_group_after_master_change(self, onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys), (onos_instances-1))
        self.igmp.setUp(controller=master)
        groups = [self.igmp.random_mcast_ip()]
        src_list = [self.igmp.randomsourceip()]
        self.igmp.onos_ssm_table_load(groups, src_list=src_list,controller=master)
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
	log.info('Changing cluster master %s to %s'%(master,standbys[0]))
	self.change_cluster_current_master(new_master=standbys[0])
	log.info('Verifying multicast traffic after cluster master change')
	status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)
        log.info('Sending igmp TO_EXCLUDE message to leave the group %s'%groups[0])
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_CHANGE_TO_EXCLUDE,
                             iface = self.V_INF1, delay = 1)
	time.sleep(10)
        status = self.verify_igmp_data_traffic(groups[0],intf = self.V_INF1,source= src_list[0])
        assert_equal(status,False)

    #pass
    def test_cluster_state_with_igmp_join_before_and_after_master_change(self,onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys), (onos_instances-1))
        self.igmp.setUp(controller=master)
        groups = [self.igmp.random_mcast_ip()]
        src_list = [self.igmp.randomsourceip()]
        self.igmp.onos_ssm_table_load(groups, src_list=src_list,controller=master)
	log.info('Changing cluster master %s to %s'%(master,standbys[0]))
	self.change_cluster_current_master(new_master = standbys[0])
        self.igmp.send_igmp_join(groups = [groups[0]], src_list = src_list,record_type = IGMP_V3_GR_TYPE_INCLUDE,
                             iface = self.V_INF1, delay = 2)
	time.sleep(1)
	self.change_cluster_current_master(new_master = master)
        status = self.verify_igmp_data_traffic(groups[0],intf=self.V_INF1,source=src_list[0])
        assert_equal(status,True)

    #pass
    @deferred(TLS_TIMEOUT)
    def test_cluster_with_eap_tls_traffic(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
	self.tls.setUp(controller=master)
        df = defer.Deferred()
        def eap_tls_verify(df):
            tls = TLSAuthTest()
            tls.runTest()
            df.callback(0)
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(120)
    def test_cluster_for_eap_tls_traffic_before_and_after_master_change(self,onos_instances=ONOS_INSTANCES):
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        self.tls.setUp()
        df = defer.Deferred()
	def eap_tls_verify2(df2):
            tls = TLSAuthTest()
            tls.runTest()
            df.callback(0)
        for i in [0,1]:
	    if i == 1:
		log.info('Changing cluster master %s to %s'%(master, standbys[0]))
		self.change_master_current_cluster(new_master=standbys[0])
                log.info('Verifying tls authentication after cluster master changed to %s'%standbys[0])
	    else:
		log.info('Verifying tls authentication before cluster master change')
            reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_cluster_for_eap_tls_traffic_before_and_after_making_master_down(self,onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
	onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.tls.setUp()
        df = defer.Deferred()
        def eap_tls_verify(df):
            tls = TLSAuthTest()
            tls.runTest()
            df.callback(0)
        for i in [0,1]:
            if i == 1:
                log.info('Killing cluster current master %s'%master)
                cord_test_onos_shutdown(node = master)
		time.sleep(20)
                status = self.verify_cluster_status(controller=standbys[0],onos_instances=onos_instances-1,verify=True)
		assert_equal(status, True)
		log.info('Cluster came up with %d instances after killing master'%(onos_instances-1))
                log.info('Verifying tls authentication after killing cluster master')
            reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_cluster_for_eap_tls_with_no_cert_before_and_after_member_is_restarted(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
	self.tls.setUp()
        df = defer.Deferred()
        def eap_tls_no_cert(df):
            def tls_no_cert_cb():
                log.info('TLS authentication failed with no certificate')
            tls = TLSAuthTest(fail_cb = tls_no_cert_cb, client_cert = '')
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
	for i in [0,1]:
	    if i == 1:
	        log.info('Restart cluster member %s'%standbys[0])
                Container(member_onos_name,Onos.IMAGE).restart()
                time.sleep(20)
                status = self.verify_cluster_status(onos_instances=onos_instances)
                assert_equal(status, True)
                log.info('Cluster came up with %d instances after member restart'%(onos_instances))
                log.info('Verifying tls authentication after member restart')
        reactor.callLater(0, eap_tls_no_cert, df)
        return df

    #pass
    def test_cluster_proxyarp_master_change_and_app_deactivation(self,onos_instances=ONOS_INSTANCES,hosts = 3):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status,True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.proxyarp.setUpClass()
        ports_map, egress_map,hosts_config = self.proxyarp.proxyarp_config(hosts = hosts,controller=master)
        ingress = hosts+1
        for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)
	log.info('changing cluster current master from %s to %s'%(master,standbys[0]))
	self.change_cluster_current_master(new_master=standbys[0])
	log.info('verifying proxyarp after master change')
	for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)
        log.info('Deactivating proxyarp  app and expecting proxyarp functionality not to work')
        self.proxyarp.proxyarp_activate(deactivate = True,controller=standbys[0])
	time.sleep(3)
        for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = False)
            time.sleep(1)
        log.info('activating proxyarp  app and expecting to get arp reply from ONOS')
        self.proxyarp.proxyarp_activate(deactivate = False,controller=standbys[0])
	time.sleep(3)
        for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)

    #pass
    def test_cluster_with_proxyarp_and_one_member_down(self,hosts=3,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[1]]
	self.proxyarp.setUpClass()
        ports_map, egress_map,hosts_config = self.proxyarp.proxyarp_config(hosts = hosts,controller=master)
        ingress = hosts+1
        for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)
	log.info('killing cluster member %s'%standbys[1])
        Container(member_onos_name,Onos.IMAGE).kill()
        time.sleep(20)
        status = self.verify_cluster_status(onos_instances=onos_instances-1,controller=master,verify=True)
        assert_equal(status, True)
        log.info('cluster came up with %d instances after member down'%(onos_instances-1))
        log.info('verifying proxy arp functionality after cluster member down')
	for hostip, hostmac in hosts_config:
            self.proxyarp.proxyarp_arpreply_verify(ingress,hostip,hostmac,PositiveTest = True)
            time.sleep(1)

    #pass
    def test_cluster_with_proxyarp_and_concurrent_requests_with_multiple_host_and_different_interfaces(self,hosts=10,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	self.proxyarp.setUpClass()
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys), (onos_instances-1))
        ports_map, egress_map, hosts_config = self.proxyarp.proxyarp_config(hosts = hosts, controller=master)
        self.success = True
        ingress = hosts+1
        ports = range(ingress,ingress+10)
        hostmac = []
        hostip = []
        for ip,mac in hosts_config:
            hostmac.append(mac)
            hostip.append(ip)
        success_dir = {}
        def verify_proxyarp(*r):
            ingress, hostmac, hostip = r[0],r[1],r[2]
            def mac_recv_task():
                def recv_cb(pkt):
                    log.info('Arp Reply seen with source Mac is %s' %(pkt[ARP].hwsrc))
                    success_dir[current_thread().name] = True
                sniff(count=1, timeout=5,lfilter = lambda p: ARP in p and p[ARP].op == 2 and p[ARP].hwsrc == hostmac,
                    prn = recv_cb, iface = self.proxyarp.port_map[ingress])
            t = threading.Thread(target = mac_recv_task)
            t.start()
            pkt = (Ether(dst = 'ff:ff:ff:ff:ff:ff')/ARP(op=1,pdst= hostip))
            log.info('Sending arp request  for dest ip %s on interface %s' %
                 (hostip,self.proxyarp.port_map[ingress]))
            sendp(pkt, count = 10,iface = self.proxyarp.port_map[ingress])
            t.join()
        t = []
        for i in range(10):
            t.append(threading.Thread(target = verify_proxyarp, args = [ports[i],hostmac[i],hostip[i]]))
        for i in range(10):
            t[i].start()
	time.sleep(2)
        for i in range(10):
            t[i].join()
        if len(success_dir) != 10:
                self.success = False
        assert_equal(self.success, True)

    #pass
    def test_cluster_with_acl_rule_before_master_change_and_remove_acl_rule_after_master_change(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.acl.setUp()
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.acl.ACL_SRC_IP, dstIp =self.acl.ACL_DST_IP, action = 'allow',controller=master)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result = acl_rule.get_acl_rules(controller=master)
        aclRules1 = result.json()['aclRules']
	log.info('Added acl rules is %s'%aclRules1)
        acl_Id = map(lambda d: d['id'], aclRules1)
	log.info('Changing cluster current master from %s to %s'%(master,standbys[0]))
	self.change_cluster_current_master(new_master=standbys[0])
        status,code = acl_rule.remove_acl_rule(acl_Id[0],controller=standbys[0])
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)

    #pass
    def test_cluster_verifying_acl_rule_in_new_master_after_current_master_is_down(self,onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	onos_names_ips =  self.get_cluster_container_names_ips()
	master_onos_name = onos_names_ips[master]
        self.acl.setUp()
        acl_rule = ACLTest()
        status,code = acl_rule.adding_acl_rule('v4', srcIp=self.acl.ACL_SRC_IP, dstIp =self.acl.ACL_DST_IP, action = 'allow',controller=master)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        result1 = acl_rule.get_acl_rules(controller=master)
        aclRules1 = result1.json()['aclRules']
        log.info('Added acl rules is %s'%aclRules1)
        acl_Id1 = map(lambda d: d['id'], aclRules1)
        log.info('Killing cluster current master %s'%master)
	Container(master_onos_name,Onos.IMAGE).kill()
	time.sleep(45)
	status = self.verify_cluster_status(onos_instances=onos_instances,controller=standbys[0])
        assert_equal(status, True)
        new_master,standbys = self.get_cluster_current_master_standbys(controller=standbys[0])
	assert_equal(len(standbys),(onos_instances-2))
	assert_not_equal(new_master,master)
        result2 = acl_rule.get_acl_rules(controller=new_master)
        aclRules2 = result2.json()['aclRules']
	acl_Id2 = map(lambda d: d['id'], aclRules2)
	log.info('Acl Ids before and after master down are %s and %s'%(acl_Id1,acl_Id2))
	assert_equal(acl_Id2,acl_Id1)

    #acl traffic scenario not working as acl rule is not getting added to onos
    def test_cluster_with_acl_traffic_before_and_after_two_members_down(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
        member2_onos_name = onos_names_ips[standbys[1]]
        ingress = self.acl.ingress_iface
        egress = self.acl.CURRENT_PORT_NUM
        acl_rule = ACLTest()
        status, code, host_ip_mac = acl_rule.generate_onos_interface_config(iface_num= self.acl.CURRENT_PORT_NUM, iface_name = 'b1',iface_count = 1, iface_ip = self.acl.HOST_DST_IP)
        self.acl.CURRENT_PORT_NUM += 1
        time.sleep(5)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        srcMac = '00:00:00:00:00:11'
        dstMac = host_ip_mac[0][1]
        self.acl.acl_hosts_add(dstHostIpMac = host_ip_mac, egress_iface_count = 1,  egress_iface_num = egress )
        status, code = acl_rule.adding_acl_rule('v4', srcIp=self.acl.ACL_SRC_IP, dstIp =self.acl.ACL_DST_IP, action = 'deny',controller=master)
        time.sleep(10)
        if status is False:
            log.info('JSON request returned status %d' %code)
            assert_equal(status, True)
        self.acl.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.acl.ACL_SRC_IP, dstIp = self.acl.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
	log.info('killing cluster members %s and %s'%(standbys[0],standbys[1]))
        Container(member1_onos_name, Onos.IMAGE).kill()
        Container(member2_onos_name, Onos.IMAGE).kill()
	time.sleep(40)
	status = self.verify_cluster_status(onos_instances=onos_instances-2,verify=True,controller=master)
        assert_equal(status, True)
	self.acl.acl_rule_traffic_send_recv(srcMac = srcMac, dstMac = dstMac ,srcIp =self.acl.ACL_SRC_IP, dstIp = self.acl.ACL_DST_IP,ingress =ingress, egress = egress, ip_proto = 'UDP', positive_test = False)
        self.acl.acl_hosts_remove(egress_iface_count = 1,  egress_iface_num = egress)

    #pass
    def test_cluster_with_dhcpRelay_releasing_dhcp_ip_after_master_change(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.dhcprelay.setUpClass(controller=master)
        mac = self.dhcprelay.get_mac(iface)
        self.dhcprelay.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.dhcprelay.default_config
        options = self.dhcprelay.default_options
        subnet = self.dhcprelay.default_subnet_config
        dhcpd_interface_list = self.dhcprelay.relay_interfaces
        self.dhcprelay.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet,
			 controller=master)
        self.dhcprelay.dhcp = DHCPTest(seed_ip = '10.10.100.10', iface = iface)
        cip, sip = self.dhcprelay.send_recv(mac)
	log.info('Changing cluster current master from %s to %s'%(master, standbys[0]))
	self.change_master_current_cluster(new_master=standbys[0])
        log.info('Releasing ip %s to server %s' %(cip, sip))
        assert_equal(self.dhcprelay.dhcp.release(cip), True)
        log.info('Triggering DHCP discover again after release')
        cip2, sip2 = self.dhcprelay.send_recv(mac)
        log.info('Verifying released IP was given back on rediscover')
        assert_equal(cip, cip2)
        log.info('Test done. Releasing ip %s to server %s' %(cip2, sip2))
        assert_equal(self.dhcprelay.dhcp.release(cip2), True)
	self.dhcprelay.tearDownClass(controller=standbys[0])


    def test_cluster_with_dhcpRelay_and_verify_dhcp_ip_after_master_down(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        self.dhcprelay.setUpClass(controller=master)
        mac = self.dhcprelay.get_mac(iface)
        self.dhcprelay.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.dhcprelay.default_config
        options = self.dhcprelay.default_options
        subnet = self.dhcprelay.default_subnet_config
        dhcpd_interface_list = self.dhcprelay.relay_interfaces
        self.dhcprelay.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet,
			 controller=master)
        self.dhcprelay.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
        log.info('Initiating dhcp process from client %s'%mac)
        cip, sip = self.dhcprelay.send_recv(mac)
        log.info('Killing cluster current master %s'%master)
	Container(master_onos_name, Onos.IMAGE).kill()
	time.sleep(60)
	status = self.verify_cluster_status(onos_instances=onos_instances-1,verify=True,controller=standbys[0])
        assert_equal(status, True)
	mac = self.dhcprelay.dhcp.get_mac(cip)[0]
        log.info("Verifying dhcp clients gets same IP after cluster master restarts")
        new_cip, new_sip = self.dhcprelay.dhcp.only_request(cip, mac)
        assert_equal(new_cip, cip)
	self.dhcprelay.tearDownClass(controller=standbys[0])

    #pass
    def test_cluster_with_dhcpRelay_and_simulate_client_by_changing_master(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.dhcprelay.setUpClass(controller=master)
        macs = ['e4:90:5e:a3:82:c1','e4:90:5e:a3:82:c2','e4:90:5e:a3:82:c3']
        self.dhcprelay.host_load(iface)
        ##we use the defaults for this test that serves as an example for others
        ##You don't need to restart dhcpd server if retaining default config
        config = self.dhcprelay.default_config
        options = self.dhcprelay.default_options
        subnet = self.dhcprelay.default_subnet_config
        dhcpd_interface_list = self.dhcprelay.relay_interfaces
        self.dhcprelay.dhcpd_start(intf_list = dhcpd_interface_list,
                         config = config,
                         options = options,
                         subnet = subnet,
			 controller=master)
        self.dhcprelay.dhcp = DHCPTest(seed_ip = '10.10.10.1', iface = iface)
	cip1, sip1 = self.dhcprelay.send_recv(macs[0])
	assert_not_equal(cip1,None)
        log.info('Got dhcp client IP %s for mac %s when cluster master is %s'%(cip1,macs[0],master))
        log.info('Changing cluster master from %s to %s'%(master, standbys[0]))
	self.change_master_current_cluster(new_master=standbys[0])
	cip2, sip2 = self.dhcprelay.send_recv(macs[1])
	assert_not_equal(cip2,None)
	log.info('Got dhcp client IP %s for mac %s when cluster master is %s'%(cip2,macs[1],standbys[0]))
	self.change_master_current_cluster(new_master=master)
        log.info('Changing cluster master from %s to %s'%(standbys[0],master))
        cip3, sip3 = self.dhcprelay.send_recv(macs[2])
	assert_not_equal(cip3,None)
	log.info('Got dhcp client IP %s for mac %s when cluster master is %s'%(cip2,macs[2],master))
	self.dhcprelay.tearDownClass(controller=standbys[0])

    def test_cluster_with_cord_subscriber_joining_next_channel_before_and_after_cluster_restart(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	self.subscriber.setUpClass(controller=master)
        self.subscriber.num_subscribers = 5
        self.subscriber.num_channels = 10
	for i in [0,1]:
	    if i == 1:
		cord_test_onos_restart()
		time.sleep(45)
		status = self.verify_cluster_status(onos_instances=onos_instances)
		assert_equal(status, True)
		log.info('Verifying cord subscriber functionality after cluster restart')
	    else:
		log.info('Verifying cord subscriber functionality before cluster restart')
            test_status = self.subscriber.subscriber_join_verify(num_subscribers = self.subscriber.num_subscribers,
                                                    num_channels = self.subscriber.num_channels,
                                                    cbs = (self.subscriber.tls_verify, self.subscriber.dhcp_next_verify,
                                                           self.subscriber.igmp_next_verify, self.subscriber.traffic_verify),
                                                    port_list = self.subscriber.generate_port_list(self.subscriber.num_subscribers,
                                                                                        self.subscriber.num_channels))
            assert_equal(test_status, True)
	self.subscriber.tearDownClass(controller=master)

    #not validated on cluster setup because ciena-cordigmp-multitable-2.0 app installation fails on cluster
    def test_cluster_with_cord_subscriber_join_next_channel_before_and_after_cluster_mastership_is_withdrawn(self,onos_instances=ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master,standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        self.subscriber.setUpClass(controller=master)
        self.subscriber.num_subscribers = 5
        self.subscriber.num_channels = 10
        for i in [0,1]:
            if i == 1:
		status=self.withdraw_cluster_current_mastership(master_ip=master)
		asser_equal(status, True)
		master,standbys = self.get_cluster_current_master_standbys()
                log.info('verifying cord subscriber functionality after cluster current master withdraw mastership')
            else:
		 log.info('verifying cord subscriber functionality before cluster master withdraw mastership')
            test_status = self.subscriber.subscriber_join_verify(num_subscribers = self.subscriber.num_subscribers,
                                                    num_channels = self.subscriber.num_channels,
                                                    cbs = (self.subscriber.tls_verify, self.subscriber.dhcp_next_verify,
                                                           self.subscriber.igmp_next_verify, self.subscriber.traffic_verify),
                                                    port_list = self.subscriber.generate_port_list(self.subscriber.num_subscribers,
                                                                                        self.subscriber.num_channels),controller=master)
            assert_equal(test_status, True)
        self.subscriber.tearDownClass(controller=master)

    #not validated on cluster setup because ciena-cordigmp-multitable-2.0 app installation fails on cluster
    def test_cluster_with_cord_subscriber_join_recv_traffic_from_10channels_and_making_one_cluster_member_down(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
	self.subscriber.setUpClass(controller=master)
	num_subscribers = 1
        num_channels = 10
	for i in [0,1]:
	    if i == 1:
                cord_test_onos_shutdown(node = standbys[0])
		time.sleep(30)
		status = self.verify_cluster_status(onos_instances=onos_instances-1,verify=True,controller=master)
                assert_equal(status, True)
		log.info('Verifying cord subscriber functionality after cluster member %s is down'%standbys[0])
	    else:
		log.info('Verifying cord subscriber functionality before cluster member %s is down'%standbys[0])
            test_status = self.subscriber.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.subscriber.tls_verify, self.subscriber.dhcp_verify,
                                                              self.subscriber.igmp_verify, self.subscriber.traffic_verify),
                                                    port_list = self.subscriber.generate_port_list(num_subscribers, num_channels),
                                                    negative_subscriber_auth = 'all',controller=master)
            assert_equal(test_status, True)
	self.subscriber.tearDownClass(controller=master)

    def test_cluster_with_cord_subscriber_joining_next_10channels_making_two_cluster_members_down(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
	member2_onos_name = onos_names_ips[standbys[1]]
	self.subscriber.setUpClass(controller=master)
        num_subscribers = 1
        num_channels = 10
	for i in [0,1]:
	    if i == 1:
                cord_test_onos_shutdown(node = standbys[0])
                cord_test_onos_shutdown(node = standbys[1])
		time.sleep(60)
		status = self.verify_cluster_status(onos_instances=onos_instances-2)
                assert_equal(status, True)
		log.info('Verifying cord subscriber funtionality after cluster two members %s and %s down'%(standbys[0],standbys[1]))
	    else:
		log.info('Verifying cord subscriber funtionality before cluster two members %s and %s down'%(standbys[0],standbys[1]))
	    test_status = self.subscriber.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.subscriber.tls_verify, self.subscriber.dhcp_next_verify,
                                                           self.subscriber.igmp_next_verify, self.subscriber.traffic_verify),
                                                    port_list = self.subscriber.generate_port_list(num_subscribers, num_channels),
                                                    negative_subscriber_auth = 'all')
            assert_equal(test_status, True)
	self.subscriber.tearDownClass(controller=master)

    #pass
    def test_cluster_with_multiple_ovs_switches(self,onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	device_dict = self.get_cluster_current_master_standbys_of_connected_devices()
	for device in device_dict.keys():
	    log.info("Device is %s"%device_dict[device])
	    assert_not_equal(device_dict[device]['master'],'none')
	    log.info('Master and standbys for device %s are %s and %s'%(device,device_dict[device]['master'],device_dict[device]['standbys']))
	    assert_equal(len(device_dict[device]['standbys']), onos_instances-1)

    #pass
    def test_cluster_state_in_multiple_ovs_switches(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        device_dict = self.get_cluster_current_master_standbys_of_connected_devices()
	cluster_ips = self.get_cluster_current_member_ips()
	for ip in cluster_ips:
	    device_dict= self.get_cluster_current_master_standbys_of_connected_devices(controller = ip)
	    assert_equal(len(device_dict.keys()),onos_instances)
            for device in device_dict.keys():
                log.info("Device is %s"%device_dict[device])
                assert_not_equal(device_dict[device]['master'],'none')
                log.info('Master and standbys for device %s are %s and %s'%(device,device_dict[device]['master'],device_dict[device]['standbys']))
                assert_equal(len(device_dict[device]['standbys']), onos_instances-1)

    #pass
    def test_cluster_verifying_multiple_ovs_switches_after_master_is_restarted(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	onos_names_ips =  self.get_cluster_container_names_ips()
	master_count = self.get_number_of_devices_of_master()
        log.info('Master count information is %s'%master_count)
	total_devices = 0
	for master in master_count.keys():
	    total_devices += master_count[master]['size']
	    if master_count[master]['size'] != 0:
		restart_ip = master
	assert_equal(total_devices,onos_instances)
	member_onos_name = onos_names_ips[restart_ip]
	log.info('Restarting cluster member %s having ip %s'%(member_onos_name,restart_ip))
        Container(member_onos_name, Onos.IMAGE).restart()
	time.sleep(40)
	master_count = self.get_number_of_devices_of_master()
	log.info('Master count information after restart is %s'%master_count)
	total_devices = 0
        for master in master_count.keys():
            total_devices += master_count[master]['size']
	    if master == restart_ip:
		assert_equal(master_count[master]['size'], 0)
	assert_equal(total_devices,onos_instances)

    #pass
    def test_cluster_verifying_multiple_ovs_switches_with_one_master_down(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_count = self.get_number_of_devices_of_master()
        log.info('Master count information is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += master_count[master]['size']
            if master_count[master]['size'] != 0:
                restart_ip = master
        assert_equal(total_devices,onos_instances)
        master_onos_name = onos_names_ips[restart_ip]
        log.info('Shutting down cluster member %s having ip %s'%(master_onos_name,restart_ip))
        Container(master_onos_name, Onos.IMAGE).kill()
        time.sleep(40)
	for ip in onos_names_ips.keys():
	    if ip != restart_ip:
		controller_ip = ip
	status = self.verify_cluster_status(onos_instances=onos_instances-1,controller=controller_ip)
        assert_equal(status, True)
        master_count = self.get_number_of_devices_of_master(controller=controller_ip)
        log.info('Master count information after restart is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += master_count[master]['size']
            if master == restart_ip:
                assert_equal(master_count[master]['size'], 0)
        assert_equal(total_devices,onos_instances)

    #pass
    def test_cluster_verifying_multiple_ovs_switches_with_current_master_withdrawing_mastership(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master_count = self.get_number_of_devices_of_master()
        log.info('Master count information is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += int(master_count[master]['size'])
            if master_count[master]['size'] != 0:
                master_ip = master
		log.info('Devices of master %s are %s'%(master_count[master]['devices'],master))
		device_id = str(master_count[master]['devices'][0])
		device_count = master_count[master]['size']
        assert_equal(total_devices,onos_instances)
	log.info('Withdrawing mastership of device %s for controller %s'%(device_id,master_ip))
	status=self.withdraw_cluster_current_mastership(master_ip=master_ip,device_id = device_id)
        assert_equal(status, True)
        master_count = self.get_number_of_devices_of_master()
        log.info('Master count information after cluster mastership withdraw is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += int(master_count[master]['size'])
            if master == master_ip:
                assert_equal(master_count[master]['size'], device_count-1)
        assert_equal(total_devices,onos_instances)

    #pass
    def test_cluster_verifying_multiple_ovs_switches_and_restarting_cluster(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master_count = self.get_number_of_devices_of_master()
        log.info('Master count information is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += master_count[master]['size']
        assert_equal(total_devices,onos_instances)
        log.info('Restarting cluster')
	cord_test_onos_restart()
	time.sleep(60)
        master_count = self.get_number_of_devices_of_master()
        log.info('Master count information after restart is %s'%master_count)
        total_devices = 0
        for master in master_count.keys():
            total_devices += master_count[master]['size']
        assert_equal(total_devices,onos_instances)
