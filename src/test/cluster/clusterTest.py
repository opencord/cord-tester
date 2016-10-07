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
from CordTestServer import cord_test_onos_restart, cord_test_onos_shutdown, cord_test_onos_add_cluster, cord_test_quagga_restart
from portmaps import g_subscriber_port_map
from scapy.all import *
import time, monotonic
import threading
from threading import current_thread
from Cluster import *
from EapTLS import TLSAuthTest
from ACL import ACLTest
import os
import json
import random
import collections
log.setLevel('INFO')

class cluster_exchange(unittest.TestCase):
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

    def get_controller(self):
        controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
        controller = controller.split(',')[0]
        return controller

    def cliEnter(self,controller = None):
        retries = 0
        while retries < 3:
            self.cli = OnosCliDriver(controller = controller,connect = True)
            if self.cli.handle:
                break
            else:
                retries += 1
                time.sleep(2)

    def cliExit(self):
        self.cli.disconnect()

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
	   raise
	   return False

    def get_cluster_current_member_ips(self,controller = None):
        tries = 0
	cluster_ips = []
        try:
            self.cliEnter(controller = controller)
            while tries <= 10:
                cluster_nodes = json.loads(self.cli.nodes(jsonFormat = True))
                if cluster_nodes:
                    log.info("cluster 'nodes' output is %s"%cluster_nodes)
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

    def get_cluster_container_names_ips(self):
        onos_names_ips = {}
        onos_ips = self.get_cluster_current_member_ips()
        onos_names_ips[onos_ips[0]] = Onos.NAME
	for i in range(1, len(onos_ips)):
	    name = '{0}-{1}'.format(Onos.NAME,i+1)
	    onos_names_ips[onos_ips[i]] = name

        return onos_names_ips

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
            return master, standbys
	except:
	    raise Exception('Cannot get cluster master and standbys')
	    return master, standbys

    def change_master_current_cluster(self,new_master=None,device_id=device_id,controller=None):
	if new_master is None: return False
	self.cliEnter()
        cmd = 'device-role' + ' ' + device_id + ' ' + new_master + ' ' + 'master'
        command = self.cli.command(cmd = cmd, jsonFormat = False)
        self.cliExit()
        time.sleep(60)
        master, standbys = self.get_cluster_current_master_standbys(controller=controller,device_id=device_id)
        assert_equal(master,new_master)
	log.info('Cluster master changed to %s successfully'%new_master)

############# Cluster Test cases ###########################
    #pass
    def test_onos_cluster_formation_verify(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        log.info('Cluster exists with %d ONOS instances'%onos_instances)

    #nottest cluster not coming up properly if member goes down
    def test_onos_cluster_adding_members(self,add = 2, onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances = onos_instances)
	assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
	onos_instances = len(onos_ips)+add
        log.info('Adding %d nodes to the ONOS cluster' %add)
        cord_test_onos_add_cluster(count = add)
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)

    def test_onos_cluster_removing_master(self, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        log.info('Removing cluster current master %s'%(master))
        cord_test_onos_shutdown(node = master_onos_name)
        time.sleep(60)
        onos_instances -= 1
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=standbys[0])
        assert_equal(status, True)
	new_master, standbys = self.get_cluster_current_master_standbys(controller=standbys[0])
	assert_not_equal(master,new_master)
	log.info('Successfully removed cluster master instance')

    def test_onos_cluster_removing_one_member(self, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
	log.info('Removing cluster member %s'%standbys[0])
        cord_test_onos_shutdown(node = member_onos_name)
	time.sleep(60)
	onos_instances -= 1
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=master)
        assert_equal(status, True)

    def test_onos_cluster_removing_two_members(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
       	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
        member2_onos_name = onos_names_ips[standbys[1]]
        log.info('Removing cluster member %s'%standbys[0])
        cord_test_onos_shutdown(node = member1_onos_name)
        log.info('Removing cluster member %s'%standbys[1])
        cord_test_onos_shutdown(node = member2_onos_name)
        time.sleep(60)
        onos_instances = onos_instances - 2
        status = self.verify_cluster_status(onos_instances = onos_instances,controller=master)
        assert_equal(status, True)

    def test_onos_cluster_removing_N_members(self,remove = 2, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        for i in range(remove):
	    member_onos_name = onos_names_ips[standbys[i]]
            log.info('Removing onos container with name %s'%standbys[i])
            cord_test_onos_shutdown(node = member_onos_name)
        time.sleep(60)
        onos_instances = onos_instances - remove
        status = self.verify_cluster_status(onos_instances = onos_instances, controller=master)
        assert_equal(status, True)

    #nottest test cluster not coming up properly if member goes down
    def test_onos_cluster_adding_and_removing_members(self,onos_instances = ONOS_INSTANCES ,add = 2, remove = 2):
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
    def test_onos_cluster_removing_and_adding_member(self,onos_instances = ONOS_INSTANCES,add = 1, remove = 1):
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

    def test_onos_cluster_restart(self,onos_instances = ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Restarting cluster')
	cord_test_onos_restart()
	status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)

    def test_onos_cluster_master_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master]
        log.info('Restarting cluster master %s'%master)
        cord_test_onos_restart(node = master_onos_name)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up after master restart as expected')

    #test fail. master changing after restart. Need to check correct behavior.
    def test_onos_cluster_master_ip_after_master_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        master1, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        master_onos_name = onos_names_ips[master1]
        log.info('Restarting cluster master %s'%master)
        cord_test_onos_restart(node = master_onos_name)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master2, standbys = self.get_cluster_current_master_standbys()
	assert_equal(master1,master2)
        log.info('Cluster master is same before and after cluster master restart as expected')

    def test_onos_cluster_one_member_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
	member_onos_name = onos_names_ips[standbys[0]]
        log.info('Restarting cluster member %s'%standbys[0])
        cord_test_onos_restart(node = member_onos_name)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting one member')

    def test_onos_cluster_two_members_restart(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
        member2_onos_name = onos_names_ips[standbys[1]]
        log.info('Restarting cluster members %s and %s'%(standbys[0],standbys[1]))
        cord_test_onos_restart(node = member1_onos_name)
        cord_test_onos_restart(node = member2_onos_name)
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting two members')

    def test_onos_cluster_N_members_restart(self, members = 2, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status,True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
	for i in range(members):
            member_onos_name = onos_names_ips[standbys[i]]
	    log.info('Restarting cluster member %s'%standbys[i])
            cord_test_onos_restart(node = member_onos_name)

        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
	log.info('Cluster came up as expected after restarting %d members'%members)

    def test_onos_cluster_master_change(self,onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
	assert_equal(len(standbys),(onos_instances-1))
        log.info('Cluster current master of device is %s'%master)
	self.change_master_current_cluster(new_master=standbys[0])
        log.info('Cluster master changed successfully')

    #tested on single onos setup.
    def test_onos_cluster_vrouter_routes_in_cluster_members(self,networks = 5,onos_instances = ONOS_INSTANCES):
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
    def test_onos_cluster_vrouter_master_down(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        onos_ips = self.get_cluster_current_member_ips()
	master, standbys = self.get_cluster_current_master_standbys()
	onos_names_ips =  self.get_cluster_container_names_ips()
	master_onos_name = onos_names_ips[master]
        self.vrouter.setUpClass()
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
	assert_equal(res,True)
        cord_test_onos_shutdown(node = master_onos_name)
	time.sleep(60)
	log.info('Verifying vrouter traffic after cluster master down')
	self.vrouter.vrouter_traffic_verify()

    #tested on single onos setup.
    def test_onos_cluster_with_vrouter_and_restarting_master(self,networks = 5,onos_instances = ONOS_INSTANCES):
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
    def test_onos_cluster_deactivating_vrouter_app(self,networks = 5, onos_instances = ONOS_INSTANCES):
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
    def test_onos_cluster_deactivating_vrouter_app_and_making_master_down(self,networks = 5,onos_instances = ONOS_INSTANCES):
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
        cord_test_onos_shutdown(node = master_onos_name)
	time.sleep(60)
	self.vrouter.vrouter_traffic_verify(positive_test=False)
        self.vrouter.vrouter_activate(deactivate=False)

    #tested on single onos setup.
    def test_onos_cluster_for_vrouter_app_and_making_member_down(self,networks = 5,onos_instances = ONOS_INSTANCES):
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
        cord_test_onos_shutdown(node = member_onos_name)
	time.sleep(60)
	self.vrouter.vrouter_traffic_verify()# Expecting vrouter should work properly if member of cluster goes down

    #tested on single onos setup.
    def test_onos_cluster_for_vrouter_app_and_restarting_member(self,networks = 5, onos_instances = ONOS_INSTANCES):
        status = self.verify_cluster_status(onos_instances = onos_instances)
        assert_equal(status, True)
        master, standbys = self.get_cluster_current_master_standbys()
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[1]]
        self.vrouter.setUpClass()
        log.info('Verifying vrouter traffic before cluster member restart')
        res = self.vrouter.vrouter_network_verify(networks, peers = 1)
        assert_equal(res, True) # Expecting vrouter should work properly
        cord_test_onos_restart(node = member_onos_name)
	log.info('Verifying vrouter traffic after cluster member restart')
        self.vrouter.vrouter_traffic_verify()# Expecting vrouter should work properly if member of cluster restarts

    #tested on single onos setup.
    def test_onos_cluster_for_vrouter_app_restarting_cluster(self,networks = 5, onos_instances = ONOS_INSTANCES):
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
    def test_onos_cluster_for_flows_of_udp_port_and_making_master_down(self, onos_instances = ONOS_INSTANCES):
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
                cord_test_onos_shutdown(node = master_onos_name)
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

    def test_onos_cluster_making_master_change_and_flows_of_ecn(self,onos_instances = ONOS_INSTANCES):
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

    @deferred(TLS_TIMEOUT)
    def test_onos_cluster_with_eap_tls_traffic(self,onos_instances=ONOS_INSTANCES):
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
    def test_onos_cluster_for_eap_tls_traffic_before_and_after_master_change(self,onos_instances=ONOS_INSTANCES):
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
    def test_onos_cluster_for_eap_tls_traffic_before_and_after_making_master_down(self,onos_instances=ONOS_INSTANCES):
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
                cord_test_onos_shutdown(node = master_onos_name)
		time.sleep(20)
                status = self.verify_cluster_status(controller=standbys[0],onos_instances=onos_instances-1,verify=True)
		assert_equal(status, True)
		log.info('Cluster came up with %d instances after killing master'%(onos_instances-1))
                log.info('Verifying tls authentication after killing cluster master')
            reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_onos_cluster_for_eap_tls_with_no_cert_before_and_after_member_is_restarted(self,onos_instances=ONOS_INSTANCES):
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

###### Dhcp Relay Test cases  ######################################

    def test_onos_cluster_with_dhcpRelay_app_releasing_dhcp_ip_after_master_change(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.dhcprelay.setUpClass()
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
                         subnet = subnet)
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
	self.dhcprelay.tearDownClass()

    def test_onos_cluster_with_dhcpRelay_app_simulating_client_by_changing_master(self, iface = 'veth0',onos_instances=ONOS_INSTANCES):
	#status = self.verify_cluster_status(onos_instances=onos_instances)
        #assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
	self.dhcprelay.setUpClass()
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
                         subnet = subnet)
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
	self.dhcprelay.tearDownClass()


############ Cord Subscriber Test cases ##################

    def test_onos_cluster_with_cord_subscriber_joining_next_channel_before_and_after_cluster_restart(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
        """Test subscriber join next for channel surfing"""
	self.subscriber.setUpClass()
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
	self.subscriber.tearDownClass()

    def test_onos_cluster_with_cord_subscriber_joining_10channels_making_one_cluster_member_down(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member_onos_name = onos_names_ips[standbys[0]]
	self.subscriber.setUpClass()
	num_subscribers = 1
        num_channels = 10
	for i in [0,1]:
	    if i == 1:
                cord_test_onos_shutdown(node = member_onos_name)
		time.sleep(30)
		status = self.verify_cluster_status(onos_instances=onos_instances-1,verify=True)
                assert_equal(status, True)
		log.info('Verifying cord subscriber functionality after cluster member %s is down'%standbys[0])
	    else:
		log.info('Verifying cord subscriber functionality before cluster member %s is down'%standbys[0])
            test_status = self.subscriber.subscriber_join_verify(num_subscribers = num_subscribers,
                                                    num_channels = num_channels,
                                                    cbs = (self.subscriber.tls_verify, self.subscriber.dhcp_verify,
                                                              self.subscriber.igmp_verify, self.subscriber.traffic_verify),
                                                    port_list = self.subscriber.generate_port_list(num_subscribers, num_channels),
                                                    negative_subscriber_auth = 'all')
            assert_equal(test_status, True)
	self.subscriber.tearDownClass()

    def test_onos_cluster_cord_subscriber_joining_next_10channels_making_two_cluster_members_down(self,onos_instances=ONOS_INSTANCES):
	status = self.verify_cluster_status(onos_instances=onos_instances)
        assert_equal(status, True)
	master, standbys = self.get_cluster_current_master_standbys()
        assert_equal(len(standbys),(onos_instances-1))
        onos_names_ips =  self.get_cluster_container_names_ips()
        member1_onos_name = onos_names_ips[standbys[0]]
	member2_onos_name = onos_names_ips[standbys[1]]
	self.subscriber.setUpClass()
        num_subscribers = 1
        num_channels = 10
	for i in [0,1]:
	    if i == 1:
                cord_test_onos_shutdown(node = member1_onos_name)
                cord_test_onos_shutdown(node = member2_onos_name)
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
	self.subscriber.tearDownClass()

