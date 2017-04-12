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
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from functools import partial
#from CordContainer import Onos
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
sys.path.append(utils_dir)
sys.path.insert(1, '/usr/local/lib/python2.7/dist-packages/requests')
import time, monotonic
from CordContainer import Onos
from OnosLog import OnosLog
from CordLogger import CordLogger
from CordTestUtils import log_test as log
import os
import json
import random
import collections
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo,LinearTopo,Topo
from mininet.topolib import TreeTopo
#from mininet.clean import Cleanup
from mininet.node import Controller, RemoteController, Switch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.node import CPULimitedHost
log.setLevel('INFO')

class mininet_exchange(unittest.TestCase):
    app = 'org.onosproject.fwd'
    controller = os.getenv('ONOS_CONTROLLER_IP') or 'localhost'
    controller = controller.split(',')[0]

    @classmethod
    def setUpClass(cls):
	pass

    @classmethod
    def tearDownClass(cls):
	pwd = os.getcwd()
	log.info('teardown- current working dir is %s'%pwd)
	os.chdir('/root')
	cmds = ['rm -r mininet','apt-get remove mininet']
	for cmd in cmds:
            os.system(cmd)
        os.chdir(pwd)
        log.info('teardown- dir after removing mininet is %s'%os.getcwd())
        time.sleep(5)

    def setUp(self):
        self.onos_ctrl = OnosCtrl(self.app)
        self.onos_ctrl.activate()

    def tearDown(self):
        self.onos_ctrl = OnosCtrl(self.app)
        self.onos_ctrl.deactivate()

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

    def test_creation_of_topology(self):
        try:
            net = Mininet( topo=None, build=False)
            h1 = net.addHost( 'h1')
            h2 = net.addHost( 'h2' )
            h3 = net.addHost( 'h3' )
            s1 = net.addSwitch( 's1', dpid="0000000000000201")
            s2 = net.addSwitch( 's2', dpid="0000000000000202")
            s3 = net.addSwitch( 's3', dpid="0000000000000203")
            net.addLink(h1, s1, )
            net.addLink(h2, s2, )
            net.addLink(h3, s3, )
            net.addLink(s1, s2, )
            net.addLink(s2, s3, )
            #net.build()
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
	    s1.start( [ctrl] )
            s2.start( [ctrl] )
            s3.start( [ctrl] )
	    #CLI(net)
	    for switch in net.switches:
		log.info('dpid of switch is %s'%switch.dpid)
	    for host in net.hosts:
	   	log.info('host %s added with IP addres %s'%(host.name,host.IP()))
            net.stop()
	    log.info('Successfully created  mininet topology and connected to cluster controllers')
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_creation_of_single_switch_topology(self,hosts=5):
        try:
            topo = SingleSwitchTopo(hosts)
            net = Mininet(topo=topo )
            net.start()
            log.info('Node connections are %s'%dumpNodeConnections(net.hosts))
      	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
	    for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response is %s'%response)
            assert_equal(response,0.0)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_creation_of_linear_topology(self,switches=5):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            log.info('Node connections are %s'%dumpNodeConnections(net.hosts))
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response is %s'%response)
            assert_equal(response,0.0)
	    #CLI(net)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating minine topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_creation_of_tree_topology(self):
        try:
            topo = TreeTopo(depth=2,fanout=2)
            net = Mininet(topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response is %s'%response)
            assert_equal(response,0.0)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_executing_commands_from_mininet_host(self,switches=4):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            for host in net.hosts:
                result = host.cmd('ping -c 2', net.switches[0].IP())
                log.info('Result is %s'%result)
                res = result.find('icmp_seq')
                assert_not_equal(res, -1)
            net.stop()
        except Exception as Error:
            Cleanup.cleanup()
            log.info('Error while creating topology is %s'%Error)
            raise
        Cleanup.cleanup()

    def test_verifying_pingall_from_mininet(self,switches=5):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                log.info('switch is %s'%switch  )
                switch.start([ctrl])
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            assert_equal(response,0.0)
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_initiating_pingall_from_mininet_with_onos_app_deactivation(self,switches=3):
        try:
	    topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('PingAll response before onos app \'org.onosproject.fwd\' deactivate is %s'%response)
            assert_equal(response, 0.0)
            OnosCtrl(self.app).deactivate()
            response = net.pingAll()
            log.info('PingAll response after onos app \'org.onosproject.fwd\' deactivate is %s'%response)
            assert_equal(response, 100.0)
	    net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
	Cleanup.cleanup()

    def test_verifying_mininet_hosts_in_onos_controller(self,switches=4):
        try:
	    topo = LinearTopo(switches)
            net = Mininet( topo=topo)
	    net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            log.info('mininet all the devices IDs %s'%net.keys())
            log.info('mininet all the devices details %s'%net.values())
            log.info('mininet all the devices information %s'%net.items())
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            assert_equal(response, 0.0)
            self.cliEnter()
            hosts = json.loads(self.cli.hosts(jsonFormat = True))
            log.info('Discovered hosts: %s' %hosts)
            assert_equal(len(hosts),switches)
            self.cliExit()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_tcp_bandwidth_measure_between_mininet_hosts_using_iperf(self):
        try:
	    topo = TreeTopo(depth=2,fanout=2)
            net = Mininet( topo=topo, host=CPULimitedHost, link=TCLink, build=False)
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('PingAll response is %s'%response)
            bandwidth = net.iperf()
            log.info('TCP Bandwidth between hosts measured using iperf is %s'%bandwidth)
            assert_equal(len(bandwidth),2)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_udp_bandwidth_measure_between_mininet_hosts_using_iperf(self):
        try:
            topo = TreeTopo(depth=2,fanout=2)
            net = Mininet( topo=topo, host=CPULimitedHost, link=TCLink, build=False)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            bandwidth = net.iperf(l4Type = 'UDP')
            log.info('UDP Bandwidth between hosts measured using iperf is %s'%bandwidth)
            assert_equal(len(bandwidth),3)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_tcp_bandwidth_between_mininet_hosts_using_iperf_with_one_host_removed(self,switches=3):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            iperf = net.iperf(l4Type='TCP')
            log.info('Iperf response before host removed is %s'%iperf)
            assert_equal(len(iperf),2)
	    net.delNode(net.hosts[2])
            iperf = net.iperf(l4Type='TCP')
            log.info('Iperf response after host removed is %s'%iperf)
	    assert_equal(len(iperf),2)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_udp_bandwidth_between_mininet_hosts_using_iperf_with_one_host_removed(self,switches=3):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            iperf = net.iperf(l4Type='UDP')
            log.info('Iperf response before host removed is %s'%iperf)
            assert_equal(len(iperf),3)
            net.delNode(net.hosts[2])
            iperf = net.iperf(l4Type='UDP')
            log.info('Iperf response after host removed is %s'%iperf)
	    assert_equal(len(iperf),3)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_hosts_assigned_with_non_default_ip_address(self):
        try:
            net = Mininet( topo=None, controller=RemoteController, host=CPULimitedHost, link=TCLink, build=False)
            h1 = net.addHost( 'h1', ip='192.168.10.1/24' )
            h2 = net.addHost( 'h2', ip='192.168.10.10/24' )
            s1 = net.addSwitch( 's1')
            s2 = net.addSwitch( 's2')
            net.addLink(h1, s1, )
            net.addLink(h2, s2, )
            net.addLink(s1, s2, )
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            net.start()
            assert_equal(net.hosts[0].IP(),'192.168.10.1')
            assert_equal(net.hosts[1].IP(),'192.168.10.10')
            response = net.pingAll()
            log.info('PingAll response is %s'%response)
            assert_equal(response,0.0)
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_hosts_assigned_with_non_default_ip_address_in_different_subnets(self):
        try:
            net = Mininet( topo=None, controller=RemoteController, host=CPULimitedHost, link=TCLink, build=False)
            h1 = net.addHost( 'h1', ip='192.168.10.10/24' )
            h2 = net.addHost( 'h2', ip='192.168.20.10/24' )
            s1 = net.addSwitch( 's1')
            s2 = net.addSwitch( 's2')
            net.addLink(h1, s1, )
            net.addLink(h2, s2, )
            net.addLink(s1, s2, )
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            assert_equal(net.hosts[0].IP(),'192.168.10.10')
            assert_equal(net.hosts[1].IP(),'192.168.20.10')
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            assert_equal(response,100.0)
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pingall_with_connection_remove_between_switches(self,switches=4):
        try:
	    topo = LinearTopo(switches)
            net = Mininet(topo=topo)
	    #net.build()
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response before link delete is %s'%response)
            assert_equal(response,0.0)
            log.info('Deleting link between switches s1 and s2')
            net.delLinkBetween(net.switches[0], net.switches[1], )
            response = net.pingAll()
            log.info('Pingall response after the link delete is is %s'%response)
            assert_not_equal(response,0.0)
            net.stop()
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pingall_with_removing_one_mininet_host(self,switches=3):
        try:
	    topo = LinearTopo(switches)
            net = Mininet(topo=topo)
	    #net.build()
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response before host delete is %s'%response)
            assert_equal(response,0.0)
            log.info('removing host h2')
            net.delNode(net.hosts[1])
            response = net.pingAll()
            log.info('Pingall response after host delete is %s'%response)
            assert_equal(response,0)
            net.stop()
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pingall_with_removing_one_mininet_switch(self,switches=3):
        try:
	    topo = LinearTopo(switches)
            net = Mininet(topo=topo)
	    #net.build()
            net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response before switch delete is %s'%response)
            assert_equal(response,0.0)
            log.info('Deleting switch s2')
            net.delNode(net.switches[1])
            response = net.pingAll()
            log.info('Pingall response after switch delete is %s'%response)
            assert_not_equal(response,0.0)
            net.stop()
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_mininet_switch_status_in_onos_controller(self,switches=4):
        try:
	    topo = LinearTopo(switches)
            net = Mininet(topo=topo, build=False)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('Pingall response is %s'%response)
            assert_equal(response,0.0)
            self.cliEnter()
            devices = json.loads(self.cli.devices(jsonFormat = True))
	    count = 0
	    switch_ids = []
	    for switch in net.switches:
                dvcid = 'of:'+switch.dpid
                switch_ids.append(dvcid)
	    for device in devices:
	        if str(device['id']) in switch_ids:
	            assert_equal(str(device['available']), 'True')
		    count += 1
	    assert_equal(count,switches)
            self.cliExit()
            net.stop()
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verify_host_status_in_onos_controller_with_removing_one_mininet_host(self,switches=5):
        try:
	    topo = LinearTopo(switches)
            net = Mininet( topo=topo, build=False)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('pingall response is %s'%response)
            assert_equal(response,0.0)
            self.cliEnter()
            hosts = json.loads(self.cli.hosts(jsonFormat = True))
	    log.info('Discovered Hosts are %s'%hosts)
            assert_equal(len(hosts),switches)
            log.info('removing host h2')
            net.delNode(net.hosts[0])
            hosts = json.loads(self.cli.hosts(jsonFormat = True))
            assert_equal(len(hosts),switches-1)
            self.cliExit()
            net.stop()
        except Exception as Error:
            log.info('Got error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pushing_mac_flows_from_onos_controller_to_mininet_switches(self,switches=3):
        try:
            topo = LinearTopo(switches)
            net = Mininet( topo=topo)
            net.start()
            egress_mac = RandMAC()._fix()
            ingress_mac = RandMAC()._fix()
            egress = 1
            ingress = 2
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            self.cliEnter()
            devices = json.loads(self.cli.devices(jsonFormat = True))
            for switch in net.switches:
		dvcid = 'of:'+switch.dpid
                flow = OnosFlowCtrl(deviceId = dvcid,
                                        egressPort = egress,
                                        ingressPort = ingress,
                                        ethSrc = ingress_mac,
                                        ethDst = egress_mac)
                result = flow.addFlow()
                assert_equal(result, True)
	    self.cliExit()
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pushing_ipv4_flows_from_onos_controller_to_mininet_switches(self,switches=5):
        try:
            topo = LinearTopo(switches)
            net = Mininet( topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            egress = 1
            ingress = 2
            egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
            ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
            response = net.pingAll()
            log.info('pingAll response is %s'%response)
            for switch in net.switches:
		dvcid = 'of:'+switch.dpid
                flow = OnosFlowCtrl(deviceId = dvcid,
                                    egressPort = egress,
                                    ingressPort = ingress,
                                    ethType = '0x0800',
				    ipSrc = ('IPV4_SRC', ingress_map['ip']+'/32'),
                                    ipDst = ('IPV4_DST', egress_map['ip']+'/32')
                                    )
                result = flow.addFlow()
                assert_equal(result, True)
            net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_pushing_ipv6_flows_from_onos_controller_to_mininet_switches(self,switches=5):
	try:
	    topo = LinearTopo(switches)
	    net = Mininet( topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                switch.start( [ctrl] )
            egress = 1
            ingress = 2
            egress_map = { 'ether': '00:00:00:00:00:03', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1001' }
            ingress_map = { 'ether': '00:00:00:00:00:04', 'ipv6': '2001:db8:a0b:12f0:1010:1010:1010:1002' }
	    response = net.pingAll()
            log.info('pingAll response is %s'%response)
            for switch in net.switches:
		dvcid = 'of:'+switch.dpid
                flow = OnosFlowCtrl(deviceId = dvcid,
                                    egressPort = egress,
                                    ingressPort = ingress,
                                    ethType = '0x86dd',
                            	    ipSrc = ('IPV6_SRC', ingress_map['ipv6'] + '/48'),
                            	    ipDst = ('IPV6_DST', egress_map['ipv6'] + '/48')
                                    )
                result = flow.addFlow()
                assert_equal(result, True)
            net.stop()
   	except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_topology_created_with_50_switches_in_onos_controller(self,switches=50):
	try:
	    topo = LinearTopo(switches)
	    net = Mininet(topo=topo)
	    net.start()
	    ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
	    for switch in net.switches:
                switch.start([ctrl])
	    time.sleep(5)
	    self.cliEnter()
            devices = json.loads(self.cli.devices(jsonFormat = True))
	    device_list = []
	    count = 0
	    for device in devices:
		device_list.append(str(device['id']))
	    log.info('device list is %s'%device_list)
	    for switch in net.switches:
                switch_id = 'of:'+switch.dpid
		if switch_id in device_list:
		    count += 1
	    assert_equal(count,switches)
	    self.cliExit()
	    net.stop()
	except Exception as Error:
	    log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
	Cleanup.cleanup()

    def test_topology_created_with_200_switches_in_onos_controller(self,switches=200):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                log.info('switch is %s'%switch  )
                switch.start([ctrl])
	    time.sleep(10)
	    self.cliEnter()
            devices = json.loads(self.cli.devices(jsonFormat = True))
            device_list = []
            count = 0
	    for device in devices:
                device_list.append(str(device['id']))
            log.info('device list is %s'%device_list)
            for switch in net.switches:
                switch_id = 'of:'+switch.dpid
                if switch_id in device_list:
                    count += 1
            assert_equal(count,switches)
	    self.cliExit()
	    net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()

    def test_verifying_nodes_removed_in_mininet_status_in_onos_controller(self,switches=50, delete=20):
        try:
            topo = LinearTopo(switches)
            net = Mininet(topo=topo)
            net.start()
            o1_ctrl = net.addController( 'onos', controller=RemoteController, ip=self.controller, port=6653)
            for switch in net.switches:
                log.info('switch is %s'%switch)
                switch.start([o1_ctrl])
	    time.sleep(5)
	    self.cliEnter()
            devices = json.loads(self.cli.devices(jsonFormat = True))
            device_list = []
            count = 0
            for device in devices:
                device_list.append(str(device['id']))
            log.info('device list is %s'%device_list)
            for switch in net.switches:
                switch_id = 'of:'+switch.dpid
                if switch_id in device_list:
                    count += 1
            assert_equal(count,switches)
	    count = 0
	    dltd_list = []
	    for switch in net.switches:
                log.info('Switch is %s'%switch)
	        dltd_list.append('of:'+switch.dpid)
                net.delNode(switch)
                count += 1
                if count == delete:
                    break
	    log.info('deleted switch dpid\'s %s'%dltd_list)
	    count = 0
	    devices = json.loads(self.cli.devices(jsonFormat = True))
	    for device in devices:
		if str(device['id']) in dltd_list:
		    assert_equal(str(device['available']), 'False')
		    count += 1
	    assert_equal(count,delete)
	    self.cliExit()
	    net.stop()
        except Exception as Error:
            log.info('Got unexpected error %s while creating topology'%Error)
            Cleanup.cleanup()
            raise
        Cleanup.cleanup()
