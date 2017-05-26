#
# Copyright 2016-present Ciena Corporation
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
import os,sys
import keystoneclient.v2_0.client as ksclient
import keystoneclient.apiclient.exceptions
import neutronclient.v2_0.client as nclient
import neutronclient.common.exceptions
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client
import neutronclient.v2_0.client as neutronclient
from nose.tools import assert_equal
from CordTestUtils import get_mac, log_test
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl
from OnosFlowCtrl import OnosFlowCtrl
from OnboardingServiceUtils import OnboardingServiceUtils
from SSHTestAgent import SSHTestAgent
from CordTestUtils import running_on_pod, getstatusoutput
from CordLogger import CordLogger
from CordTestUtils import log_test as log
import requests
import time
import json
from VSGAccess import VSGAccess
from CordTestConfig import setup_module, running_on_ciab
from vsgTest import *
log.setLevel('INFO')

class onboarding_exchange(CordLogger):
    ONOS_INSTANCES = 3
    V_INF1 = 'veth0'
    device_id = 'of:' + get_mac()
    TEST_IP = '8.8.8.8'
    HOST = "10.1.0.1"
    USER = "vagrant"
    PASS = "vagrant"
    head_node = os.getenv('HEAD_NODE', 'prod')
    HEAD_NODE = head_node + '.cord.lab' if len(head_node.split('.')) == 1 else head_node
    test_path = os.path.dirname(os.path.realpath(__file__))
    on_pod = running_on_pod()
    vcpe_dhcp = 'vcpe0.222.111'
    vsg_exchange = vsg_exchange()
    vm_name = 'mysite_exampleservice'

    @classmethod
    def setUpClass(cls):
        OnboardingServiceUtils.setUp()
	cls.vsg_exchange.setUpClass()

    @classmethod
    def tearDownClass(cls):
        OnboardingServiceUtils.tearDown()

    def cliEnter(self,  controller = None):
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

    def onos_shutdown(self,  controller = None):
        status = True
        self.cliEnter(controller = controller)
        try:
            self.cli.shutdown(timeout = 10)
        except:
            log.info('Graceful shutdown of ONOS failed for controller: %s' %controller)
            status = False

        self.cliExit()
        return status

    def get_exampleservice_vm_public_ip(self, vm_name = 'mysite_exampleservice'):
	if not vm_name:
		vm_name = self.vm_name
	exampleservices = OnboardingServiceUtils.get_exampleservices()
	for service in exampleservices:
		if vm_name in service.name:
			return service.get_public_ip()
	return None

    def test_exampleservice_health(self):
        """
        Algo:
        1. Login to compute node VM
        2. Get all exampleservice
        3. Ping to all exampleservice
        4. Verifying Ping success
        """
        status = OnboardingServiceUtils.health_check()
        assert_equal(status, True)

    def test_exampleservice_for_login(self):
        if self.on_pod is False:
            return
        exampleservices = OnboardingServiceUtils.get_exampleservices()
	exampleservice_access_status = map(lambda exampleservice: exampleservice.check_access(), exampleservices)
        status = filter(lambda st: st == False, exampleservice_access_status)
        assert_equal(len(status), 0)

    def test_exampleservice_for_default_route_through_testclient(self):
        if self.on_pod is False:
           return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_exampleservice_for_service_access_through_testclient(self):
        if self.on_pod is False:
            return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- ping -c 3 8.8.8.8"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal( status, True)

    def test_exampleservice_for_service_reachability_from_cord_tester(self, vcpe_intf=None):
        if self.on_pod is False:
            return
	if not vcpe_intf:
		vcpe_intf = self.dhcp_vcpes_reserved[0]
	vm_public_ip = self.get_exampleservice_vm_public_ip()
	self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        vm_public_ip = self.get_exampleservice_vm_public_ip()
	st, _ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        assert_equal(st, False)
	self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)

    def test_exampleservice_operational_status_from_testclient(self):
	vm_public_ip = self.get_exampleservice_vm_public_ip()
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = 'sudo lxc exec testclient -- apt-get install -y curl'
        status, _  = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)
        #Test connectivity to ExampleService from test client
        cmd = 'sudo lxc exec testclient -- curl -s http://{}'.format(vm_public_ip)
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    def test_exampleservice_operational_access_from_cord_tester(self, vcpe_intf=None):
        if self.on_pod is False:
            return
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
	vm_public_ip = self.get_exampleservice_vm_public_ip()
        self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        st, _ = getstatusoutput('curl -s http://{}'.format(vm_public_ip))
        assert_equal(st, False)

    def test_exampleservice_for_service_message(self, service_message='"'+'hello'+'"'):
	vm_public_ip = self.get_exampleservice_vm_public_ip()
	vcpe_intf = self.vcpe_dhcp
	try:
	    self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            st,out = getstatusoutput('curl -s http://{}'.format(vm_public_ip))
            assert_equal(st, False)
            output = out.split('\n')
	    srvs_msg = ''
            for line in output:
                line = line.split(':')
                if line[0].strip() == 'Service Message':
                    srvs_msg = line[1].strip()
	    assert_equal(service_message, srvs_msg)
        finally:
            self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)

    def test_exampleservice_for_tenant_message(self, tenant_message='"'+'world'+'"'):
	vcpe_intf = self.vcpe_dhcp
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        try:
            self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            st,out = getstatusoutput('curl -s http://10.6.1.194')
            assert_equal(st, False)
            output = out.split('\n')
            tnt_msg = ''
            for line in output:
                line = line.split(':')
                if line[0].strip() == 'Tenant Message':
                    tnt_msg = line[1].strip()
            assert_equal(tenant_message, tnt_msg)
        finally:
            self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)

    def test_exampleservice_access_after_subscriber_interface_toggle(self, vcpe_intf=None):
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        try:
            self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            #curl request from test container
            cmd = 'curl -s http://{}'.format(vm_public_ip)
            st,_ = getstatusoutput(cmd)
            assert_equal(st, False)
            st,_ = getstatusoutput('ifconfig {} down'.format(vcpe_intf))
	    time.sleep(1)
            assert_equal(st, False)
            st,_ = getstatusoutput(cmd)
            assert_equal(st, False)
            st,_ = getstatusoutput('ifconfig {} up'.format(vcpe_intf))
            time.sleep(1)
	    self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
	    st,_ = getstatusoutput(cmd)
            assert_equal(st, False)
        finally:
            self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)

    def test_exampleservice_access_after_service_paused(self, vcpe_intf=None,vm_name=None):
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
	if not vm_name:
		vm_name = self.vm_name
	vm_public_ip = self.get_exampleservice_vm_public_ip()
        self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        assert_equal(st, False)
        exampleservices = OnboardingServiceUtils.get_exampleservices()
	status = False
        for service in exampleservices:
                if self.vm_name in service.name:
                        log.info('pausing mysite-example-server')
			service.pause()
			time.sleep(1)
        		st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        		assert_equal(st, True)
			service.unpause()
			self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
			status = True
	assert_equal(status, True)

    def test_exampleservice_access_after_service_is_suspended(self, vcpe_intf=None,vm_name=None):
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        if not vm_name:
                vm_name = self.vm_name
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        assert_equal(st, False)
        exampleservices = OnboardingServiceUtils.get_exampleservices()
        status = False
        for service in exampleservices:
                if self.vm_name in service.name:
                        log.info('suspending mysite-example-server')
                        service.suspend()
                        time.sleep(5)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
                        assert_equal(st, True)
                        service.resume()
                        self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        status = True
        assert_equal(status, True)

    def test_exampleservice_access_after_service_restart(self, vcpe_intf=None,vm_name=None):
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        if not vm_name:
                vm_name = self.vm_name
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        assert_equal(st, False)
        exampleservices = OnboardingServiceUtils.get_exampleservices()
        status = False
        for service in exampleservices:
                if self.vm_name in service.name:
                        log.info('restarting mysite-example-server')
                        service.reboot()
                        time.sleep(30)
			self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
                        assert_equal(st, False)
                        self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        status = True
        assert_equal(status, True)

    def test_exampleservice_access_after_service_stop(self, vcpe_intf=None,vm_name=None):
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        if not vm_name:
                vm_name = self.vm_name
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        assert_equal(st, False)
        exampleservices = OnboardingServiceUtils.get_exampleservices()
        status = False
        for service in exampleservices:
                if self.vm_name in service.name:
                        log.info('restarting mysite-example-server')
                        service.stop()
                        time.sleep(1)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
                        assert_equal(st, True)
			service.start()
                        self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        status = True
        assert_equal(status, True)

    def test_exampleservice_for_service_message_after_service_stop_and_start(self, service_message='"'+'hello'+'"'):
        vm_public_ip = self.get_exampleservice_vm_public_ip()
        vcpe_intf = self.vcpe_dhcp
        try:
            self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            st,out = getstatusoutput('curl -s http://{}'.format(vm_public_ip))
            assert_equal(st, False)
	    exampleservices = OnboardingServiceUtils.get_exampleservices()
	    status = False
            for service in exampleservices:
                if self.vm_name in service.name:
                        log.info('stopping mysite-example-server')
                        service.stop()
                        time.sleep(5)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
                        assert_equal(st, True)
                        service.start()
			self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
			time.sleep(50)
                        st,out = getstatusoutput('curl -s http://{} --max-time 10'.format(vm_public_ip))
                        assert_equal(st, False)
                        output = out.split('\n')
                        srvs_msg = ''
                        for line in output:
                            line = line.split(':')
                            if line[0].strip() == 'Service Message':
                                srvs_msg = line[1].strip()
				break
                        assert_equal(service_message, srvs_msg)
		        self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        status = True
			break
	    assert_equal(status,True)
        finally:
            self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)

    @deferred(150)
    def test_exampleservice_for_tenant_message_after_service_restart(self,service_message='"'+'world'+'"'):
	df = defer.Deferred()
	def test_xos_subscriber(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.vcpe_dhcp
            try:
                self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st,out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
		if out:
			st = True
                assert_equal(st, True)
                exampleservices = OnboardingServiceUtils.get_exampleservices()
                status = False
                for service in exampleservices:
                    if self.vm_name in service.name:
                        log.info('restarting mysite-example-server')
                        service.reboot()
                        time.sleep(20)
			self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
			time = 0
			while(time  <= 100):
			    time.sleep(10)
                            st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
			    if out:
				st = True
				break
			    time += 10
                        assert_equal(st,True)
                        output = out.split('\n')
                        tnnt_msg = ''
                        for line in output:
                            line = line.split(':')
                            if line[0].strip() == 'Tenant Message':
                                tnnt_msg = line[1].strip()
                                break
                        assert_equal(tenant_message, tnnt_msg)
                        self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                        status = True
                        break
                assert_equal(status,True)
            except Exception as error:
            	self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
		log.info('Got Unexpected error %s'%error)
		raise
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(30)
    def test_multiple_subcribers_access_for_same_exampleservice(self,index=0):
        df = defer.Deferred()
        def test_xos_subscriber(df):
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf1 = self.vcpe_dhcp
	    vcpe_intf2 = 'vcpe1.304.304'
            subId = self.vsg_exchange.vsg_xos_subscriber_id(index)
            if subId == '0':
                subId = self.vsg_exchange.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
	    try:
	        for vcpe in [vcpe_intf1,vcpe_intf2]:
       	            self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe)
		    time.sleep(1)
                    #curl request from test container
	            st, out = getstatusoutput('route -n')
	            log.info('route -n out is %s'%out)
                    curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                    st,out = getstatusoutput(curl_cmd)
		    if out:
			st = True
                    assert_equal(st, True)
	            log.info('examle service access success for subscriber %s'%vcpe)
                    self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe)
                    time.sleep(1)
	    except Exception as error:
		log.info('Got unexpected error %s'%error)
		self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf1)
		self.vsg_exchange.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf2)
		raise
	    df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(50)
    def test_exampleservice_access_after_vcpe_instance_restart(self,vcpe_intf=None,vcpe_name=None):
        df = defer.Deferred()
        def test_xos_subscriber(df,vcpe_intf=vcpe_intf,vcpe_name=vcpe_name):
            if not vcpe_intf:
                vcpe_intf = self.vsg_exchange.dhcp_vcpes_reserved[0]
            if not vcpe_name:
                vcpe_name = self.vsg_exchange.container_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
		if out:
			st = True
                assert_equal(st, True)
                #restarting example service VM
                cmd = 'sudo docker restart {}'.format(vcpe_name)
                status, _ = vsg.run_cmd(cmd)
                assert_equal(status, True)
                time.sleep(10)
		self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput(curl_cmd)
		if out:
			st = True
                assert_equal(st, True)
            except Exception as error:
		log.info('Got Unexpeted error %s'%error)
                self.vsg_exchange.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
		raise
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(30)
    def test_exampleservice_access_after_firewall_rule_added_to_drop_service_running_server_in_vcpe_instance(self,vcpe_intf=None,vcpe_name=None):
        df = defer.Deferred()
        def test_xos_subscriber(df,vcpe_intf=vcpe_intf,vcpe_name=vcpe_name):
            if not vcpe_intf:
                vcpe_intf = self.vsg_exchange.dhcp_vcpes_reserved[0]
            if not vcpe_name:
                vcpe_name = self.vsg_exchange.container_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.vsg_exchange.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
                if out:
                        st = True
                assert_equal(st, True)
                #restarting example service VM
                cmd = 'sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,vm_public_ip)
                status, _ = vsg.run_cmd(cmd)
                assert_equal(status, True)
                time.sleep(1)
                st, out = getstatusoutput(curl_cmd)
                if out:
                        st = True
                assert_equal(st, True)
		cmd = 'sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,vm_public_ip)
            except Exception as error:
                log.info('Got Unexpeted error %s'%error)
		cmd = 'sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,vm_public_ip)
		status, _ = vsg.run_cmd(cmd)
                self.vsg_exchange.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
                raise
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    def test_exampleservice_after_firewall_rule_added_to_drop_service_running_server_in_vcpe(self):
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        public_ip = self.get_exampleservice_vm_public_ip()
        vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
        try:
            self.add_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
            #curl request from test container
            curl_cmd = 'curl -s http://{}'.format(public_ip)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, True)
            #restarting example service VM
            st,_ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j ACCEPT'.format(vcpe_name,public_ip))
            time.sleep(1)
            st,_ = getstatusoutput(curl_cmd)
            assert_equal(st, False)
        finally:
            st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,public_ip))
            self.del_static_route_via_vcpe_interface([public_ip],vcpe=vcpe_intf)
