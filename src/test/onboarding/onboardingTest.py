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
from nose.tools import assert_equal, assert_not_equal
from twisted.internet import defer
from nose.twistedtools import reactor, deferred
from CordTestUtils import *
from onosclidriver import OnosCliDriver
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnboardingServiceUtils import OnboardingServiceUtils
from SSHTestAgent import SSHTestAgent
from CordTestConfig import setup_module, running_on_ciab
from CordLogger import CordLogger
from CordTestUtils import *
from CordTestUtils import log_test as log
import requests
import time
import json
from VSGAccess import VSGAccess
from CordTestConfig import setup_module, running_on_ciab
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
    vm_name = 'mysite_exampleservice'
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config.json'))
    restApiXos =  None
    subscriber_account_num = 200
    subscriber_s_tag = 304
    subscriber_c_tag = 304
    subscribers_per_s_tag = 8
    subscriber_map = {}
    subscriber_info = []
    volt_subscriber_info = []
    restore_methods = []
    FABRIC_PORT_HEAD_NODE = 1
    FABRIC_PORT_COMPUTE_NODE = 2
    APP_NAME = 'org.ciena.xconnect'
    APP_FILE = os.path.join(test_path, '..', 'apps/xconnect-1.0-SNAPSHOT.oar')
    NUM_SUBSCRIBERS = 5

    @classmethod
    def getSubscriberCredentials(cls, subId):
        """Generate our own account num, s_tag and c_tags"""
        if subId in cls.subscriber_map:
            return cls.subscriber_map[subId]
        account_num = cls.subscriber_account_num
        cls.subscriber_account_num += 1
        s_tag, c_tag = cls.subscriber_s_tag, cls.subscriber_c_tag
        cls.subscriber_c_tag += 1
        if cls.subscriber_c_tag % cls.subscribers_per_s_tag == 0:
            cls.subscriber_s_tag += 1
        cls.subscriber_map[subId] = account_num, s_tag, c_tag
        return cls.subscriber_map[subId]

    @classmethod
    def getXosCredentials(cls):
        onos_cfg = OnosCtrl.get_config()
        if onos_cfg is None:
            return None
        if 'apps' in onos_cfg and \
           'org.opencord.vtn' in onos_cfg['apps'] and \
           'cordvtn' in onos_cfg['apps']['org.opencord.vtn'] and \
           'xos' in onos_cfg['apps']['org.opencord.vtn']['cordvtn']:
            xos_cfg = onos_cfg['apps']['org.opencord.vtn']['cordvtn']['xos']
            endpoint = xos_cfg['endpoint']
            user = xos_cfg['user']
            password = xos_cfg['password']
            xos_endpoints = endpoint.split(':')
            xos_host = xos_endpoints[1][len('//'):]
            xos_port = xos_endpoints[2][:-1]
            #log.info('xos_host: %s, port: %s, user: %s, password: %s' %(xos_host, xos_port, user, password))
            return dict(host = xos_host, port = xos_port, user = user, password = password)

        return None
    @classmethod
    def getSubscriberConfig(cls, num_subscribers):
        features =  {
            'cdn': True,
            'uplink_speed': 1000000000,
            'downlink_speed': 1000000000,
            'uverse': True,
            'status': 'enabled'
        }
        subscriber_map = []
        for i in xrange(num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, _, _ = cls.getSubscriberCredentials(subId)
            identity = { 'account_num' : str(account_num),
                         'name' : 'My House {}'.format(i)
                         }
            sub_info = { 'features' : features,
                         'identity' : identity
                         }
            subscriber_map.append(sub_info)

        return subscriber_map

    @classmethod
    def getVoltSubscriberConfig(cls, num_subscribers):
        voltSubscriberMap = []
        for i in xrange(num_subscribers):
            subId = 'sub{}'.format(i)
            account_num, s_tag, c_tag = cls.getSubscriberCredentials(subId)
            voltSubscriberInfo = {}
            voltSubscriberInfo['voltTenant'] = dict(s_tag = str(s_tag),
                                                    c_tag = str(c_tag),
                                                    subscriber = '')
            voltSubscriberInfo['account_num'] = account_num
            voltSubscriberMap.append(voltSubscriberInfo)

        return voltSubscriberMap

    @classmethod
    def setUpClass(cls):
        OnboardingServiceUtils.setUp()
        cls.controllers = get_controllers()
        cls.controller = cls.controllers[0]
        cls.cli = None
        cls.on_pod = running_on_pod()
        cls.on_ciab = running_on_ciab()
        cls.olt = OltConfig(olt_conf_file = cls.olt_conf_file)
        cls.vcpes = cls.olt.get_vcpes()
        cls.vcpes_dhcp = cls.olt.get_vcpes_by_type('dhcp')
        cls.vcpes_reserved = cls.olt.get_vcpes_by_type('reserved')
        cls.dhcp_vcpes_reserved = [ 'vcpe{}.{}.{}'.format(i, cls.vcpes_reserved[i]['s_tag'], cls.vcpes_reserved[i]['c_tag'])
                                    for i in xrange(len(cls.vcpes_reserved)) ]
        cls.untagged_dhcp_vcpes_reserved = [ 'vcpe{}'.format(i) for i in xrange(len(cls.vcpes_reserved)) ]
        cls.container_vcpes_reserved = [ 'vcpe-{}-{}'.format(vcpe['s_tag'], vcpe['c_tag']) for vcpe in cls.vcpes_reserved ]
        vcpe_dhcp_reserved = None
        vcpe_container_reserved = None
        if cls.vcpes_reserved:
            vcpe_dhcp_reserved = cls.dhcp_vcpes_reserved[0]
            if cls.on_pod is False:
                vcpe_dhcp_reserved = cls.untagged_dhcp_vcpes_reserved[0]
            vcpe_container_reserved = cls.container_vcpes_reserved[0]

        cls.vcpe_dhcp_reserved = vcpe_dhcp_reserved
        cls.vcpe_container_reserved = vcpe_container_reserved
        dhcp_vcpe_offset = len(cls.vcpes_reserved)
        cls.dhcp_vcpes = [ 'vcpe{}.{}.{}'.format(i+dhcp_vcpe_offset, cls.vcpes_dhcp[i]['s_tag'], cls.vcpes_dhcp[i]['c_tag'])
                           for i in xrange(len(cls.vcpes_dhcp))  ]
        cls.untagged_dhcp_vcpes = [ 'vcpe{}'.format(i+dhcp_vcpe_offset) for i in xrange(len(cls.vcpes_dhcp)) ]
        cls.container_vcpes = [ 'vcpe-{}-{}'.format(vcpe['s_tag'], vcpe['c_tag']) for vcpe in cls.vcpes_dhcp ]
        vcpe_dhcp = None
        vcpe_container = None
        #cache the first dhcp vcpe in the class for quick testing
        if cls.vcpes_dhcp:
            vcpe_container = cls.container_vcpes[0]
            vcpe_dhcp = cls.dhcp_vcpes[0]
            if cls.on_pod is False:
                vcpe_dhcp = cls.untagged_dhcp_vcpes[0]
        cls.vcpe_container = vcpe_container_reserved or vcpe_container
        cls.vcpe_dhcp = vcpe_dhcp_reserved or vcpe_dhcp
        VSGAccess.setUp()
        cls.setUpCordApi()
        if cls.on_pod is True:
            cls.openVCPEAccess(cls.volt_subscriber_info)

    @classmethod
    def setUpCordApi(cls):
        our_path = os.path.dirname(os.path.realpath(__file__))
        cord_api_path = os.path.join(our_path, '..', 'cord-api')
        framework_path = os.path.join(cord_api_path, 'Framework')
        utils_path = os.path.join(framework_path, 'utils')
        data_path = os.path.join(cord_api_path, 'Tests', 'data')
        subscriber_cfg = os.path.join(data_path, 'Subscriber.json')
        volt_tenant_cfg = os.path.join(data_path, 'VoltTenant.json')
        num_subscribers = max(cls.NUM_SUBSCRIBERS, 5)
        cls.subscriber_info = cls.getSubscriberConfig(num_subscribers)
        cls.volt_subscriber_info = cls.getVoltSubscriberConfig(num_subscribers)

        sys.path.append(utils_path)
        sys.path.append(framework_path)
        from restApi import restApi
        restApiXos = restApi()
        xos_credentials = cls.getXosCredentials()
        if xos_credentials is None:
            restApiXos.controllerIP = cls.HEAD_NODE
            restApiXos.controllerPort = '9000'
        else:
            restApiXos.controllerIP = xos_credentials['host']
            restApiXos.controllerPort = xos_credentials['port']
            restApiXos.user = xos_credentials['user']
            restApiXos.password = xos_credentials['password']
        cls.restApiXos = restApiXos

    @classmethod
    def getVoltId(cls, result, subId):
        if type(result) is not type([]):
            return None
        for tenant in result:
            if str(tenant['subscriber']) == str(subId):
                return str(tenant['id'])
        return None

    @classmethod
    def closeVCPEAccess(cls, volt_subscriber_info):
        OnosCtrl.uninstall_app(cls.APP_NAME, onos_ip = cls.HEAD_NODE)

    @classmethod
    def openVCPEAccess(cls, volt_subscriber_info):
        """
        This code is used to configure leaf switch for head node access to compute node over fabric.
        Care is to be taken to avoid overwriting existing/default vcpe flows.
        The access is opened for generated subscriber info which should not overlap.
        We target the fabric onos instance on head node.
        """
        OnosCtrl.install_app(cls.APP_FILE, onos_ip = cls.HEAD_NODE)
        time.sleep(2)
        s_tags = map(lambda tenant: int(tenant['voltTenant']['s_tag']), volt_subscriber_info)
        #only get unique vlan tags
        s_tags = list(set(s_tags))
        devices = OnosCtrl.get_device_ids(controller = cls.HEAD_NODE)
        if devices:
            device_config = {}
            for device in devices:
                device_config[device] = []
                for s_tag in s_tags:
                    xconnect_config = {'vlan': s_tag, 'ports' : [ cls.FABRIC_PORT_HEAD_NODE, cls.FABRIC_PORT_COMPUTE_NODE ] }
                    device_config[device].append(xconnect_config)

            cfg = { 'apps' : { 'org.ciena.xconnect' : { 'xconnectTestConfig' : device_config } } }
            OnosCtrl.config(cfg, controller = cls.HEAD_NODE)


    @classmethod
    def tearDownClass(cls):
        OnboardingServiceUtils.tearDown()
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.volt_subscriber_info)

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

    def add_static_route_via_vcpe_interface(self, routes, vcpe=None,dhcp_ip=True):
        if not vcpe:
            vcpe = self.dhcp_vcpes_reserved[0]
        if dhcp_ip:
            os.system('dhclient '+vcpe)
        time.sleep(1)
        for route in routes:
            log.info('route is %s'%route)
            cmd = 'ip route add ' + route + ' via 192.168.0.1 '+ 'dev ' + vcpe
            os.system(cmd)
        return True

    def del_static_route_via_vcpe_interface(self,routes,vcpe=None,dhcp_release=True):
        if not vcpe:
            vcpe = self.dhcp_vcpes_reserved[0]
        cmds = []
        for route in routes:
            cmd = 'ip route del ' + route + ' via 192.168.0.1 ' + 'dev ' + vcpe
            os.system(cmd)
        if dhcp_release:
            os.system('dhclient '+vcpe+' -r')
        return True

    def vsg_for_external_connectivity(self, subscriber_index, reserved = False):
        if reserved is True:
            if self.on_pod is True:
                vcpe = self.dhcp_vcpes_reserved[subscriber_index]
            else:
                vcpe = self.untagged_dhcp_vcpes_reserved[subscriber_index]
        else:
            if self.on_pod is True:
                vcpe = self.dhcp_vcpes[subscriber_index]
            else:
                vcpe = self.untagged_dhcp_vcpes[subscriber_index]
        mgmt = 'eth0'
        host = '8.8.8.8'
        self.success = False
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp echo requests to external network 8.8.8.8')
        st, _ = getstatusoutput('ping -c 3 8.8.8.8')
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    @deferred(50)
    def test_exampleservice_health(self):
        """
        Algo:
        1. Login to compute node VM
        2. Get all exampleservice
        3. Ping to all exampleservice
        4. Verifying Ping success
        """
        df = defer.Deferred()
        def test_exampleservice(df):
            status = OnboardingServiceUtils.health_check()
            assert_equal(status, True)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(50)
    def test_exampleservice_for_login(self):
        """
        Algo:
        1. Login to compute node VM
        2. Get all exampleservice
        3. Login to all exampleservice
        4. Verifying Login success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            exampleservice_access_status = map(lambda exampleservice: exampleservice.check_access(), exampleservices)
            status = filter(lambda st: st == False, exampleservice_access_status)
            assert_equal(len(status), 0)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(30)
    def test_exampleservice_for_default_route_through_testclient(self):
        """
        Algo:
        1. Login to Head node
        2. Verify default route exists in test client
        """
        if self.on_pod is False:
           return
        df = defer.Deferred()
        def test_exampleservice(df):
            ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
            cmd = "sudo lxc exec testclient -- route | grep default"
            status, output = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(50)
    def test_exampleservice_for_service_access_through_testclient(self):
        """
        Algo:
        1. Login to Head node
        2. Ping to all exampleservice from test client
        3. Verifying Ping success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
            ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
            cmd = "sudo lxc exec testclient -- ping -c 3 {}".format(vm_public_ip)
            status, output = ssh_agent.run_cmd(cmd)
            assert_equal( status, True)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(30)
    def test_exampleservice_for_service_reachability_from_cord_tester(self):
        """
        Algo:
        1. Add static route to example service running VM IP in cord-tester
        2. Ping to the VM IP
        3. Verifying Ping success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
	    vcpe_intf = self.dhcp_vcpes_reserved[0]
	    try:
		self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(vm_public_ip))
        	assert_equal(st, False)
	    except Exception as error:
		log.info('Got Unexpected  error %s'%error)
		raise
	    finally:
		self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(40)
    def test_exampleservice_operational_status_from_testclient(self):
        """
        Algo:
        1. Login to Head node
        2. Do curl request to the example service running VM IP from test client
        3. Verifying curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
            ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
            cmd = 'sudo lxc exec testclient -- apt-get install -y curl'
            status, _  = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            #Test connectivity to ExampleService from test client
            cmd = 'sudo lxc exec testclient -- curl -s http://{}'.format(vm_public_ip)
            status, _ = ssh_agent.run_cmd(cmd)
            assert_equal(status, True)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(30)
    def test_exampleservice_operational_access_from_cord_tester(self):
        """
        Algo:
        1. Add static route to example service running VM IP in cord-tester
        2. Do curl request to the VM IP
        3. Verifying curl request success
        """
        if self.on_pod is False:
            return
        vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def test_exampleservice(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
            try:
	        self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
        	st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
        	assert_not_equal(out,'')
            except Exception as error:
                log.info('Got Unexpected  error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(40)
    def test_exampleservice_for_service_message(self, service_message="\"hello\""):
        """
        Algo:
	1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying Service message in curl response
        """
        if self.on_pod is False:
            return
	vm_public_ip = self.get_exampleservice_vm_public_ip()
	vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def test_exampleservice(df):
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
	    try:
	        self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st,out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                output = out.split('\n')
	        srvs_msg = ''
                for line in output:
                    line = line.split(':')
                    if line[0].strip() == 'Service Message':
                        srvs_msg = line[1].strip()
	        assert_equal(service_message, srvs_msg)
	    except Exception as error:
	        log.info('Got Unexpected error %s'%error)
	        raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(40)
    def test_exampleservice_for_tenant_message(self, tenant_message="\"world\""):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying Tenant message in curl response
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
    	    vcpe_intf = self.dhcp_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st,out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                output = out.split('\n')
                tnt_msg = ''
                for line in output:
                    line = line.split(':')
                    if line[0].strip() == 'Tenant Message':
                        tnt_msg = line[1].strip()
                assert_equal(tenant_message, tnt_msg)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(60)
    def test_exampleservice_access_after_subscriber_interface_toggle(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
	5. Toggle vcpe interface in cord-tester and do curl request again
	6. Again verify curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
	    vm_public_ip = self.get_exampleservice_vm_public_ip()
	    vcpe_intf = self.dhcp_vcpes_reserved[0]
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(cmd)
                assert_not_equal(out,'')
                st, _ = getstatusoutput('ifconfig {} down'.format(vcpe_intf))
                assert_equal(st, False)
		time.sleep(1)
                st, _ = getstatusoutput('ifconfig {} up'.format(vcpe_intf))
		assert_equal(st, False)
                time.sleep(1)
	        self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
	        st, out = getstatusoutput(cmd)
                assert_not_equal(out,'')
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
		getstatusoutput('ifconfig {} up'.format(vcpe_intf))
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df


    @deferred(60)
    def test_exampleservice_access_after_service_paused(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Pause example service running VM and do curl request again
        6. Verify curl response is an empty output
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
	    service_vm = None
    	    vm_public_ip = self.get_exampleservice_vm_public_ip()
	    vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
              	   break
	    assert_not_equal(service_vm,None)
	    try:
            	self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            	st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
            	assert_not_equal(out,'')
		log.info('Pausing example service running vm')
            	service_vm.pause()
		time.sleep(2)
        	st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
        	assert_equal(out,'')
		service_vm.unpause()
		time.sleep(3)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		service_vm.unpause()
		time.sleep(3)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    #Test failing. server state goes to error after resuming
    @deferred(60)
    def test_exampleservice_access_after_service_is_suspended(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Suspend example service running VM and do curl request again
        6. Verify curl response is an empty output
	7. Resume suspended VM and do curl request now
	8. Verifying curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
                   break
            assert_not_equal(service_vm,None)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                log.info('Suspending example service running vm')
                service_vm.suspend()
                time.sleep(5)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_equal(out,'')
                service_vm.resume()
		time.sleep(5)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                service_vm.stop()
		time.sleep(1)
		service_vm.start()
		time.sleep(5)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(60)
    def test_exampleservice_access_after_service_restart(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Restart example service running VM and do curl request again
        9. Verifying curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
                   break
            assert_not_equal(service_vm,None)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
		assert_not_equal(out,'')
                log.info('Restarting example service running vm')
                service_vm.reboot()
		time.sleep(5)
		clock = 0
		status = False
		while(clock <= 30):
		    time.sleep(5)
                    st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
		    if out != '':
			status = True
			break
		    clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    #not test. vSG VM goes down after restart
    @deferred(70)
    def test_exampleservice_access_after_vsg_vm_restart(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Restart vSG VM and do curl request again
        9. Verifying curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved [0]
	    vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                log.info('Restarting vSG VM')
                vsg.reboot()
                time.sleep(5)
                clock = 0
                status = False
                while(clock <= 40):
                    time.sleep(5)
                    st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                    if out != '':
                        status = True
                        break
                    clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(80)
    def test_exampleservice_access_after_service_stop(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Stop example service running VM and do curl request again
        6. Verify curl response is an empty output
        7. Start stopped VM and do curl request now
        8. Verifying curl request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
                   break
            assert_not_equal(service_vm,None)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                log.info('Stopping example service running vm')
                service_vm.stop()
                time.sleep(5)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
		assert_equal(out,'')
                service_vm.start()
		time.sleep(5)
                clock = 0
                status = False
                while(clock <= 60):
                    time.sleep(5)
                    st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                    if out != '':
                        status = True
                        break
                    clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		service_vm.start()
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(80)
    def test_exampleservice_for_service_message_after_service_stop_and_start(self, service_message="\"hello\""):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Stop example service running VM and do curl request again
        6. Verify curl response is an empty output
        7. Start stopped VM and do curl request now
        8. Verifying Service message in curl response
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
	def test_exampleservice(df):
	    service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
                   break
            assert_not_equal(service_vm,None)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st,out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
	        log.info('Stopping example service running VM')
                service_vm.stop()
                time.sleep(5)
                st, out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_equal(out,'')
                service.start()
	        time.sleep(5)
		clock = 0
		while(clock <= 60):
		    time.sleep(5)
                    st,out = getstatusoutput('curl -s http://{} --max-time 10'.format(vm_public_ip))
		    if out != '':
                	output = out.split('\n')
                	srvs_msg = None
                	for line in output:
                    	    line = line.split(':')
                    	    if line[0].strip() == 'Service Message':
                        	srvs_msg = line[1].strip()
				clock = 60
				break
		    clock += 5
                assert_equal(service_message, srvs_msg)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                service_vm.start()
		time.sleep(5)
	    finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(80)
    def test_exampleservice_for_tenant_message_after_service_restart(self,tenant_message="\"world\""):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Restart example service running VM and do curl request again
        6. Verifying Tenant message in curl response
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            service_vm = None
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            exampleservices = OnboardingServiceUtils.get_exampleservices()
            for service in exampleservices:
                if self.vm_name in service.name:
                   service_vm = service
                   break
            assert_not_equal(service_vm,None)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st,out = getstatusoutput('curl -s http://{} --max-time 5'.format(vm_public_ip))
                assert_not_equal(out,'')
                log.info('Restarting example service running VM')
                service_vm.reboot()
                time.sleep(5)
                clock = 0
                while(clock <= 40):
                    time.sleep(5)
                    st,out = getstatusoutput('curl -s http://{} --max-time 10'.format(vm_public_ip))
                    if out != '':
                        output = out.split('\n')
                        tnnt_msg = None
                        for line in output:
                            line = line.split(':')
                            if line[0].strip() == 'Tenant Message':
                                tnnt_msg = line[1].strip()
                                clock = 40
                                break
                    clock += 5
                assert_equal(tenant_message, tnnt_msg)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(50)
    def test_exampleservice_access_after_vcpe_instance_restart(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Restart vcpe instance and do curl request again
        8. Verifying curl  request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
		assert_not_equal(out,'')
                #restarting example service VM
                cmd = 'sudo docker restart {}'.format(vcpe_name)
                status, _ = vsg.run_cmd(cmd)
                assert_equal(status, True)
                time.sleep(5)
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                clock = 0
                status = False
                while(clock <= 30):
                    time.sleep(5)
                    st, out = getstatusoutput(curl_cmd)
                    if out != '':
                        status = True
                        break
                    clock += 5
                assert_equal(status,True)
            except Exception as error:
                log.info('Got Unexpeted error %s'%error)
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(50)
    def test_exampleservice_access_after_vcpe_instance_wan_interface_toggle(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Restart vcpe instance and do curl request again
        8. Verifying curl  request success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_exampleservice(df):
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            wan_intf = 'eth0'
            mgmt = 'eth0'
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
                assert_not_equal(out,'')
                st = VSGAccess.vcpe_wan_down(vcpe_name)
                if st is False:
                        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe_intf)
                assert_not_equal(st, '0')
                time.sleep(2)
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
                assert_equal(out,'')
                st = VSGAccess.vcpe_wan_up(vcpe_name)
                if st is False:
                        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe_intf)
                assert_not_equal(st, '0')
                time.sleep(5)
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                st, out = getstatusoutput(curl_cmd)
                assert_not_equal(out,'')
            except Exception as error:
                log.info('Got Unexpeted error %s'%error)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name,wan_intf))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(30)
    def test_exampleservice_access_after_firewall_rule_added_to_drop_service_running_server_in_vcpe_instance(self):
        """
        Algo:
        1. Get dhcp ip to vcpe interface in cord-tester
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Add a firewall rule in vcpe instance to drop packets destined to example service VM
        6. Do curl request now
        7. Verifying curl response is an empty output
	8. Delete the firewall rule and do curl request again
	9. Verifying curl request success
        """
        df = defer.Deferred()
        def test_exampleservice(df,vcpe_intf=vcpe_intf,vcpe_name=vcpe_name):
            vcpe_intf = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved[0]
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                #curl request from test container
                curl_cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st, out = getstatusoutput(curl_cmd)
                assert_not_equal(out,'')
                #restarting example service VM
                cmd = 'sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,vm_public_ip)
                status, _ = vsg.run_cmd(cmd)
                assert_equal(status, True)
                time.sleep(1)
                st, out = getstatusoutput(curl_cmd)
                assert_equal(out,'')
            except Exception as error:
                log.info('Got Unexpeted error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,vm_public_ip))
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df


    def vsg_xos_subscriber_create(self, index, subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return ''
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        log.info('Creating tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        subId = ''
        try:
            result = self.restApiXos.ApiPost('TENANT_SUBSCRIBER', subscriber_info)
            assert_equal(result, True)
            result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
            assert_not_equal(subId, '0')
            log.info('Subscriber ID for account num %s = %s' %(str(volt_subscriber_info['account_num']), subId))
            volt_tenant = volt_subscriber_info['voltTenant']
            #update the subscriber id in the tenant info before making the rest
            volt_tenant['subscriber'] = subId
            result = self.restApiXos.ApiPost('TENANT_VOLT', volt_tenant)
            assert_equal(result, True)
            #if the vsg instance was already instantiated, then reduce delay
            if c_tag % self.subscribers_per_s_tag == 0:
                delay = 350
            else:
                delay = 90
            log.info('Delaying %d seconds for the VCPE to be provisioned' %(delay))
            time.sleep(delay)
            log.info('Testing for external connectivity to VCPE %s' %(vcpe))
            self.vsg_for_external_connectivity(index)
        finally:
            return subId

    def vsg_xos_subscriber_delete(self, index, subId = '', voltId = '', subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return
        if subscriber_info is None:
            subscriber_info = self.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        log.info('Deleting tenant with s_tag: %d, c_tag: %d' %(s_tag, c_tag))
        if not subId:
            #get the subscriber id first
            result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
            assert_not_equal(result, None)
            subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
            assert_not_equal(subId, '0')
        if not voltId:
            #get the volt id for the subscriber
            result = self.restApiXos.ApiGet('TENANT_VOLT')
            assert_not_equal(result, None)
            voltId = self.getVoltId(result, subId)
            assert_not_equal(voltId, None)
        log.info('Deleting subscriber ID %s for account num %s' %(subId, str(volt_subscriber_info['account_num'])))
        status = self.restApiXos.ApiDelete('TENANT_SUBSCRIBER', subId)
        assert_equal(status, True)
        #Delete the tenant
        log.info('Deleting VOLT Tenant ID %s for subscriber %s' %(voltId, subId))
        self.restApiXos.ApiDelete('TENANT_VOLT', voltId)

    def vsg_xos_subscriber_id(self, index):
        log.info('index and its type are %s, %s'%(index, type(index)))
        volt_subscriber_info = self.volt_subscriber_info[index]
        result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        assert_not_equal(result, None)
        subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
        return subId

    @deferred(500)
    def test_xos_subcriber_access_exampleservice(self,index=0):
        """
        Algo:
        1. Create two vcpe instances using XOS
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Repeat steps for both vcpes
        """
        df = defer.Deferred()
        def test_exampleservice(df):
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf = self.dhcp_vcpes[0]
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            try:
                self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                time.sleep(1)
                cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                st,out = getstatusoutput(cmd)
                assert_not_equal(out,'')
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                raise
	    finally:
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf)
                self.vsg_xos_subscriber_delete(index, subId = subId)
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

    @deferred(500)
    def test_exampleservice_multiple_subcribers_access_same_service(self,index1=0,index2=1):
        """
        Algo:
        1. Create two vcpe instances using XOS
        2. Add static route to example service running VM IP in cord-tester
        3. Do curl request to the VM IP
        4. Verifying curl request success
        5. Repeat steps for both vcpes
        """
        df = defer.Deferred()
        def test_exampleservice(df):
            vm_public_ip = self.get_exampleservice_vm_public_ip()
            vcpe_intf1 = self.dhcp_vcpes[0]
            vcpe_intf2 = self.dhcp_vcpes[1]
            subId1 = self.vsg_xos_subscriber_id(index1)
            if subId1 == '0':
                subId1 = self.vsg_xos_subscriber_create(index1)
            assert_not_equal(subId1,'0')
            subId2 = self.vsg_xos_subscriber_id(index2)
            if subId2 == '0':
                subId2 = self.vsg_xos_subscriber_create(index2)
            assert_not_equal(subId2,'0')
            try:
                for vcpe in [vcpe_intf1,vcpe_intf2]:
                    self.add_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf1)
                    time.sleep(1)
                    status = False
                    cmd = 'curl -s http://{} --max-time 5'.format(vm_public_ip)
                    st,out = getstatusoutput(cmd)
                    assert_not_equal(out,'')
                    self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf2)
                    time.sleep(1)
            except Exception as error:
                log.info('Got unexpected error %s'%error)
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf1)
                self.del_static_route_via_vcpe_interface([vm_public_ip],vcpe=vcpe_intf2)
                self.vsg_xos_subscriber_delete(index1, subId = subId1)
                self.vsg_xos_subscriber_delete(index2, subId = subId2)
                raise
            df.callback(0)
        reactor.callLater(0,test_exampleservice,df)
        return df

