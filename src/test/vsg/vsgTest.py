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
import time
import os
import sys
import json
import requests
from nose.tools import *
from twisted.internet import defer
from nose.twistedtools import reactor, deferred
from CordTestUtils import *
from OltConfig import OltConfig
from onosclidriver import OnosCliDriver
from SSHTestAgent import SSHTestAgent
from CordLogger import CordLogger
from VSGAccess import VSGAccess
from CordTestUtils import log_test as log
from CordTestConfig import setup_module, running_on_ciab, teardown_module
from OnosCtrl import OnosCtrl
from CordContainer import Onos
from CordSubscriberUtils import CordSubscriberUtils, XosUtils
log.setLevel('INFO')

class vsg_exchange(CordLogger):
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
    olt_conf_file = os.getenv('OLT_CONFIG_FILE', os.path.join(test_path, '..', 'setup/olt_config.json'))
    restApiXos =  None
    cord_subscriber = None
    SUBSCRIBER_ACCOUNT_NUM = 200
    SUBSCRIBER_S_TAG = 304
    SUBSCRIBER_C_TAG = 304
    SUBSCRIBERS_PER_S_TAG = 8
    subscriber_info = []
    volt_subscriber_info = []
    restore_methods = []
    TIMEOUT=120
    FABRIC_PORT_HEAD_NODE = 1
    FABRIC_PORT_COMPUTE_NODE = 2
    APP_NAME = 'org.ciena.xconnect'
    APP_FILE = os.path.join(test_path, '..', 'apps/xconnect-1.0-SNAPSHOT.oar')
    NUM_SUBSCRIBERS = 5

    @classmethod
    def setUpCordApi(cls, **subscriber_config):
        num_subscribers = subscriber_config.get('num_subscribers', cls.NUM_SUBSCRIBERS)
        account_num = subscriber_config.get('account_num', cls.SUBSCRIBER_ACCOUNT_NUM)
        s_tag = subscriber_config.get('s_tag', cls.SUBSCRIBER_S_TAG)
        c_tag = subscriber_config.get('c_tag', cls.SUBSCRIBER_C_TAG)
        subscribers_per_s_tag = subscriber_config.get('subscribers_per_s_tag', cls.SUBSCRIBERS_PER_S_TAG)
        cls.cord_subscriber = CordSubscriberUtils(num_subscribers,
                                                  account_num = account_num,
                                                  s_tag = s_tag,
                                                  c_tag = c_tag,
                                                  subscribers_per_s_tag = subscribers_per_s_tag)
        cls.restApiXos = XosUtils.getRestApi()

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
        version = Onos.getVersion(onos_ip = cls.HEAD_NODE)
        app_version = '1.0-SNAPSHOT'
        major = int(version.split('.')[0])
        minor = int(version.split('.')[1])
        if major > 1:
            app_version = '2.0-SNAPSHOT'
        elif major == 1 and minor > 10:
            app_version = '2.0-SNAPSHOT'
        cls.APP_FILE = os.path.join(cls.test_path, '..', 'apps/xconnect-{}.oar'.format(app_version))
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
    def vsgSetup(cls, **subscriber_config):
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
        cls.setUpCordApi(**subscriber_config)
        if cls.on_pod is True:
            cls.openVCPEAccess(cls.cord_subscriber.volt_subscriber_info)

    @classmethod
    def setUpClass(cls):
        num_subscribers = max(cls.NUM_SUBSCRIBERS, 5)
        cls.vsgSetup(num_subscribers = num_subscribers)

    @classmethod
    def vsgTeardown(cls):
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.cord_subscriber.volt_subscriber_info)

    @classmethod
    def tearDownClass(cls):
        cls.vsgTeardown()

    def onos_shutdown(self, controller = None):
        status = True
        cli = Onos.cliEnter(onos_ip = controller)
        try:
            cli.shutdown(timeout = 10)
        except:
            log.info('Graceful shutdown of ONOS failed for controller: %s' %controller)
            status = False

        Onos.cliExit(cli)
        return status

    def log_set(self, level = None, app = 'org.onosproject'):
        CordLogger.logSet(level = level, app = app, controllers = self.controllers, forced = True)

    @classmethod
    def get_dhcp(cls, vcpe, mgmt = 'eth0'):
        """Get DHCP for vcpe interface saving management settings"""

        def put_dhcp():
            VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)

        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        if vcpe_ip is not None:
            cls.restore_methods.append(put_dhcp)
        return vcpe_ip

    @classmethod
    def config_restore(cls):
        """Restore the vsg test configuration on test case failures"""
        for restore_method in cls.restore_methods:
            restore_method()

    def get_vsg_vcpe_pair(self):
        vcpes = self.vcpes_dhcp
        vcpe_containers = []
        vsg_vcpe = {}
        for vcp in vcpes:
                vcpe_container = 'vcpe-{}-{}'.format(vcp['s_tag'], vcp['c_tag'])
                vcpe_containers.append(vcpe_container)
                vsg = VSGAccess.get_vcpe_vsg(vcpe_container)
                vsg_vcpe[vcpe_container]=str(vsg.get_ip())
        return vsg_vcpe

    def get_vcpe_containers_and_interfaces(self):
	vcpe_containers = {}
	vcpe_interfaces = []
	vcpes = self.vcpes_dhcp
	count = 0
	for vcpe in vcpes:
		vcpe_intf = 'vcpe{}.{}.{}'.format(count,vcpe['s_tag'],vcpe['c_tag'])
		vcpe_interfaces.append(vcpe_intf)
                vcpe_container = 'vcpe-{}-{}'.format(vcpe['s_tag'], vcpe['c_tag'])
                vcpe_containers[vcpe_intf] = vcpe_container
		count += 1
	log.info('vcpe interfaces are %s'%vcpe_interfaces)
	log.info('vcpe containers are %s'%vcpe_containers)
	return vcpe_interfaces,vcpe_containers

    def get_vcpe_interface_dhcp_ip(self,vcpe=None):
        if not vcpe:
            vcpe = self.dhcp_vcpes_reserved[0]
        st, _ = getstatusoutput('dhclient {}'.format(vcpe))
	vcpe_ip = get_ip(vcpe)
	return vcpe_ip

    def release_vcpe_interface_dhcp_ip(self,vcpe=None):
        if not vcpe:
            vcpe = self.dhcp_vcpes_reserved[0]
        st, _ = getstatusoutput('dhclient {} -r'.format(vcpe))
        vcpe_ip = get_ip(vcpe)
        assert_equal(vcpe_ip, None)

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

    def get_vsg_health_check(self, vsg_name=None):
        if self.on_pod is False:
            return
        if vsg_name is None:
            vcpe = self.container_vcpes_reserved[0]
            vsg = VSGAccess.get_vcpe_vsg(vcpe)
            status = vsg.get_health()
            return status
        else:
            vsgs = VSGAccess.get_vsgs()
            for vsg in vsgs:
                if vsg.name == vsg_name:
                    status = vsg.get_health()
                    return status
            return None

    def test_vsg_health(self):
        """
        Test Method:
        1. Login to compute node VM
        2. Get all vSGs
        3. Ping to all vSGs
        4. Verifying Ping success
        """
        status = True
        if self.on_pod is True:
            status = VSGAccess.health_check()
        assert_equal(status, True)

    def test_vsg_health_check(self, vsg_name=None, verify_status=True):
        """
        Test Method:
	1. If vsg name not specified, Get vsg corresponding to vcpe
        1. Login to compute mode VM
        3. Ping to the vSG
        4. Verifying Ping success
        """
	st = self.get_vsg_health_check(vsg_name=vsg_name)
	assert_equal(st,verify_status)

    @deferred(30)
    def test_vsg_for_vcpe(self):
        """
        Test Method:
	1. Get list of all compute nodes created using Openstack
        2. Login to compute mode VM
        3. Get all vSGs
        4. Verifying atleast one compute node and one vSG created
        """
        df = defer.Deferred()
        def vsg_for_vcpe_df(df):
            if self.on_pod is True:
                vsgs = VSGAccess.get_vsgs()
                compute_nodes = VSGAccess.get_compute_nodes()
                time.sleep(14)
                assert_not_equal(len(vsgs), 0)
                assert_not_equal(len(compute_nodes), 0)
            df.callback(0)
        reactor.callLater(0,vsg_for_vcpe_df,df)
        return df

    def test_vsg_for_login(self):
        """
        Test Method:
        1. Login to compute node VM
        2. Get all vSGs
        3. Verifying login to vSG is success
        """
        if self.on_pod is False:
            return
        vsgs = VSGAccess.get_vsgs()
        vsg_access_status = map(lambda vsg: vsg.check_access(), vsgs)
        status = filter(lambda st: st == False, vsg_access_status)
        assert_equal(len(status), 0)

    def test_vsg_for_default_route_through_testclient(self):
	"""
	Test Method:
	1. Login to head node
	2. Verifying for default route in lxc test client
	"""
        if self.on_pod is False:
            return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "sudo lxc exec testclient -- route | grep default"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal(status, True)

    @deferred(30)
    def test_vsg_for_external_connectivity_through_testclient(self):
        """
        Test Method:
        1. Login to head node
        2. On head node, executing ping to 8.8.8.8 from lxc test client
	3. Verifying for the ping success
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_external_connectivity(df):
            ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
            cmd = "sudo lxc exec testclient -- ping -c 3 8.8.8.8"
            status, output = ssh_agent.run_cmd(cmd)
            assert_equal( status, True)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_for_external_connectivity(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to 8.8.8.8 and Verifying ping should success
	4. Restoring management interface configuration in  cord-tester
        """
        reserved = True
        if self.on_pod:
            reserved = self.on_ciab
        df = defer.Deferred()
        def test_external_connectivity(df):
            self.vsg_for_external_connectivity(0, reserved = reserved)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_for_external_connectivity_to_google(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to www.google.com and Verifying ping should success
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            host = 'www.google.com'
            vcpe = self.dhcp_vcpes_reserved[0]
            mgmt = 'eth0'
            assert_not_equal(vcpe, None)
	    try:
            	vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
                assert_not_equal(vcpe_ip, None)
                log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
                log.info('Sending icmp ping requests to %s' %host)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
		assert_equal(st, 0)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
                VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    def retrieve_content_from_host_to_validate_path_mtu(self, host):
        vcpe = self.dhcp_vcpes_reserved[0]
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Initiating get requests to %s' %host)
        r = requests.get('http://{}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        return r.status_code

    @deferred(30)
    def test_vsg_to_retrieve_content_from_google_to_validate_path_mtu(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Retrieve contents from www.google.com and Verify response status is 200 ok.
        4. This validates path mtu for end to end traffic with request to retrieve web contents in cord framework.
           (Based on website response, size differs, needs check on MTU)
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.google.com')
            assert_equal(status_code, 200)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_to_retrieve_content_from_rediff_to_validate_path_mtu(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Retrieve contents from www.rediff.com and Verify response status is 200 ok.
        4. This validates path mtu for end to end traffic with request to retrieve web contents in cord framework.
           (Based on website response, size differs, needs check on MTU)
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.rediff.com')
            assert_equal(status_code, 200)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_to_retrieve_content_from_yahoo_to_validate_path_mtu(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Retrieve contents from www.yahoo.com and Verify response status is 200 ok.
        4. This validates path mtu for end to end traffic with request to retrieve web contents in cord framework.
           (Based on website response, size differs, needs check on MTU)
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.yahoo.com')
            assert_equal(status_code, 200)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_to_retrieve_content_from_facebook_to_validate_path_mtu(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Retrieve contents from www.facebook.com and Verify response status is 200 ok.
        4. This validates path mtu for end to end traffic with request to retrieve web contents in cord framework.
           (Based on website response, size differs, needs check on MTU)
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.facebook.com')
            assert_equal(status_code, 200)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df


    @deferred(30)
    def test_vsg_for_external_connectivity_to_invalid_host(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to www.goglee.com and Verifying ping should not success
        4. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            host = 'www.goglee.com'
            vcpe = self.dhcp_vcpes_reserved[0]
            mgmt = 'eth0'
            assert_not_equal(vcpe, None)
	    try:
            	vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
            	assert_not_equal(vcpe_ip, None)
            	log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
            	log.info('Sending icmp ping requests to non existent host %s' %host)
            	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
	    	assert_not_equal(st, 0)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_for_external_connectivity_with_ttl_1(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to 8.8.8.8 with ttl set to 1
	4. Verifying ping should not success
        5. Restoring management interface configuration in  cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            host = '8.8.8.8'
            vcpe = self.dhcp_vcpes_reserved[0]
            mgmt = 'eth0'
            assert_not_equal(vcpe, None)
	    try:
            	vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        	assert_not_equal(vcpe_ip, None)
        	log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        	log.info('Sending icmp ping requests to host %s with ttl 1' %host)
        	st, _ = getstatusoutput('ping -c 1 -t 1 {}'.format(host))
         	assert_not_equal(st, 0)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(60)
    def test_vsg_for_external_connectivity_with_wan_interface_toggle_in_vcpe(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to 8.8.8.8 and Verifying ping succeeds
	4. Now down the WAN interface of vcpe
	5. Ping to 8.8.8.8 and Verifying ping fails
	6. Now Up the WAN interface of vcpe
	7. Ping to 8.8.8.8 and Verifying ping succeeds
	8. Restoring management interface configuration in cord-tester
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            if self.on_pod is False:
                return
            host = '8.8.8.8'
            mgmt = 'eth0'
	    vcpe = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved[0]
            assert_not_equal(vcpe_name, None)
            assert_not_equal(vcpe, None)
            #first get dhcp on the vcpe interface
	    try:
            	vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        	assert_not_equal(vcpe_ip, None)
        	log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        	log.info('Sending ICMP pings to host %s' %(host))
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
		if st != 0:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, 0)
        	#bring down the wan interface and check again
        	st = VSGAccess.vcpe_wan_down(vcpe_name)
        	if st is False:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, True)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	if st == 0:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_not_equal(st, 0)
        	st = VSGAccess.vcpe_wan_up(vcpe_name)
        	if st is False:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, True)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
          	assert_equal(st, 0)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(60)
    def test_vsg_for_external_connectivity_with_lan_interface_toggle_in_vcpe(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to 8.8.8.8 and Verifying ping should success
        4. Now down the LAN interface of vcpe
        5. Ping to 8.8.8.8 and Verifying ping should not success
        6. Now Up the LAN interface of vcpe
        7. Ping to 8.8.8.8 and Verifying ping should success
        8. Restoring management interface configuration in  cord-tester
        """
        if self.on_pod is False:
            return
        df = defer.Deferred()
        def test_external_connectivity(df):
            host = '8.8.8.8'
            mgmt = 'eth0'
            vcpe = self.dhcp_vcpes_reserved[0]
            vcpe_name = self.container_vcpes_reserved[0]
            assert_not_equal(vcpe, None)
            assert_not_equal(vcpe_name, None)
            #first get dhcp on the vcpe interface
	    try:
            	vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
       	 	assert_not_equal(vcpe_ip, None)
        	log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        	log.info('Sending ICMP pings to host %s' %(host))
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	if st != 0:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, 0)
        	#bring down the lan interface and check again
        	st = VSGAccess.vcpe_lan_down(vcpe_name)
        	if st is False:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, True)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	if st == 0:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_not_equal(st, 0)
        	st = VSGAccess.vcpe_lan_up(vcpe_name)
        	if st is False:
            		VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        	assert_equal(st, True)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, 0)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(120)
    def test_vsg_multiple_subscribers_for_same_vcpe_instance(self):
	"""
	Test Method:
	1. Create a vcpe instance
	2. Create multiple vcpe interfaces in cord-tester with same s-tag and c-tag to access vcpe instance
	3. Verify all the interfaces gets dhcp IP in same subnet
	"""
        df = defer.Deferred()
        def test_external_connectivity(df):
            vcpe_intfs,containers = self.get_vcpe_containers_and_interfaces()
            for vcpe in vcpe_intfs:
                vcpe_ip = self.get_vcpe_interface_dhcp_ip(vcpe=vcpe)
                assert_not_equal(vcpe_ip,None)
            for vcpe in vcpe_intfs:
                self.release_vcpe_interface_dhcp_ip(vcpe=vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(120)
    def test_vsg_for_multiple_subscribers_with_same_vcpe_instance_and_validate_external_connectivity(self):
        """
        Test Method:
        1. Create a vcpe instance
        2. Create multiple vcpe interfaces in cord-tester with same s-tag and c-tag to access vcpe instance
        3. Verify all the interfaces gets dhcp IP in same subnet
	4. From cord-tester ping to external  with vcpe interface option
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
            host = '8.8.8.8'
            vcpe_intfs, containers = self.get_vcpe_containers_and_interfaces()
	    try:
                for vcpe in vcpe_intfs:
                    vcpe_ip = self.get_vcpe_interface_dhcp_ip(vcpe=vcpe)
                    assert_not_equal(vcpe_ip,None)
                    self.add_static_route_via_vcpe_interface([host],vcpe=vcpe,dhcp_ip=False)
                    st, _ = getstatusoutput('ping -I {} -c 3 {}'.format(vcpe,host))
                    assert_equal(st, 0)
                    self.del_static_route_via_vcpe_interface([host],vcpe=vcpe,dhcp_release=False)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
        	for vcpe in vcpe_intfs:
            	    self.release_vcpe_interface_dhcp_ip(vcpe=vcpe)
            df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(30)
    def test_vsg_vcpe_interface_and_validate_dhcp_ip_after_interface_toggle(self):
        """
        Test Method:
        1. Create a vcpe instance
        2. Create a vcpe interface in cord-tester
        3. Verify the interface gets dhcp IP
	4. Toggle the interface
	5. Verify the interface gets dhcp IP
        """
        df = defer.Deferred()
        def test_external_connectivity(df):
	    vcpe_intf = self.dhcp_vcpes_reserved[0]
	    host = '8.8.8.8'
            try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, 0)
                os.system('ifconfig {} down'.format(vcpe_intf))
                time.sleep(1)
                os.system('ifconfig {} up'.format(vcpe_intf))
		time.sleep(1)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, 0)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
		self.del_static_route_via_vcpe_interface([host], vcpe=vcpe_intf)
	    df.callback(0)
        reactor.callLater(0,test_external_connectivity,df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_for_external_connectivity_after_restarting_vcpe_instance(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Get dhcp ip to vcpe interface
        3. Add static route to destination route in test container
        4. From test container ping to destination route and verify ping success
        5. Login to compute node and execute command to pause vcpe container
        6. From test container ping to destination route and verify ping success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def test_external_connectivity(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
		clock = 0
		status = False
		while(clock <= 20):
			time.sleep(5)
                	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
			if st == False:
				status = True
				break
			clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, test_external_connectivity, df)
        return df

    @nottest #Setup getting distrubed if vSG VM restart
    @deferred(TIMEOUT)
    def test_vsg_for_external_connectivity_after_restarting_vsg_vm(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Get dhcp ip to vcpe interface
        3. Add static route to destination route in test container
        4. From test container ping to destination route and verify ping success
        5. Login to compute node and execute command to pause vcpe container
        6. From test container ping to destination route and verify ping success
        """
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def test_external_connectivity(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
		vsg.reboot()
                clock = 0
                status = False
                while(clock <= 30):
                        time.sleep(5)
                        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                        if st == False:
                                status = True
                                break
                        clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                vsg.reboot()
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, test_external_connectivity, df)
        return df

    @deferred(60)
    def test_vsg_for_external_connectivity_with_vcpe_container_paused(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
	2. Get dhcp ip to vcpe interface
	3. Add static route to destination route in test container
        4. From test container ping to destination route and verify ping success
        5. Login to compute node and execute command to pause vcpe container
        6. From test container ping to destination route and verify ping success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def test_external_connectivity(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker pause {}'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
		vsg.run_cmd('sudo docker unpause {}'.format(vcpe_name))
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
		raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, test_external_connectivity, df)
        return df

    @deferred(30)
    def test_vsg_firewall_with_deny_destination_ip_set(self, vcpe_name=None, vcpe_intf=None):
	"""
	Test Method:
	1. Get vSG corresponding to vcpe
	2. Login to compute node
	3. Execute iptable command on vcpe from compute node to deny a destination IP
	4. From cord-tester ping to the denied IP address
	5. Verifying that ping should not be successful
	"""
	if not vcpe_name:
		vcpe_name = self.container_vcpes_reserved[0]
	if not vcpe_intf:
		vcpe_intf = self.dhcp_vcpes_reserved[0]
	df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
            	st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
            	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
            	assert_equal(st, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		#vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
	reactor.callLater(0, vcpe_firewall, df)
	return df

    @deferred(60)
    def test_vsg_firewall_with_rule_to_add_and_delete_dest_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        4. From cord-tester ping to the denied IP address
	5. Verifying that ping should not be successful
	6. Delete the iptable rule in  vcpe
	7. From cord-tester ping to the denied IP address
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
	    host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
	        self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
	        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
	        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
	        st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
		raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
	        self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		#vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_verifying_reachability_for_non_blocked_dest_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        4. From cord-tester ping to the denied IP address
	5. Verifying that ping should not be successful
	6. From cord-tester ping to the denied IP address other than the denied one
        7. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host1 = '8.8.8.8'
            host2 = '204.79.197.203'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        	assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_appending_rules_with_deny_dest_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP1
        4. From cord-tester ping to the denied IP address IP1
        5. Verifying that ping should not be successful
	6. Execute iptable command on vcpe from compute node to deny a destination IP2
        6. From cord-tester ping to the denied IP address IP2
        7. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host1 = '8.8.8.8'
            host2 = '204.79.197.203'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, False)
		st,_ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host1))
		time.sleep(1)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, out = getstatusoutput('ping -c 1 {}'.format(host2))
		log.info('host2 ping output is %s'%out)
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 2 -d {} -j DROP'.format(vcpe_name,host2))
		time.sleep(1)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_removing_one_rule_denying_dest_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP1
        4. Execute iptable command on vcpe from compute node to deny a destination IP2
        5. From cord-tester ping to the denied IP address IP1
        6. Verifying that ping should not be successful
        7. From cord-tester ping to the denied IP address IP2
        8. Verifying that ping should not be successful
        9. Execute iptable command on vcpe from compute node to remove deny a destination IP2 rule
        10. From cord-tester ping to the denied IP address IP2
        11. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host1 = '8.8.8.8'
            host2 = '204.79.197.203'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
                self.add_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
	        st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,False)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
		#vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_changing_rule_id_deny_dest_ip(self, vcpe_name=None, vcpe_intf=None):
	"""
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        5. From cord-tester ping to the denied IP address IP1
        6. Verifying that ping should not be successful
        9. Execute iptable command on vcpe from compute node to change the rule ID to 2 to  deny the same  destination IP
        10. From cord-tester ping to the denied IP address IP
        11. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 2 -d {} -j DROP '.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(50)
    def test_vsg_firewall_changing_deny_rule_to_accept_dest_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        5. From cord-tester ping to the denied IP address IP1
        6. Verifying that ping should not be successful
        9. Execute iptable command on vcpe from compute node to accept the same  destination IP
        10. From cord-tester ping to the accepted IP
        11. Verifying the ping should  success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
	    vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -d {} -j ACCEPT'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j ACCEPT'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_denying_destination_network(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP subnet
        4. From cord-tester ping to the denied IP address IP1 in the denied subnet
        5. Verifying that ping should not be successful
        6. From cord-tester ping to the denied IP address IP2 in the denied subnet
        7. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            network = '204.79.197.192/28'
            host1 = '204.79.197.203'
            host2 = '204.79.197.210'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
	        self.add_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
		st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,network))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_denying_destination_network_subnet_modification(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP subnet
        4. From cord-tester ping to the denied IP address IP1 in the denied subnet
        5. Verifying that ping should not be successful
        6. From cord-tester ping to the denied IP address IP2 in the denied subnet
        7. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            network1 = '204.79.197.192/28'
            network2 = '204.79.197.192/27'
            host1 = '204.79.197.203'
            host2 = '204.79.197.210'
            host3 = '204.79.197.224'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host1,host2,host3],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,network1))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 2 -d {} -j DROP'.format(vcpe_name,network2))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host3))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network1))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network2))
                self.del_static_route_via_vcpe_interface([host1,host2,host3],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_with_deny_source_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a source IP
        4. From cord-tester ping to 8.8.8.8 from the denied IP
        5. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		source_ip = get_ip(vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_rule_with_add_and_delete_deny_source_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a source IP
        4. From cord-tester ping to 8.8.8.8 from the denied IP
        5. Verifying that ping should not be successful
	6. Delete the iptable rule in vcpe
	7. From cord-tester ping to 8.8.8.8 from the denied IP
	8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            source_ip = get_ip(self.vcpe_dhcp)
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
	        self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		source_ip = get_ip(vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
	        st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_requests_type(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny icmp echo-requests type protocol packets
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
	6. Delete the iptable rule
	7. From cord-tester ping to 8.8.8.8
	8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
		st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
	    except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_reply_type(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny icmp echo-reply type protocol packets
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Delete the iptable rule
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format('8.8.8.8'))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_requests_type(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny icmp echo-requests type protocol packets
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Insert another rule to accept the icmp-echo requests protocol packets
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD  -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -p icmp --icmp-type echo-request -j ACCEPT'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j ACCEPT'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_reply_type(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny icmp echo-reply type protocol packets
        4. From cord-tester ping to 8.8.8.8
        5. Verifying the ping should not success
        6. Insert another rule to accept the icmp-echo requests protocol packets
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	        assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD  -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -p icmp --icmp-type echo-reply -j ACCEPT'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j ACCEPT'.format(vcpe_name))
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_for_deny_icmp_protocol(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny icmp protocol packets
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Delete the iptable rule
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		#vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_rule_deny_icmp_protocol_and_destination_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Execute iptable command on vcpe from compute node to deny icmp protocol packets
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
	9. Delete the rule added in step 3
	10. From cord-tester ping to 8.8.8.8
	11. Verifying that ping should not be successful
	12. Delete the rule added in step 6
	13. From cord-tester ping to 8.8.8.8
	14. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe_name))
		st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
		st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {}  -j DROP'.format(vcpe_name,host))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {}  -j DROP'.format(vcpe_name,host))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(100)
    def test_vsg_firewall_flushing_all_configured_rules(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a destination IP
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Execute iptable command on vcpe from compute node to deny icmp protocol packets
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        9. Flush all the iptable rules configuraed in vcpe
        10. Delete the rule added in step 6
        11. From cord-tester ping to 8.8.8.8
        12. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -F FORWARD'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
		vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
		status = False
		clock = 0
		while(clock <= 30):
		    time.sleep(5)
                    st,_ = getstatusoutput('ping -c 1 {}'.format(host))
		    if st == False:
			status = True
			break
		    clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_deny_all_ipv4_traffic(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all ipv4 Traffic
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Delete the iptable  rule added
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_replacing_deny_rule_to_accept_rule_ipv4_traffic(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all ipv4 Traffic
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Replace the deny rule added in step 3 with accept rule
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -4 -j ACCEPT'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_deny_all_traffic_coming_on_lan_interface_in_vcpe(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all the  traffic coming on lan interface inside vcpe container
        4. From cord-tester ping to 8.8.8.8
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -i eth1 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_deny_all_traffic_going_out_of_wan_interface_in_vcpe(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all the  traffic going out of wan interface inside vcpe container
        4. From cord-tester ping to 8.8.8.8
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD  -o eth0 -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_firewall_deny_all_traffic_from_lan_to_wan_in_vcpe(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all the  traffic from lan to wan interface in vcpe
        4. From cord-tester ping to 8.8.8.8
        5. Verifying that ping should not be successful
        6. Delete the iptable  rule added
        7. From cord-tester ping to 8.8.8.8
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
	    host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_deny_all_dns_traffic(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all dns Traffic
        4. From cord-tester ping to www.google.com
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to www.google.com
        8. Verifying the ping should success
        """
	mgmt = 'eth0'
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = 'google-public-dns-a.google.com'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p udp --dport 53 -j DROP'.format(vcpe_name))
		vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe_intf, mgmt = mgmt)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_not_equal(st, False)
		VSGAccess.restore_interface_config(mgmt, vcpe=vcpe_intf)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p udp --dport 53 -j DROP'.format(vcpe_name))
                vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe_intf, mgmt = mgmt)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
		VSGAccess.restore_interface_config(mgmt, vcpe=vcpe_intf)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p udp --dport 53 -j DROP'.format(vcpe_name))
		VSGAccess.restore_interface_config(mgmt,vcpe=vcpe_intf)
                raise
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(60)
    def test_vsg_firewall_deny_all_ipv4_traffic_vcpe_container_restart(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all dns Traffic
        4. From cord-tester ping to www.google.com
        5. Verifying that ping should not be successful
        6. Delete the iptable  rule added
        7. From cord-tester ping to www.google.com
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
		clock = 0
		status = False
		while(clock <= 20 ):
		    time.sleep(5)
		    st, _ = getstatusoutput('ping -c 1 {}'.format(host))
		    if st == False:
			status = True
			break
		    clock += 5
                assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(40)
    def test_vsg_nat_dnat_modifying_destination_ip(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all dns Traffic
        4. From cord-tester ping to www.google.com
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to www.google.com
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
	    dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
            finally:

                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    @deferred(40)
    def test_vsg_nat_dnat_modifying_destination_ip_and_delete(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all dns Traffic
        4. From cord-tester ping to www.google.com
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to www.google.com
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
            dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
		st, _ = vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
		vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                raise
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    @deferred(50)
    def test_vsg_dnat_change_modifying_destination_ip_address(self, vcpe_name=None, vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny all dns Traffic
        4. From cord-tester ping to www.google.com
        5. Verifying the ping should not success
        6. Delete the iptable  rule added
        7. From cord-tester ping to www.google.com
        8. Verifying the ping should success
        """
        if not vcpe_name:
                vcpe_name = self.container_vcpes_reserved[0]
        if not vcpe_intf:
                vcpe_intf = self.dhcp_vcpes_reserved[0]
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
            dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -R PREROUTING 1  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                #vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    def vsg_xos_subscriber_create(self, index, subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return ''
        if subscriber_info is None:
            subscriber_info = self.cord_subscriber.subscriber_info[index]
        if volt_subscriber_info is None:
            volt_subscriber_info = self.cord_subscriber.volt_subscriber_info[index]
        s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
        c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
        vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
        subId = self.cord_subscriber.subscriberCreate(index, subscriber_info, volt_subscriber_info)
        if subId:
            #if the vsg instance was already instantiated, then reduce delay
            if c_tag % self.SUBSCRIBERS_PER_S_TAG == 0:
                delay = 350
            else:
                delay = 90
            log.info('Delaying %d seconds for the VCPE to be provisioned' %(delay))
            time.sleep(delay)
            log.info('Testing for external connectivity to VCPE %s' %(vcpe))
            self.vsg_for_external_connectivity(index)

        return subId

    def vsg_xos_subscriber_delete(self, index, subId = '', voltId = '', subscriber_info = None, volt_subscriber_info = None):
        if self.on_pod is False:
            return
        self.cord_subscriber.subscriberDelete(index, subId = subId, voltId = voltId,
                                              subscriber_info = subscriber_info,
                                              volt_subscriber_info = volt_subscriber_info)

    def vsg_xos_subscriber_id(self, index):
        if self.on_pod is False:
            return ''
        return self.cord_subscriber.subscriberId(index)

    def test_vsg_xos_subscriber_create_reserved(self):
        if self.on_pod is False:
            return
        tags_reserved = [ (int(vcpe['s_tag']), int(vcpe['c_tag'])) for vcpe in self.vcpes_reserved ]
        volt_tenants = self.restApiXos.ApiGet('TENANT_VOLT')
        subscribers = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        reserved_tenants = filter(lambda tenant: (int(tenant['s_tag']), int(tenant['c_tag'])) in tags_reserved, volt_tenants)
        reserved_config = []
        for tenant in reserved_tenants:
            for subscriber in subscribers:
                if int(subscriber['id']) == int(tenant['subscriber']):
                    volt_subscriber_info = {}
                    volt_subscriber_info['voltTenant'] = dict(s_tag = tenant['s_tag'],
                                                              c_tag = tenant['c_tag'],
                                                              subscriber = tenant['subscriber'])
                    volt_subscriber_info['volt_id'] = tenant['id']
                    volt_subscriber_info['account_num'] = subscriber['identity']['account_num']
                    reserved_config.append( (subscriber, volt_subscriber_info) )
                    break
            else:
                log.info('Subscriber not found for tenant %s, s_tag: %s, c_tag: %s' %(str(tenant['subscriber']),
                                                                                      str(tenant['s_tag']),
                                                                                      str(tenant['c_tag'])))

        for subscriber_info, volt_subscriber_info in reserved_config:
            self.vsg_xos_subscriber_delete(0,
                                           subId = str(subscriber_info['id']),
                                           voltId = str(volt_subscriber_info['volt_id']),
                                           subscriber_info = subscriber_info,
                                           volt_subscriber_info = volt_subscriber_info)
            subId = self.vsg_xos_subscriber_create(0,
                                                   subscriber_info = subscriber_info,
                                                   volt_subscriber_info = volt_subscriber_info)
            log.info('Created reserved subscriber %s' %(subId))

    def vsg_create(self, num_subscribers):
        if self.on_pod is False:
            return
        num_subscribers = min(num_subscribers, len(self.cord_subscriber.subscriber_info))
        for index in xrange(num_subscribers):
            #check if the index exists
            subId = self.vsg_xos_subscriber_id(index)
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)
            subId = self.vsg_xos_subscriber_create(index)
            log.info('Created Subscriber %s' %(subId))

    def test_vsg_xos_subscriber_create_all(self):
        self.vsg_create(len(self.cord_subscriber.subscriber_info))

    def vsg_delete(self, num_subscribers):
        if self.on_pod is False:
            return
        num_subscribers = min(num_subscribers, len(self.cord_subscriber.subscriber_info))
        for index in xrange(num_subscribers):
            subId = self.vsg_xos_subscriber_id(index)
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)

    def test_vsg_xos_subscriber_delete_all(self):
        self.vsg_delete(len(self.cord_subscriber.subscriber_info))

    def test_vsg_xos_subscriber_create_and_delete(self):
        subId = self.vsg_xos_subscriber_create(0)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(0, subId)

    def test_vsg_xos_subscriber_2_create_and_delete(self):
        subId = self.vsg_xos_subscriber_create(1)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(1, subId)

    def test_vsg_xos_subscriber_3_create_and_delete(self):
        subId = self.vsg_xos_subscriber_create(2)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(2, subId)

    def test_vsg_xos_subscriber_4_create_and_delete(self):
        subId = self.vsg_xos_subscriber_create(3)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(3, subId)

    def test_vsg_xos_subscriber_5_create_and_delete(self):
        subId = self.vsg_xos_subscriber_create(4)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(4, subId)

    @deferred(400)
    def test_vsg_xos_subscriber_external_connectivity_through_vcpe_instance(self, index=0):
        df = defer.Deferred()
        status = False
        def test_xos_subscriber(df):
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                log.info('Creating vcpe instance ')
		subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            vcpe = self.dhcp_vcpes[index]
            host = '8.8.8.8'
            self.add_static_route_via_vcpe_interface([host],vcpe=vcpe)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
	    self.del_static_route_via_vcpe_interface([host],vcpe=vcpe)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    #pass
    @deferred(50)
    def test_vsg_xos_subscriber_external_connectivity_without_creating_vcpe_instance(self, index=0):
        df = defer.Deferred()
        def test_xos_subscriber(df):
            subId = self.vsg_xos_subscriber_id(index)
            if subId != '0':
		log.info('deleting already existing vcpe instance ')
		self.vsg_xos_subscriber_delete(index, subId)
	    vcpe = self.dhcp_vcpes[index]
	    host = '8.8.8.8'
	    self.add_static_route_via_vcpe_interface([host],vcpe=vcpe)
	    st, out = getstatusoutput('route -n')
	    log.info('route -n outpu-1-1-1--1-1-1-1-1-1-1  is %s'%out)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
	    self.del_static_route_via_vcpe_interface([host],vcpe=vcpe)
            assert_equal(st, True)
	    df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
	return df

    @deferred(400)
    def test_vsg_xos_subscriber_external_connectivity_after_removing_vcpe_instance_from_xos(self,index=0,host = '8.8.8.8'):
        df = defer.Deferred()
        def test_xos_subscriber(df):
	    subId = self.vsg_xos_subscriber_id(index)
	    if subId == '0':
        	subId = self.vsg_xos_subscriber_create(index)
	    assert_not_equal(subId,'0')
	    vcpe = self.dhcp_vcpes[index]
            if subId and subId != '0':
	        self.add_static_route_via_vcpe_interface([host],vcpe=vcpe)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                self.vsg_xos_subscriber_delete(index, subId)
	        time.sleep(2)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
	        self.del_static_route_via_vcpe_interface([host],vcpe=vcpe)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(400)
    def test_vsg_xos_subscriber_external_connectivity_after_restarting_vcpe_instance(self, index=0, host = '8.8.8.8'):
        df = defer.Deferred()
        def test_xos_subscriber(df):
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
	    vcpe_intf = self.dhcp_vcpes[index]
            self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
	    vcpe_name = 'vcpe-{}-{}'.format(vcpe_intf.split('.')[1],vcpe_intf.split('.')[2])
	    vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    st, _ = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
	    assert_equal(st, True)
            time.sleep(5)
            self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(400)
    def test_vsg_xos_subscriber_external_connectivity_toggling_vcpe_instance(self, index=0, host = '8.8.8.8'):
        df = defer.Deferred()
        def test_xos_subscriber(df):
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            vcpe_intf = self.dhcp_vcpes[index]
            self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
            vcpe_name = 'vcpe-{}-{}'.format(vcpe_intf.split('.')[1],vcpe_intf.split('.')[2])
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            st, _ = vsg.run_cmd('sudo docker stop {}'.format(vcpe_name))
            assert_equal(st, True)
            time.sleep(3)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, True)
            st, _ = vsg.run_cmd('sudo docker start {}'.format(vcpe_name))
            assert_equal(st, True)
            time.sleep(5)
            st,_ = getstatusoutput('ping -c 1 {}'.format(host))
            assert_equal(st, False)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    #getting list out of range error while creating vcpe of index 6
    def test_vsg_create_xos_subscribers_in_different_vsg_vm(self, index1=4, index2=6):
	indexes = list(index1,index2)
	subids = []
	for index in indexes:
        	subId = self.vsg_xos_subscriber_id(index)
        	if not subId:
        		subId = self.vsg_xos_subscriber_create(index)
		assert_not_equal(subId,'0')
		subids.append(subId)
	log.info('succesfully created two vcpe instances in two different vSG VMs')
	self.vsg_xos_subscriber_delete(index1, subid[0])
	self.vsg_xos_subscriber_delete(index2, subid[1])

    #Unable to reach external network via vcpes created by XOS
    @deferred(TIMEOUT+400)
    def test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_goes_down(self):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Kill first vcpe instance
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df):
            host1 = '8.8.8.8'
	    host2 = '4.2.2.2'
            vcpe_intf1 = self.dhcp_vcpes[0]
            vcpe_intf2 = self.dhcp_vcpes[1]
            vcpe_name1 = 'vcpe-{}-{}'.format(vcpe_intf1.split('.')[1],vcpe_intf1.split('.')[2])
            vcpe_name2 = 'vcpe-{}-{}'.format(vcpe_intf2.split('.')[1],vcpe_intf2.split('.')[2])
            subId1 = self.vsg_xos_subscriber_id(0)
            log.info('already existing subid of index 0 is %s'%subId1)
            if subId1 == '0':
		log.info('creating vcpe instance of index 0')
                subId1 = self.vsg_xos_subscriber_create(0)
	    assert_not_equal(subId1,'0')
            subId2 = self.vsg_xos_subscriber_id(1)
            log.info('already existing subid of index 1 is %s'%subId2)
            if subId2 == '0':
		log.info('creating vcpe instance of index 1')
                subId2 = self.vsg_xos_subscriber_create(1)
	    assert_not_equal(subId2,'0')
	    vsg1 = VSGAccess.get_vcpe_vsg(vcpe_name1)
	    vsg2 = VSGAccess.get_vcpe_vsg(vcpe_name2)
	    try:
		for intf in [vcpe_intf1,vcpe_intf2]:
		    host = host1 if intf is vcpe_intf1 else host2
		    self.add_static_route_via_vcpe_interface([host],vcpe=intf)
                    st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                    assert_equal(st, False)
		    if intf is vcpe_intf2:
	    		self.vsg_xos_subscriber_delete(1, subId2)
            		st, _  = vsg2.run_cmd('sudo docker kill {}'.format(vcpe_name2))
            		time.sleep(2)
			self.add_static_route_via_vcpe_interface([host],vcpe=intf)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                        assert_equal(st, False)
                        st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                        assert_equal(st, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
            	self.vsg_xos_subscriber_delete(0, subId1)
            	self.vsg_xos_subscriber_delete(1, subId2)
		self.del_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
		self.del_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(TIMEOUT+400)
    def test_vsg_xos_subscriber_external_connectivity_after_vcpe_is_removed_and_added_again(self,index=0):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Remove first vcpe instance
        4.Verify external network cant be reachable form first vcpe interface
	5.Add back the removed vcpe instance
	6.Verify external connectivity through vcpe instances from cord-tester
        """
        df = defer.Deferred()
        def test_xos_subscriber(df,index=index):
            host = '8.8.8.8'
            subId = self.vsg_xos_subscriber_id(index)
            log.info('already existing subid of index 0 is %s'%subId)
            if subId == '0':
                log.info('creating vcpe instance of index %s'%index)
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            vcpe_intf = self.dhcp_vcpes[0]
            vcpe_name = 'vcpe-{}-{}'.format(vcpe_intf.split('.')[1],vcpe_intf.split('.')[2])
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
        	self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
	        st,_ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
		log.info('Deleting vcpe Instance of index %s'%index)
		self.vsg_xos_subscriber_delete(0, subId)
        	st, _ = vsg.run_cmd('sudo docker kill {}'.format(vcpe_name))
		time.sleep(1)
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st,_ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, True)
		subId = self.vsg_xos_subscriber_create(index)
        	self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
        	st,_ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		self.vsg_xos_subscriber_delete(0, subId)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(TIMEOUT+400)
    def test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_restarts(self):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Restart first vcpe instance
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df):
            host1 = '8.8.8.8'
	    host2 = '4.2.2.2'
            subId1 = self.vsg_xos_subscriber_id(0)
            log.info('already existing subid of index 0 is %s'%subId1)
            if subId1 == '0':
                log.info('creating vcpe instance of index 0')
                subId1 = self.vsg_xos_subscriber_create(0)
            assert_not_equal(subId1,'0')
            subId2 = self.vsg_xos_subscriber_id(1)
            log.info('already existing subid of index 1 is %s'%subId2)
            if subId2 == '0':
                log.info('creating vcpe instance of index 1')
                subId2 = self.vsg_xos_subscriber_create(1)
            vcpe_intf1 = self.dhcp_vcpes[0]
            vcpe_intf2 = self.dhcp_vcpes[1]
            vcpe_name1 = 'vcpe-{}-{}'.format(vcpe_intf1.split('.')[1],vcpe_intf1.split('.')[2])
            vcpe_name2 = 'vcpe-{}-{}'.format(vcpe_intf2.split('.')[1],vcpe_intf2.split('.')[2])
            vsg1 = VSGAccess.get_vcpe_vsg(vcpe_name1)
            vsg2 = VSGAccess.get_vcpe_vsg(vcpe_name2)
	    try:
		#checking external connectivity from vcpe interface 1 before vcpe 2 restart
		self.add_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
		#checking external connectivity from vcpe interface 2 before vcpe 2 restart
                self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, False)
        	st, _  = vsg2.run_cmd('sudo docker restart {}'.format(vcpe_name2))
		time.sleep(10)
		#checking external connectivity from vcpe interface 1 after vcpe 2 restart
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
		self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
		time = 0
		status = False
		while(time <= 100):
		     time.sleep(10)
		     st,_ = getstatusoutput('ping -c 1 {}'.format(hos2))
		     if st is False:
			status = True
        		break
		     time += 10
		assert_equal(status, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
        	self.del_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
        	self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                self.vsg_xos_subscriber_delete(0, subId1)
        	self.vsg_xos_subscriber_delete(1, subId2)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(500)
    def test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_is_paused(self):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Pause running first vcpe instance
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df):
            host1 = '8.8.8.8'
            host2 = '4.2.2.2'
            subId1 = self.vsg_xos_subscriber_id(0)
            log.info('already existing subid of index 0 is %s'%subId1)
            if subId1 == '0':
                log.info('creating vcpe instance of index 0')
                subId1 = self.vsg_xos_subscriber_create(0)
            assert_not_equal(subId1,'0')
            subId2 = self.vsg_xos_subscriber_id(1)
            log.info('already existing subid of index 1 is %s'%subId2)
            if subId2 == '0':
                log.info('creating vcpe instance of index 1')
                subId2 = self.vsg_xos_subscriber_create(1)
            vcpe_intf1 = self.dhcp_vcpes[0]
            vcpe_intf2 = self.dhcp_vcpes[1]
            vcpe_name1 = 'vcpe-{}-{}'.format(vcpe_intf1.split('.')[1],vcpe_intf1.split('.')[2])
            vcpe_name2 = 'vcpe-{}-{}'.format(vcpe_intf2.split('.')[1],vcpe_intf2.split('.')[2])
            vsg1 = VSGAccess.get_vcpe_vsg(vcpe_name1)
            vsg2 = VSGAccess.get_vcpe_vsg(vcpe_name2)
            try:
                #checking external connectivity from vcpe interface 1 before vcpe 2 pause
                self.add_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                #checking external connectivity from vcpe interface 2 before vcpe 2 pause
                self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, False)
                st, _  = vsg2.run_cmd('sudo docker pause {}'.format(vcpe_name2))
                time.sleep(1)
                #checking external connectivity from vcpe interface 1 after vcpe 2 pause
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                #checking external connectivity from vcpe interface 2 after vcpe 2 pause
                st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                log.info('In Finally block 3333333333333333')
		st, _  = vsg2.run_cmd('sudo docker unpause {}'.format(vcpe_name2))
                self.del_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
                self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                self.vsg_xos_subscriber_delete(0, subId1)
                self.vsg_xos_subscriber_delete(1, subId2)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(500)
    def test_vsg_xos_subscriber_external_connectivity_if_one_vcpe_stops(self):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Stop running first vcpe instance
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df):
            host1 = '8.8.8.8'
            host2 = '4.2.2.2'
            subId1 = self.vsg_xos_subscriber_id(0)
            log.info('already existing subid of index 0 is %s'%subId1)
            if subId1 == '0':
                log.info('creating vcpe instance of index 0')
                subId1 = self.vsg_xos_subscriber_create(0)
            assert_not_equal(subId1,'0')
            subId2 = self.vsg_xos_subscriber_id(1)
            log.info('already existing subid of index 1 is %s'%subId2)
            if subId2 == '0':
                log.info('creating vcpe instance of index 1')
                subId2 = self.vsg_xos_subscriber_create(1)
            vcpe_intf1 = self.dhcp_vcpes[0]
            vcpe_intf2 = self.dhcp_vcpes[1]
            vcpe_name1 = 'vcpe-{}-{}'.format(vcpe_intf1.split('.')[1],vcpe_intf1.split('.')[2])
            vcpe_name2 = 'vcpe-{}-{}'.format(vcpe_intf2.split('.')[1],vcpe_intf2.split('.')[2])
            vsg1 = VSGAccess.get_vcpe_vsg(vcpe_name1)
            vsg2 = VSGAccess.get_vcpe_vsg(vcpe_name2)
            try:
                #checking external connectivity from vcpe interface 1 before vcpe 2 stop
                self.add_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                #checking external connectivity from vcpe interface 2 before vcpe 2 stop
                self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, False)
                st, _  = vsg2.run_cmd('sudo docker stop {}'.format(vcpe_name2))
                time.sleep(5)
                #checking external connectivity from vcpe interface 1 after vcpe 2 stop
                st,_ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                #checking external connectivity from vcpe interface 1 after vcpe 2 stop
		self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
                raise
            finally:
                st, _  = vsg2.run_cmd('sudo docker start {}'.format(vcpe_name2))
                time.sleep(10)
                self.del_static_route_via_vcpe_interface([host1],vcpe=vcpe_intf1)
                self.add_static_route_via_vcpe_interface([host2],vcpe=vcpe_intf2)
                self.vsg_xos_subscriber_delete(0, subId1)
                self.vsg_xos_subscriber_delete(1, subId2)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(420)
    def test_vsg_xos_subscriber_external_connectivity_after_vsg_vm_is_stopped(self, index=0):
        """
        Test Method:
        1.Create two vcpe instances in two different vsg vms using XOS
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Bring down first vSG vm
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df,index=index):
            host = '8.8.8.8'
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                log.info('creating vcpe instance of index 0')
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            vcpe_intf = self.dhcp_vcpes[index] #'vcpe{}.{}.{}'.format(s_tag, c_tag)
            vcpe_name = self.container_vcpes[index]
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
		log.info('Stopping vsg instance')
		vsg.stop()
		time.sleep(5)
		self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		st, _ = getstatusoutput('ping -c 1 {}'.format(host))
		assert_equal(st, True)
	    except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
		vsg.start()
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		self.vsg_xos_subscriber_delete(index, subId)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(420)
    def test_vsg_xos_subscriber_external_connectivity_after_vsg_vm_is_restarted(self, index=0):
        """
        Test Method:
        1.Create subscriber
        2.Verify external connectivity through vcpe instances from cord-tester
        3.Bring down first vSG vm
        4.Verify external network cant be reachable form first vcpe interface
        """
        df = defer.Deferred()
        def test_xos_subscriber(df,index=index):
            host = '8.8.8.8'
            subId = self.vsg_xos_subscriber_id(index)
            if subId == '0':
                log.info('creating vcpe instance of index 0')
                subId = self.vsg_xos_subscriber_create(index)
            assert_not_equal(subId,'0')
            vcpe_intf = self.dhcp_vcpes[index] #'vcpe{}.{}.{}'.format(s_tag, c_tag)
            vcpe_name = self.container_vcpes[index]
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                log.info('Restarting vsg instance')
                vsg.reboot()
                time.sleep(10)
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		time = 0
		status = False
		while(time <= 100):
			time.sleep(10)
                	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
			if st is False:
                		status = True
				break
			time += 10
		assert_equal(status, True)
            except Exception as error:
                log.info('Got Unexpected error %s'%error)
	  	raise
	    finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		self.vsg_xos_subscriber_delete(index, subId)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(780)
    def test_vsg_xos_multiple_subscribers_external_connectivity_if_two_vsgs_stop_and_start(self, index1=4, index2=6):
	"""
	Test Method:
	1.Create two vcpe instances in two different vsg vms using XOS
	2.Verify external connectivity through vcpe instances from cord-tester
	3.Bring down first vSG vm
	4.Verify external network cant be reachable form first vcpe interface
	5.Bring down second vSG vm also
	6.Verify external network cant be reachable form first vcpe interface also
	"""
        df = defer.Deferred(df,index1=index1,index2=index2)
        def test_xos_subscriber(df,index=index):
            subId1 = self.vsg_xos_subscriber_create(index1)
            subId2 = self.vsg_xos_subscriber_create(index2)
            if subId1 == '0':
                self.vsg_xos_subscriber_delete(index1, subId1)
	    assert_not_equal(subId1, '0')
            if subId2 == '0':
                self.vsg_xos_subscriber_delete(index2, subId2)
	    assert_not_equal(subId2, '0')
	    for index in [index1,index2]:
                vcpe_intf = self.dhcp_vcpes[index] #'vcpe{}.{}.{}'.format(s_tag, c_tag)
                vcpe_name = self.container_vcpes[index]
                vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
		try:
                    self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                    st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                    assert_equal(st, False)
		    log.info('Stopping vsg instance of index %s'%index)
		    vsg.stop()
		    time.sleep(5)
                    self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                    st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                    assert_equal(st, True)
		except Exception as error:
		    log.info('Got Unexpected error %s'%error)
		    raise
		finally:
		    vsg.start()
		    self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    @deferred(420)
    def test_vsg_xos_subscriber_external_connectivity_with_creating_firewall_rule(self,index=0):
        """
        Alog:
        1.Cretae a vcpe instance using XOS
        2.Get dhcp IP to vcpe interface in cord-tester
        3.Verify external network can be reachable from cord-tester
        4.Add an iptable rule to drop packets destined to external network in vcpe
        5.Verify now external network cant be reachable
        6.Delele the iptable in vcpe instance
        7.Verify external network can be reachable from cord-tester
        """
        df = defer.Deferred()
        def test_xos_subscriber(df,index=index):
            log.info('cls.dhcp_vcpes is %s'%self.dhcp_vcpes)
            host = '8.8.8.8'
            subId = self.vsg_xos_subscriber_create(index)
	    if subId == '0':
		subId = self.vsg_xos_subscriber_create(index)
	    assert_not_equal(subId, '0')
            vcpe_intf = self.dhcp_vcpes[index] #'vcpe{}.{}.{}'.format(s_tag, c_tag)
	    vcpe_name = self.container_vcpes[index]
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                #ssert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
		self.vsg_xos_subscriber_delete(index, subId)
            except Exception as error:
		log.info('Got Unexpected error %s'%error)
		raise
	    finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		self.vsg_xos_subscriber_delete(index, subId)
            df.callback(0)
        reactor.callLater(0,test_xos_subscriber,df)
        return df

    def test_vsg_for_packet_received_with_invalid_ip_fields(self):
	"""
	Test Method:
	1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
	4.From subscriber, send a ping packet with invalid ip fields
	5.Verify that vSG drops the packet
	6.Verify ping fails
	"""

    def test_vsg_for_packet_received_with_invalid_mac_fields(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send a ping packet with invalid mac fields
        5.Verify that vSG drops the packet
        6.Verify ping fails
        """

    def test_vsg_for_vlan_id_mismatch_in_stag(self):
        """
        Test Method:
        1.Create a vSG VM in compute Node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.Send a ping request to external valid IP from subscriber, with incorrect vlan id in  s-tag and valid c-tag
        5.Verify that ping fails as the packet drops at VM entry
        6.Repeat step 4 with correct s-tag
	7.Verify that ping success
        """

    def test_vsg_for_vlan_id_mismatch_in_ctag(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.Send a ping request to external valid IP from subscriber, with valid s-tag and incorrect vlan id in c-tag
        5.Verify that ping fails as the packet drops at vCPE container entry
        6.Repeat step 4 with valid s-tag and c-tag
        7.Verify that ping success
        """

    def test_vsg_for_matching_and_mismatching_vlan_id_in_stag(self):
        """
        Test Method:
        1.Create two vSG VMs in compute node
	2.Create a vCPE container in each vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber one, send ping request with valid s and c tags
        5.From subscriber two, send ping request with vlan id mismatch in s-tag and valid c tags
        6.Verify that ping success for only subscriber one and fails for two.
        """

    def test_vsg_for_matching_and_mismatching_vlan_id_in_ctag(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
	2.Create two vCPE containers in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber one, send ping request with valid s and c tags
        5.From subscriber two, send ping request with valid s-tag and vlan id mismatch in c-tag
        6.Verify that ping success for only subscriber one and fails for two
        """

    def test_vsg_for_out_of_range_vlanid_in_ctag(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        4.From subscriber, send ping request with valid stag and vlan id in c-tag is an out of range value ( like 0,4097 )
        4.Verify that ping fails as the ping packets drops at vCPE container entry
        """

    def test_vsg_for_out_of_range_vlanid_in_stag(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
	2.Create a vCPE container in vSG VM
	3.Ensure vSG VM and vCPE container created properly
        2.From subscriber, send ping request with vlan id in s-tag is an out of range value ( like 0,4097 ), with valid c-tag
        4.Verify that ping fails as the ping packets drops at vSG VM entry
        """

    def test_vsg_for_extracting_all_compute_stats_from_all_vcpe_containers(self):
	"""
	Test Method:
	1.Create a vSG VM in compute node
	2.Create 10 vCPE containers in VM
	3.Ensure vSG VM and vCPE containers created properly
	4.Login to all vCPE containers
	4.Get all compute stats from all vCPE containers
	5.Verify the stats # verification method need to add
	"""

    def test_vsg_for_extracting_dns_stats_from_all_vcpe_containers(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create 10 vCPE containers in VM
        3.Ensure vSG VM and vCPE containers created properly
	4.From  10 subscribers, send ping to valid and invalid dns hosts
        5.Verify dns resolves and ping success for valid dns hosts
	6.Verify ping fails for invalid dns hosts
        7.Verify dns host name resolve flows in OvS
	8.Login to all 10 vCPE containers
	9.Extract all dns stats
	10.Verify dns stats for queries sent, queries received for dns host resolve success and failed scenarios
        """
        pass
