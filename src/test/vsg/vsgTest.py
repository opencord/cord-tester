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
from CordTestConfig import setup_module, running_on_ciab
from OnosCtrl import OnosCtrl

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
    olt_conf_file = os.path.join(test_path, '..', 'setup/olt_config.json')
    restApiXos =  None
    subscriber_account_num = 200
    subscriber_s_tag = 304
    subscriber_c_tag = 304
    subscribers_per_s_tag = 8
    subscriber_map = {}
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
    def setUpClass(cls):
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
    def tearDownClass(cls):
        VSGAccess.tearDown()
        if cls.on_pod is True:
            cls.closeVCPEAccess(cls.volt_subscriber_info)

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
            vcpe = self.vcpe_dhcp
        st, _ = getstatusoutput('dhclient {}'.format(vcpe))
	vcpe_ip = get_ip(vcpe)
	return vcpe_ip

    def release_vcpe_interface_dhcp_ip(self,vcpe=None):
        if not vcpe:
            vcpe = self.vcpe_dhcp
        st, _ = getstatusoutput('dhclient {} -r'.format(vcpe))
        vcpe_ip = get_ip(vcpe)
        assert_equal(vcpe_ip, None)

    def add_static_route_via_vcpe_interface(self, routes, vcpe=None,dhcp_ip=True):
	if not vcpe:
	    vcpe = self.vcpe_dhcp
	if dhcp_ip:
	    os.system('dhclient '+vcpe)
	time.sleep(1)
	for route in routes:
	    log.info('route is %s'%route)
	    cmd = 'ip route add ' + route + ' via 192.168.0.1 '+ 'dev ' + vcpe
	    cmds.append(cmd)
	for cmd in cmds:
	    os.system(cmd)
	return True

    def del_static_route_via_vcpe_interface(self,routes,vcpe=None,dhcp_release=True):
        if not vcpe:
            vcpe = self.vcpe_dhcp
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

    def test_vsg_health_check(self, vsg_name='mysite_vsg-1', verify_status=True):
        """
        Test Method:
	1. If vsg name not specified, Get vsg corresponding to vcpe
        1. Login to compute mode VM
        3. Ping to the vSG
        4. Verifying Ping success
        """
        if self.on_pod is False:
            return
        if not vsg_name:
            vcpe = self.vcpe_container
            vsg = VSGAccess.get_vcpe_vsg(vcpe)
            status = vsg.get_health()
            assert_equal(status, verify_status)
        else:
            vsgs = VSGAccess.get_vsgs()
            status = None
            for vsg in vsgs:
                if vsg.name == vsg_name:
                    status = vsg.get_health()
                    log.info('vsg health check status is %s'%status)
                    assert_equal(status,verify_status)

    @deferred(TIMEOUT)
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

    def test_vsg_for_external_connectivity_through_testclient(self):
        """
        Test Method:
        1. Login to head node
        2. On head node, executing ping to 8.8.8.8 from lxc test client
	3. Verifying for the ping success
        """
        if self.on_pod is False:
            return
        ssh_agent = SSHTestAgent(host = self.HEAD_NODE, user = self.USER, password = self.PASS)
        cmd = "lxc exec testclient -- ping -c 3 8.8.8.8"
        status, output = ssh_agent.run_cmd(cmd)
        assert_equal( status, True)

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
        self.vsg_for_external_connectivity(0, reserved = reserved)

    def test_vsg_for_external_connectivity_to_google(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to www.google.com and Verifying ping should success
        4. Restoring management interface configuration in  cord-tester
        """
        host = 'www.google.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_equal(st, 0)

    def retrieve_content_from_host_to_validate_path_mtu(self, host):
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Initiating get requests to %s' %host)
        r = requests.get('http://{}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        return r.status_code

    #Test cases to check path mtu across cord framework wih some selected websites to check response.
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
        status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.google.com')
        assert_equal(status_code, 200)

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
        status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.rediff.com')
        assert_equal(status_code, 200)

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
        status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.yahoo.com')
        assert_equal(status_code, 200)

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
        status_code = self.retrieve_content_from_host_to_validate_path_mtu('www.facebook.com')
        assert_equal(status_code, 200)

    def test_vsg_for_external_connectivity_to_invalid_host(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to www.goglee.com and Verifying ping should not success
        4. Restoring management interface configuration in  cord-tester
        """
        host = 'www.goglee.com'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to non existent host %s' %host)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

    def test_vsg_for_external_connectivity_with_ttl_1(self):
        """
        Test Method:
        1. Get dhcp IP to vcpe interface in cord-tester
        2. Verifying vcpe interface gets dhcp IP
        3. Ping to 8.8.8.8 with ttl set to 1
	4. Verifying ping should not success
        5. Restoring management interface configuration in  cord-tester
        """
        host = '8.8.8.8'
        vcpe = self.vcpe_dhcp
        mgmt = 'eth0'
        assert_not_equal(vcpe, None)
        vcpe_ip = VSGAccess.vcpe_get_dhcp(vcpe, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, vcpe))
        log.info('Sending icmp ping requests to host %s with ttl 1' %host)
        st, _ = getstatusoutput('ping -c 1 -t 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = vcpe)
        assert_not_equal(st, 0)

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
        if self.on_pod is False:
            return
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = VSGAccess.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
	if st != 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the wan interface and check again
        st = VSGAccess.vcpe_wan_down(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = VSGAccess.vcpe_wan_up(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

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
        host = '8.8.8.8'
        mgmt = 'eth0'
        vcpe = self.vcpe_container
        assert_not_equal(vcpe, None)
        assert_not_equal(self.vcpe_dhcp, None)
        #first get dhcp on the vcpe interface
        vcpe_ip = VSGAccess.vcpe_get_dhcp(self.vcpe_dhcp, mgmt = mgmt)
        assert_not_equal(vcpe_ip, None)
        log.info('Got DHCP IP %s for %s' %(vcpe_ip, self.vcpe_dhcp))
        log.info('Sending ICMP pings to host %s' %(host))
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st != 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)
        #bring down the lan interface and check again
        st = VSGAccess.vcpe_lan_down(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        if st == 0:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_not_equal(st, 0)
        st = VSGAccess.vcpe_lan_up(vcpe)
        if st is False:
            VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, True)
        st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        VSGAccess.restore_interface_config(mgmt, vcpe = self.vcpe_dhcp)
        assert_equal(st, 0)

    def test_vsg_multiple_subscribers_for_same_vcpe_instace(self):
	"""
	Test Method:
	1. Create a vcpe instance
	2. Create multiple vcpe interfaces in cord-tester with same s-tag and c-tag to access vcpe instance
	3. Verify all the interfaces gets dhcp IP in same subnet
	"""
        vcpe_intfs,containers = self.get_vcpe_containers_and_interfaces()
        for vcpe in vcpe_intfs:
            vcpe_ip = self.get_vcpe_interface_dhcp_ip(vcpe=vcpe)
            assert_not_equal(vcpe_ip,None)
        for vcpe in vcpe_intfs:
            self.release_vcpe_interface_dhcp_ip(vcpe=vcpe)

    def test_vsg_for_multiple_subscribers_with_same_vcpe_instance_and_validate_external_connectivity(self):
        """
        Test Method:
        1. Create a vcpe instance
        2. Create multiple vcpe interfaces in cord-tester with same s-tag and c-tag to access vcpe instance
        3. Verify all the interfaces gets dhcp IP in same subnet
	4. From cord-tester ping to external  with vcpe interface option
        """
        host = '8.8.8.8'
        vcpe_intfs, containers = self.get_vcpe_containers_and_interfaces()
        for vcpe in vcpe_intfs:
            vcpe_ip = self.get_vcpe_interface_dhcp_ip(vcpe=vcpe)
            assert_not_equal(vcpe_ip,None)
            self.add_static_route_via_vcpe_interface([host],vcpe=vcpe,dhcp_ip=False)
            st, _ = getstatusoutput('ping -I {} -c 3 {}'.format(vcpe,host))
            assert_equal(st, 0)
            self.del_static_route_via_vcpe_interface([host],vcpe=vcpe,dhcp_release=False)
        for vcpe in vcpe_intfs:
            self.release_vcpe_interface_dhcp_ip(vcpe=vcpe)

    def test_vsg_vcpe_interface_and_validate_dhcp_ip_after_interface_toggle(self):
        """
        Test Method:
        1. Create a vcpe instance
        2. Create a vcpe interface in cord-tester
        3. Verify the interface gets dhcp IP
	4. Toggle the interface
	5. Verify the interface gets dhcp IP
        """
        vcpe_intfs,containers = self.get_vcpe_containers_and_interfaces()
        for vcpe in vcpe_intfs:
            vcpe_ip = self.get_vcpe_interface_dhcp_ip(vcpe=vcpe)
            assert_not_equal(vcpe_ip,None)
            os.system('ifconfig {} down'.format(vcpe))
            time.sleep(1)
            os.system('ifconfig {} up'.format(vcpe))
            time.sleep(1)
            vcpe_ip2 = get_ip(vcpe)
            assert_equal(vcpe_ip2,vcpe_ip)
        for vcpe in vcpe_intfs:
            self.release_vcpe_interface_dhcp_ip(vcpe=vcpe)

    @deferred(TIMEOUT)
    def test_vsg_for_external_connectivity_after_restarting_vcpe_instance(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
                st, _ = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_for_external_connectivity_after_restarting_vsg_vm(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
                st, _ = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_for_external_connectivity_with_vcpe_container_paused(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
                st, _ = vsg.run_cmd('sudo docker pause {}'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker unpause'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_with_deny_destination_ip(self, vcpe_name=None, vcpe_intf=None):
	"""
	Test Method:
	1. Get vSG corresponding to vcpe
	2. Login to compute node
	3. Execute iptable command on vcpe from compute node to deny a destination IP
	4. From cord-tester ping to the denied IP address
	5. Verifying that ping should not be successful
	"""
	if not vcpe_name:
		vcpe_name = self.vcpe_container
	if not vcpe_intf:
		vcpe_intf = self.vcpe_dhcp
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
	reactor.callLater(0, vcpe_firewall, df)
	return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_with_rule_add_and_delete_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
	        self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_verifying_reachability_for_non_blocked_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_appending_rules_with_deny_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
		st,_ = vsg.run_cmd('sudo docker exec {} iptables -F FORWARD'.format(vcpe_name))
		time.sleep(2)
                st,_ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, out = getstatusoutput('ping -c 1 {}'.format(host2))
		log.info('host2 ping output is %s'%out)
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -A FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,True)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_removing_one_rule_denying_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
	def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host1 = '8.8.8.8'
            host2 = '204.79.197.203'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
                self.add_static_route_via_vcpe_interface([host1,host2],vcpe=self.vcpe_dhcp)
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host1))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host2))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
		log.info('restarting vcpe container')
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_changing_rule_id_deny_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
            	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD 2 -d {} -j DROP '.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,True)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_changing_deny_rule_to_accept_dest_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
	    vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -d {} -j ACCEPT'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j ACCEPT'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT) #Fail
    def test_vsg_firewall_denying_destination_network(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
	        self.add_static_route_via_vcpe_interface([host1,host2],vcpe=self.vcpe_dhcp)
		st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,network))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host1))
                assert_equal(st, True)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host2))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network))
                self.del_static_route_via_vcpe_interface([host1,host2],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_denying_destination_network_subnet_modification(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
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
		self.add_static_route_via_vcpe_interface([host1,host2,host3],vcpe=self.vcpe_dhcp)
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network1))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,network2))
                self.del_static_route_via_vcpe_interface([host1,host2,host3],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_with_deny_source_ip(self,vcpe_name=None,vcpe_intf=None):
        """
        Test Method:
        1. Get vSG corresponding to vcpe
        2. Login to compute node
        3. Execute iptable command on vcpe from compute node to deny a source IP
        4. From cord-tester ping to 8.8.8.8 from the denied IP
        5. Verifying that ping should not be successful
        """
        if not vcpe_name:
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            #source_ip = get_ip(self.vcpe_dhcp)
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
		source_ip = get_ip(self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_rule_with_add_and_delete_deny_source_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            source_ip = get_ip(self.vcpe_dhcp)
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
	        self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
		source_ip = get_ip(self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
	        st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -s {} -j DROP'.format(vcpe_name,source_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_requests_type(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
		st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_rule_with_deny_icmp_protocol_echo_reply_type(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format('8.8.8.8'))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD  -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -p icmp --icmp-type echo-request -j ACCEPT'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j DROP'.format(vcpe_name))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-request -j ACCEPT'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_reply_type(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	        assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD  -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -p icmp --icmp-type echo-reply -j ACCEPT'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j DROP'.format(vcpe_name))
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp --icmp-type echo-reply -j ACCEPT'.format(vcpe_name))
		self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_for_deny_icmp_protocol(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st,False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
		vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_rule_deny_icmp_protocol_and_destination_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
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
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {}  -j DROP'.format(vcpe_name,host))
		vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p icmp -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT) #Fail
    def test_vsg_firewall_flushing_all_configured_rules(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe_name,host))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p icmp -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -F FORWARD'.format(vcpe_name))
		time.sleep(1)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_ipv4_traffic(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_replacing_deny_rule_to_accept_rule_ipv4_traffic(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
       	 	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -4 -j ACCEPT'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_traffic_coming_on_lan_interface_in_vcpe(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -i eth1 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_traffic_going_out_of_wan_interface_in_vcpe(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD  -o eth0 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_traffic_from_lan_to_wan_in_vcpe(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
	    host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -i eth1 -o eth0 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    #this test case needs modification.default route should be vcpe interface to run this test case
    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_dns_traffic(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = 'www.msn.com'
	    host_ip = '131.253.33.203'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
	    try:
		self.add_static_route_via_vcpe_interface([host_ip],vcpe=self.vcpe_dhcp)
        	st, _ = getstatusoutput('ping -c 1 {}'.format(host))
        	assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -p udp --dport 53 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -R FORWARD 1 -p udp --dport 53 -j ACCEPT'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -p udp --dport 53 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host_ip],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_firewall_deny_all_ipv4_traffic_vcpe_container_restart(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            if self.on_pod is False:
                df.callback(0)
                return
            host = '8.8.8.8'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -4 -j DROP'.format(vcpe_name))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
		time.sleep(3)
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -4 -j DROP'.format(vcpe_name))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0, vcpe_firewall, df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_dnat_modifying_destination_ip(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
	    dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_dnat_modifying_destination_ip_and_delete(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
            dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
		st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    @deferred(TIMEOUT)
    def test_vsg_dnat_change_modifying_destination_ip_address(self,vcpe_name=None,vcpe_intf=None):
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
                vcpe_name = self.vcpe_container
        if not vcpe_intf:
                vcpe_intf = self.vcpe_dhcp
        df = defer.Deferred()
        def vcpe_firewall(df):
            host = '8.8.8.8'
            dst_ip = '123.123.123.123'
            vsg = VSGAccess.get_vcpe_vsg(vcpe_name)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=self.vcpe_dhcp)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -A PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                st,_ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,output = vsg.run_cmd('sudo docker exec {} iptables -t nat -R PREROUTING 1  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,dst_ip))
                vsg.run_cmd('sudo docker exec {} iptables -t nat -D PREROUTING  -s 192.168.0.0/16 -i eth1 -j DNAT --to-destination {}'.format(vcpe_name,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe_name))
            df.callback(0)
        reactor.callLater(0,vcpe_firewall,df)
        return df

    def vsg_xos_subscriber_create(self, index):
        if self.on_pod is False:
            return
        subscriber_info = self.subscriber_info[index]
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
            log.info('Subscriber ID for account num %d = %s' %(volt_subscriber_info['account_num'], subId))
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

    def vsg_xos_subscriber_delete(self, index, subId = ''):
        if self.on_pod is False:
            return
        subscriber_info = self.subscriber_info[index]
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
        #get the volt id for the subscriber
        result = self.restApiXos.ApiGet('TENANT_VOLT')
        assert_not_equal(result, None)
        voltId = self.getVoltId(result, subId)
        assert_not_equal(voltId, None)
        log.info('Deleting subscriber ID %s for account num %d' %(subId, volt_subscriber_info['account_num']))
        status = self.restApiXos.ApiDelete('TENANT_SUBSCRIBER', subId)
        assert_equal(status, True)
        #Delete the tenant
        log.info('Deleting VOLT Tenant ID %s for subscriber %s' %(voltId, subId))
        self.restApiXos.ApiDelete('TENANT_VOLT', voltId)

    def vsg_xos_subscriber_id(self, index):
        volt_subscriber_info = self.volt_subscriber_info[index]
        result = self.restApiXos.ApiGet('TENANT_SUBSCRIBER')
        assert_not_equal(result, None)
        subId = self.restApiXos.getSubscriberId(result, volt_subscriber_info['account_num'])
        return subId

    def test_vsg_xos_subscriber_create_all(self):
        for index in xrange(len(self.subscriber_info)):
            #check if the index exists
            subId = self.vsg_xos_subscriber_id(index)
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)
            subId = self.vsg_xos_subscriber_create(index)
            log.info('Created Subscriber %s' %(subId))

    def test_vsg_xos_subscriber_delete_all(self):
        for index in xrange(len(self.subscriber_info)):
            subId = self.vsg_xos_subscriber_id(index)
            if subId and subId != '0':
                self.vsg_xos_subscriber_delete(index, subId = subId)

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

    def test_vsg_without_creating_vcpe_instance(self, index=0):
	vcpe = self.dhcp_vcpes[index]
	host = '8.8.8.8'
	st, _ = getstatusoutput('dhclient {}'.format(vcpe))
	assert_equal(st,True)
        subId = self.vsg_xos_subscriber_create(index)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(index, subId)

    def test_vsg_for_remove_vcpe_instance(self,index=0):
        subId = self.vsg_xos_subscriber_create(index)
        if subId and subId != '0':
            self.vsg_xos_subscriber_delete(index, subId)
            vcpe = self.dhcp_vcpes[index]
            host = '8.8.8.8'
            st, _ = getstatusoutput('dhclient {}'.format(vcpe))
            assert_equal(st,True)

    def test_vsg_create_xos_subscribers_in_different_vsg_vm(self):
        subId1 = self.vsg_xos_subscriber_create(4)
	subId2 = self.vsg_xos_subscriber_create(6)
        if subId1 and subId1 != '0':
            self.vsg_xos_subscriber_delete(4, subId1)
        if subId2 and subId2 != '0':
            self.vsg_xos_subscriber_delete(6, subId2)

    def test_vsg_external_connectivity_from_two_subscribers_if_one_vsg_goes_down(self):
        subId1 = self.vsg_xos_subscriber_create(4)
        subId2 = self.vsg_xos_subscriber_create(6)
        if subId1 and subId1 != '0':
            self.vsg_xos_subscriber_delete(4, subId1)
        if subId2 and subId2 != '0':
            self.vsg_xos_subscriber_delete(6, subId2)

    def test_vsg_with_xos_subscriber_creating_firewall(self,index=4):
        log.info('cls.dhcp_vcpes is %s'%self.dhcp_vcpes)
        host = '8.8.8.8'
        self.vsg_xos_subscriber_delete(4, 3)
        subId = self.vsg_xos_subscriber_create(index)
        if subId and subId != '0':
            subscriber_info = self.subscriber_info[index]
            volt_subscriber_info = self.volt_subscriber_info[index]
            s_tag = int(volt_subscriber_info['voltTenant']['s_tag'])
            c_tag = int(volt_subscriber_info['voltTenant']['c_tag'])
            vcpe = 'vcpe-{}-{}'.format(s_tag, c_tag)
            vcpe_intf = self.dhcp_vcpes[index] #'vcpe{}.{}.{}'.format(s_tag, c_tag)
            vsg = VSGAccess.get_vcpe_vsg(vcpe)
            try:
                self.add_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
                st, _ = vsg.run_cmd('sudo docker exec {} iptables -I FORWARD -d {} -j DROP'.format(vcpe,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, True)
                st,_ = vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe,host))
                st, _ = getstatusoutput('ping -c 1 {}'.format(host))
                assert_equal(st, False)
            finally:
                vsg.run_cmd('sudo docker exec {} iptables -D FORWARD -d {} -j DROP'.format(vcpe,host))
                self.del_static_route_via_vcpe_interface([host],vcpe=vcpe_intf)
                vsg.run_cmd('sudo docker restart {}'.format(vcpe))
            self.vsg_xos_subscriber_delete(4, subId)
        self.vsg_xos_subscriber_delete(4, subId)


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

    def test_subscriber_access_if_vsg1_goes_down(self):
	"""
	# Intention is to verify if subscriber can reach internet via vSG2 if vSG1 goes down
        Test Method:
        1.Create two vSG VMs for two services in compute node
        2.Create one vCPE container in each VM for one subscriber
        3.Ensure VMs and containers created properly
        4.From subscriber end, send ping to public IP with stag corresponds to vSG-1 VM and ctag
        5.Verify ping gets success
        6.Verify ping success flows in OvS
	7.Down the vSG-1 VM
        8.Now repeat step 4
	9.Verify that ping fails as vSG-1 is down
        10.Repeat step 4 with stag corresponding to vSG-2
        9.Verify ping success and flows added in OvS
        """

    def test_subscriber_access_if_vsg2_goes_down(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 restarts
        Test Method:
        1.Create two vSG VMs for two services in compute node
        2.Create one vCPE container in each VM for one subscriber
        3.Ensure VMs and containers created properly
        4.From subscriber end, send ping to public IP with stag corresponds to vSG-1 VM and ctag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now restart vSG-1 VM
        8.Now repeat step 4 while vSG-1 VM restarts
        9.Verify that ping fails as vSG-1 is restarting
        10.Repeat step 4 with stag corresponding to vSG-2 while vSG-1 VM restarts
        11.Verify ping success and flows added in OvS
        """

    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_going_down(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 goes down
        Test Method:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now stop vCPE-1 container
        8.Now repeat step 4
        9.Verify that ping fails as vCPE-1 container is down
        10.Repeat step 4 with ctag corresponding to vCPE-2 container
        11.Verify ping success and flows added in OvS
        """

    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_restart(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 restarts
        Test Method:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now restart vCPE-1 container
        8.Now repeat step 4 while vCPE-1 restarts
        9.Verify that ping fails as vCPE-1 container is restarts
        10.Repeat step 4 with ctag corresponding to vCPE-2 container while vCPE-1 restarts
        11..Verify ping success and flows added in OvS
        """

    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_paused(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 paused
        Test Method:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now pause vCPE-1 container
        8.Now repeat step 4 while vCPE-1 in pause state
        9.Verify that ping fails as vCPE-1 container in pause state
        10.Repeat step 4 with ctag corresponding to vCPE-2 container while vCPE-1 in pause state
        11.Verify ping success and flows added in OvS
        """
    def test_vsg_for_multiple_vcpes_in_vsg_vm_with_one_vcpe_removed(self):
        """
        # Intention is to verify if subscriber can reach internet via vSG2 if vSG1 removed
        Test Method:
        1.Create a vSG VM in compute node
        2.Create two vCPE containers corresponds to two subscribers in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber-1 end, send ping to public IP with ctag corresponds to vCPE-1 and stag
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vCPE-1 container
        8.Now repeat step 4
        9.Verify that ping fails as vCPE-1 container removed
        10.Repeat step 4 with ctag corresponding to vCPE-2 container
        11.Verify ping success and flows added in OvS
        """

    def test_vsg_for_vcpe_instance_removed_and_added_again(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber end, send ping to public IP
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vCPE container in vSG VM
        8.Now repeat step 4
        9.Verify that ping fails as vCPE container removed
	10.Create the vCPE container again for the same subscriber
	11.Ensure that vCPE created now
        12.Now repeat step 4
        13.Verify ping success and flows added in OvS
        """

    def test_vsg_for_vsg_vm_removed_and_added_again(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.From subscriber end, send ping to public IP
        5.Verify ping gets success
        6.Verify ping success flows added in OvS
        7.Now remove vSG VM
        8.Now repeat step 4
        9.Verify that ping fails as vSG VM not exists
        10.Create the vSG VM and vCPE  container in VM again
        11.Ensure that vSG and vCPE created
        12.Now repeat step 4
        13.Verify ping success and flows added in OvS
        """

    #Test vSG - Subscriber Configuration
    def test_vsg_for_configuring_new_subscriber_in_vcpe(self):
	"""
	Test Method:
	1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
	4.Configure a subscriber in XOS and assign a service id
	5.Set the admin privileges to the subscriber
	6.Verify subscriber configuration is success
	"""
    def test_vsg_for_adding_subscriber_devices_in_vcpe(self):
	"""
	Test Method:
	1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
	5.Verify subscriber successfully configured in vCPE
	6.Now add devices( Mac addresses ) under the subscriber admin group
	7.Verify all devices ( Macs ) added successfully
	"""
    def test_vsg_for_removing_subscriber_devices_in_vcpe(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
	8.Now remove All the added devices in XOS
	9.Verify all the devices removed
        """
    def test_vsg_modifying_subscriber_devices_in_vcpe(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a user in XOS and assign a service id
        5.Verify subscriber successfully configured in vCPE.
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
        8.Now remove few devices in XOS
        9.Verify devices removed successfully
	10.Now add few additional devices in XOS  under the same subscriber admin group
	11.Verify newly added devices successfully added
        """
    def test_vsg_for_vcpe_login_failing_with_incorrect_subscriber_credentials(self):
	"""
	Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
	8.Login vCPE with credentials with which subscriber configured
	9.Verify subscriber successfully logged in
	10.Logout and login again with incorrect credentials ( either user name or password )
	11.Verify login attempt to vCPE fails wtih incorrect credentials
	"""
    def test_vsg_for_subscriber_configuration_in_vcpe_after_vcpe_restart(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create a vCPE container in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS  and assign a service id
        5.Verify subscriber successfully configured
        6.Now add devices( Mac addresses ) under the subscriber admin group
        7.Verify all devices ( Macs ) added successfully
        8.Restart vCPE ( locate backup config path while restart )
        9.Verify subscriber details in vCPE after restart should be same as before the restart
        """
    def test_vsg_creating_multiple_vcpe_instances_and_configuring_subscriber_in_each_instance(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create 2 vCPE containers in vSG VM
        3.Ensure VM and containers created properly
        4.Configure a subscriber in XOS for each vCPE instance and assign a service id
        5.Verify subscribers successfully configured
	6.Now login vCPE-2 with subscriber-1 credentials
	7.Verify login fails
	8.Now login vCPE-1 with subscriber-2 credentials
	9.Verify login fails
	10.Now login vCPE-1 with subscriber-1 and vCPE-2 with  subscriber-2 credentials
	11.Verify that both the subscribers able to login to their respective vCPE containers
	"""
    def test_vsg_for_same_subscriber_configuring_multiple_services(self):
        """
        Test Method:
        1.Create 2 vSG VMs in compute node
        2.Create a vCPE container in each vSG VM
        3.Ensure VMs and containers created properly
        4.Configure same subscriber in XOS for each vCPE instance and assign a service id
        5.Verify subscriber successfully configured
        6.Now login vCPE-1 with subscriber credentials
        7.Verify login success
        8.Now login vCPE-2 with the same subscriber credentials
        9.Verify login success
        """
    #vCPE Firewall Functionality
    def test_vsg_firewall_for_creating_acl_rule_based_on_source_ip(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic from a source IP
        5.Bound the acl rule to WAN interface of  vCPE
        6.Verify configuration in vCPE is success
        8.Verify flows added in OvS
        """
    def test_vsg_firewall_for_creating_acl_rule_based_on_destination_ip(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic to a destination ip
        5.Bound the acl rule to WAN interface of  vCPE
        6.Verify configuration in vCPE is success
        8.Verify flows added in OvS
        """
    def test_vsg_firewall_for_acl_deny_rule_based_on_source_ip_traffic(self):
	"""
	Test Method:
	1.Create a vSG VM in compute node
	2.Create vCPE container in the VM
	3.Ensure vSG VM and vCPE container created properly
	4.Configure ac acl rule in vCPE to deny IP traffic from a source IP
	5.Bound the acl rule to WAN interface of  vCPE
	6.From subscriber, send ping to the denied IP address
	7.Verify that ping fails as vCPE denies ping response
	8.Verify flows added in OvS
	"""
    def test_vsg_firewall_for_acl_deny_rule_based_on_destination_ip_traffic(self):
        """
        Test Method:
        1.Create a vSG VM in compute node
        2.Create vCPE container in the VM
        3.Ensure vSG VM and vCPE container created properly
        4.Configure ac acl rule in vCPE to deny IP traffic to a destination IP
        5.Bound the acl rule to WAN interface of  vCPE
        6.From subscriber, send ping to the denied IP address
        7.Verify that ping fails as vCPE drops the ping request at WAN interface
        8.Verify flows added in OvS
        """

    def test_vsg_dnsmasq(self):
        pass

    def test_vsg_with_external_parental_control_family_shield_for_filter(self):
        pass

    def test_vsg_with_external_parental_control_with_answerx(self):
        pass

    def test_vsg_for_subscriber_upstream_bandwidth(self):
        pass

    def test_vsg_for_subscriber_downstream_bandwidth(self):
        pass

    def test_vsg_for_diagnostic_run_of_traceroute(self):
        pass

    def test_vsg_for_diagnostic_run_of_tcpdump(self):
        pass

    def test_vsg_for_iptable_rules(self):
        pass

    def test_vsg_for_iptables_with_neutron(self):
        pass
