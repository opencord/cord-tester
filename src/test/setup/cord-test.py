#!/usr/bin/env python
# Copyright 2017-present Open Networking Foundation
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
from argparse import ArgumentParser
import os,sys,time,socket,errno
import shutil, platform, re
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
cli_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../cli')
sys.path.append(utils_dir)
sys.path.append(cli_dir)
sys.path.insert(1, '/usr/local/lib/python2.7/dist-packages')
from CordTestUtils import get_mac
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from OnosFlowCtrl import OnosFlowCtrl
from threadPool import ThreadPool
from CordContainer import *
from CordTestServer import cord_test_server_start,cord_test_server_stop,cord_test_server_shutdown,CORD_TEST_HOST,CORD_TEST_PORT
from TestManifest import TestManifest
from VolthaCtrl import VolthaService
try:
    from docker import APIClient as Client
except:
    from docker import Client
from docker.utils import kwargs_from_env
from Xos import XosServiceProfile
try:
    from Fabric import FabricMAAS
except:
    FabricMAAS = None

class CordTester(Container):
    sandbox = '/root/test'
    sandbox_setup = '/root/test/src/test/setup'
    tester_base = os.path.dirname(os.path.realpath(__file__))
    tester_paths = os.path.realpath(__file__).split(os.path.sep)
    tester_path_index = tester_paths.index('src') - 1
    sandbox_host = os.path.sep.join(tester_paths[:tester_path_index+1])

    host_guest_map = ( (sandbox_host, sandbox),
                       ('/lib/modules', '/lib/modules'),
                       ('/var/run/docker.sock', '/var/run/docker.sock')
                       )
    basename = 'cord-tester'
    switch_on_olt = False
    IMAGE = 'cordtest/nose'
    ALL_TESTS = ('tls', 'dhcp', 'dhcprelay','igmp', 'subscriber',
    'cordSubscriber', 'vrouter', 'flows', 'proxyarp', 'acl', 'xos', 'fabric',
    'cbench', 'cluster', 'netCondition', 'cordvtn', 'iperf', 'mini', 'vsg')

    def __init__(self, tests, instance = 0, num_instances = 1, ctlr_ip = None,
                 name = '', image = IMAGE, prefix = '', tag = 'candidate',
                 env = None, rm = False, update = False, network = None):
        self.tests = tests
        self.ctlr_ip = ctlr_ip
        self.rm = rm
        self.name = name or self.get_name(num_instances)
        super(CordTester, self).__init__(self.name, image = image, prefix = prefix, tag = tag)
        host_config = self.create_host_config(host_guest_map = self.host_guest_map, privileged = True)
        volumes = []
        for _, g in self.host_guest_map:
            volumes.append(g)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
        self.create = True
        #check if are trying to run tests on existing container
        if not self.exists():
            ##Remove test container if any
            self.remove_container(self.name, force=True)
        else:
            self.create = False
            self.rm = False
        self.olt = False
        self.switch_started = False
        olt_config_file = 'olt_config.json'
        if env is not None:
            if env.has_key('OLT_CONFIG'):
                self.olt = True
            if env.has_key('OLT_CONFIG_FILE'):
                olt_config_file = os.path.basename(env['OLT_CONFIG_FILE'])
        olt_conf_file = os.path.join(self.tester_base, olt_config_file)
        olt_config = OltConfig(olt_conf_file)
        self.port_map, _ = olt_config.olt_port_map()
        self.vcpes = olt_config.get_vcpes()
        #Try using the host interface in olt conf to setup the switch
        self.switches = self.port_map['switches']
        voltha_network = VolthaService.get_network('voltha')
        voltha_rest_ip = VolthaService.get_ip('chameleon')
        if env is not None:
            env['TEST_SWITCH'] = self.switches[0]
            env['TEST_SWITCHES'] = ','.join(self.switches)
            env['TEST_HOST'] = self.name
            env['TEST_INSTANCE'] = instance
            env['TEST_INSTANCES'] = num_instances
            if voltha_rest_ip:
                env['VOLTHA_HOST'] = voltha_rest_ip
        if self.create:
            print('Starting test container %s, image %s, tag %s' %(self.name, self.image, self.tag))
            self.start(rm = False, volumes = volumes, environment = env,
                       host_config = host_config, tty = True)
            if network is not None:
                Container.connect_to_network(self.name, network)
            if voltha_network:
                print('Connecting container to VOLTHA container network %s' %(voltha_network))
                Container.connect_to_network(self.name, voltha_network)

    def execute_switch(self, cmd, shell = False):
        if self.olt:
            return os.system(cmd)
        return self.execute(cmd, shell = shell)

    def test_flow(self, switch):
        if not self.olt:
            return False
        egress = 1
        ingress = 2
        egress_map = { 'ether': '00:00:00:00:00:03', 'ip': '192.168.30.1' }
        ingress_map = { 'ether': '00:00:00:00:00:04', 'ip': '192.168.40.1' }
        device_id = 'of:{}'.format(get_mac(switch))
        ctlr = self.ctlr_ip.split(',')[0]
        flow = OnosFlowCtrl(deviceId = device_id,
                            egressPort = egress,
                            ingressPort = ingress,
                            ethType = '0x800',
                            ipSrc = ('IPV4_SRC', ingress_map['ip']+'/32'),
                            ipDst = ('IPV4_DST', egress_map['ip']+'/32'),
                            controller = ctlr
                            )
        result = flow.addFlow()
        if result != True:
            return result
        time.sleep(1)
        #find and remove the flow
        flow_id = flow.findFlow(device_id, IN_PORT = ('port', ingress),
                                ETH_TYPE = ('ethType','0x800'), IPV4_SRC = ('ip', ingress_map['ip']+'/32'),
                                IPV4_DST = ('ip', egress_map['ip']+'/32'))
        result = False
        if flow_id:
            result = True
            flow.removeFlow(device_id, flow_id)
        return result

    def ctlr_switch_availability(self, switch):
        '''Test Add and verify flows with IPv4 selectors'''
        if not self.olt:
            return False
        device_id = 'of:{}'.format(get_mac(switch))
        ctlr = self.ctlr_ip.split(',')[0]
        devices = OnosCtrl.get_devices(controller = ctlr)
        if devices:
            device = filter(lambda d: d['id'] == device_id, devices)
            if device:
                return True
        return False

    def start_switch(self, manifest, boot_delay = 2):
        """Start OVS"""
        ##Determine if OVS has to be started locally or not
        s_file,s_sandbox = ('of-bridge-local.sh',self.tester_base) if self.olt else ('of-bridge.sh',self.sandbox_setup)
        ovs_cmd = os.path.join(s_sandbox, s_file)
        switches = filter(lambda sw: sw.startswith('br-int'), self.switches)
        if self.olt:
            if CordTester.switch_on_olt is True:
                return
            CordTester.switch_on_olt = True
            ovs_cmd += ' {} {}'.format(len(switches), self.ctlr_ip)
            if manifest.voltha_enable and manifest.voltha_loc and Onos.ssl_key:
                ovs_cmd += ' {}'.format(manifest.voltha_loc)
            print('Starting OVS on the host with %d switches for controller: %s' %(len(switches), self.ctlr_ip))
        else:
            ovs_cmd += ' {}'.format(self.switches[0])
            print('Starting OVS on test container %s for controller: %s' %(self.name, self.ctlr_ip))
        self.execute_switch(ovs_cmd)
        time.sleep(5)
        ## Wait for the controller to see the switch
        for switch in switches:
            status = 1
            tries = 0
            result = self.ctlr_switch_availability(switch) and self.test_flow(switch)
            if result == True:
                status = 0
            while status != 0 and tries < 500:
                cmd = 'sudo ovs-ofctl dump-flows {0} | grep \"type=0x8942\"'.format(switch)
                status = self.execute_switch(cmd, shell = True)
                tries += 1
                if status != 0 and tries > 100:
                    if self.ctlr_switch_availability(switch):
                        status = 0
                if tries % 10 == 0:
                    print('Waiting for test switch %s to be connected to ONOS controller ...' %switch)

            if status != 0:
                print('Test Switch %s not connected to ONOS container.'
                      'Please remove ONOS container and restart the test' %switch)
                if self.rm:
                    self.kill()
                sys.exit(1)
            else:
                print('Test Switch %s connected to ONOS container.' %switch)

        if boot_delay:
            time.sleep(boot_delay)

        self.switch_started = True

    def setup_vcpes(self, port_num = 0):
        res = 0
        for vcpe in self.vcpes:
            port, s_tag, c_tag = vcpe['port'], vcpe['s_tag'], vcpe['c_tag']
            if os.access('/sys/class/net/{}'.format(port), os.F_OK):
                guest_port = 'vcpe{}'.format(port_num)
                port_num += 1
                print('Provisioning guest port %s for %s with host port: %s, s_tag: %d, c_tag: %d\n'
                      %(guest_port, self.name, port, s_tag, c_tag))
                cmd = 'pipework {} -i {} -l {} {} 0.0.0.0/24'.format(port, guest_port, guest_port, self.name)
                res = os.system(cmd)
                if res == 0:
                    vlan_outer_port = '{}.{}'.format(guest_port, s_tag)
                    vlan_inner_port = '{}.{}'.format(vlan_outer_port, c_tag)
                    #configure the s_tag/c_tag interfaces inside the guest container
                    cmds = ('ip link set {} up'.format(guest_port),
                            'ip link add link {} name {} type vlan id {}'.format(guest_port,
                                                                                 vlan_outer_port,
                                                                                 s_tag),
                            'ip link set {} up'.format(vlan_outer_port),
                            'ip link add link {} name {} type vlan id {}'.format(vlan_outer_port,
                                                                                 vlan_inner_port,
                                                                                 c_tag),
                            'ip link set {} up'.format(vlan_inner_port),
                            )
                    res += self.execute(cmds, shell = True)

    @classmethod
    def cleanup_vcpes(cls, vcpes):
        port_num = 0
        for vcpe in vcpes:
            port = vcpe['port']
            if os.access('/sys/class/net/{}'.format(port), os.F_OK):
                local_port = 'vcpe{}'.format(port_num)
                cmd = 'ip link del {}'.format(local_port)
                os.system(cmd)
                port_num += 1

    def setup_intfs(self, port_num = 0):
        tester_intf_subnet = '192.168.100'
        res = 0
        switches = self.port_map['switches']
        start_vlan = self.port_map['start_vlan']
        ponsim = self.port_map['ponsim']
        start_vlan += port_num
        uplink = self.port_map['uplink']
        wan = self.port_map['wan']
        if ponsim is True:
            if not wan:
                wan = 'ponmgmt'
        vcpe_port_num = port_num
        port_list = self.port_map['switch_port_list'] + self.port_map['switch_relay_port_list']
        print('Provisioning the ports for the test container\n')
        for host_intf, ports in port_list:
            if self.switch_started is False and host_intf.startswith('br-int'):
                continue
            setup_ponsim = ponsim
            host_index = 0
            host_intf_base = 'pon1'
            #if the host interface/switch does not exist, just create a dummy ovs switch
            #needed if we are running with no-switch option
            if not os.access('/sys/class/net/{}'.format(host_intf), os.F_OK):
                os.system('ovs-vsctl add-br {}'.format(host_intf))
            uplink = self.port_map[host_intf]['uplink']
            if setup_ponsim is True:
                if host_intf.find('_') < 0:
                    print('Invalid host interface specified with ponsim. Disabling ponsim setup')
                    setup_ponsim = False
                else:
                    try:
                        host_index = int(host_intf.split('_')[-1])
                        host_intf_base = host_intf.split('_')[0]
                    except:
                        print('Invalid host interface with ponsim. Disabling ponsim setup')
                        setup_ponsim = False
            for port in ports:
                guest_if = port
                local_if = 'l{}'.format(port_num+1) #port #'{0}_{1}'.format(guest_if, port_num+1)
                guest_ip = '{0}.{1}/24'.format(tester_intf_subnet, port_num+1)
                if setup_ponsim is True:
                    if port != self.port_map[uplink]:
                        host_intf = '{}_{}'.format(host_intf_base, host_index)
                        host_index += 1

                ##Use pipeworks to configure container interfaces on host/bridge interfaces
                pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4}'.format(host_intf, guest_if,
                                                                           local_if, self.name, guest_ip)
                #if the wan interface is specified for uplink, then use it instead
                if wan and port == self.port_map[uplink]:
                    pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4}'.format(wan, guest_if,
                                                                               local_if, self.name, guest_ip)
                else:
                    if start_vlan != 0:
                        pipework_cmd += ' @{}'.format(start_vlan)
                        start_vlan += 1
                print('Running PIPEWORK cmd: %s' %pipework_cmd)
                res += os.system(pipework_cmd)
                port_num += 1

            if setup_ponsim is True:
                ponsim = False
                wan = None

        self.setup_vcpes(vcpe_port_num)
        return res, port_num

    @classmethod
    def get_intf_type(cls, intf):
        intf_type = 0
        if os.path.isdir('/sys/class/net/{}/bridge'.format(intf)):
            intf_type = 1 ##linux bridge
        else:
            cmd = 'ovs-vsctl list-br | grep -q "^{0}$"'.format(intf)
            res = os.system(cmd)
            if res == 0: ##ovs bridge
                intf_type = 2

        return intf_type

    @classmethod
    def cleanup_intfs(cls, olt_conf_file):
        if not os.access(olt_conf_file, os.F_OK):
            olt_conf_file = os.path.join(cls.tester_base, os.path.basename(olt_conf_file))
        olt_config = OltConfig(olt_conf_file)
        port_map, _ = olt_config.olt_port_map()
        vcpes = olt_config.get_vcpes()
        port_num = 0
        start_vlan = port_map['start_vlan']
        wan = port_map['wan']
        cmds = ()
        res = 0
        port_list = port_map['switch_port_list'] + port_map['switch_relay_port_list']
        for intf_host, ports in port_list:
            intf_type = cls.get_intf_type(intf_host)
            for port in ports:
                local_if = 'l{}'.format(port_num+1) #port #'{0}_{1}'.format(port, port_num+1)
                if intf_type == 0:
                    if start_vlan != 0:
                        cmds = ('ip link del {}.{}'.format(intf_host, start_vlan),)
                        start_vlan += 1
                else:
                    if intf_type == 1:
                        cmds = ('brctl delif {} {}'.format(intf_host, local_if),
                                'ip link del {}'.format(local_if))
                    else:
                        cmds = ('ovs-vsctl del-port {} {}'.format(intf_host, local_if),
                                'ip link del {}'.format(local_if))

                for cmd in cmds:
                    res += os.system(cmd)
                port_num += 1

        cls.cleanup_vcpes(vcpes)

    @classmethod
    def get_name(cls, num_instances):
        cnt_name = '/{0}'.format(cls.basename)
        cnt_name_len = len(cnt_name)
        names = list(flatten(n['Names'] for n in cls.dckr.containers(all=True)))
        test_names = filter(lambda n: n.startswith(cnt_name), names)
        last_cnt_number = 0
        if test_names:
            last_cnt_name = reduce(lambda n1, n2: n1 if int(n1[cnt_name_len:]) > \
                                       int(n2[cnt_name_len:]) else n2,
                                   test_names)
            last_cnt_number = int(last_cnt_name[cnt_name_len:])
            if num_instances == 1:
                last_cnt_number -= 1
        test_cnt_name = cls.basename + str(last_cnt_number+1)
        return test_cnt_name

    @classmethod
    def build_image(cls, image):
        print('Building test container docker image %s' %image)
        ovs_version = '2.5.0'
        image_format = (ovs_version,)*4
        dockerfile = '''
FROM ubuntu:14.04
MAINTAINER chetan@ciena.com
RUN apt-get update  && \
    apt-get install -y git git-core autoconf automake autotools-dev pkg-config \
        make gcc g++ libtool libc6-dev cmake libpcap-dev libxerces-c2-dev  \
        unzip libpcre3-dev flex bison libboost-dev \
        python python-pip python-setuptools python-scapy tcpdump doxygen doxypy wget \
        openvswitch-common openvswitch-switch \
        python-twisted python-sqlite sqlite3 python-pexpect telnet arping isc-dhcp-server \
        python-paramiko python-maas-client python-keystoneclient python-neutronclient \
        python-glanceclient python-novaclient python-dev libffi-dev libssl-dev
RUN easy_install nose
RUN python -m pip install --upgrade pip
RUN mkdir -p /root/ovs
WORKDIR /root
RUN wget http://openvswitch.org/releases/openvswitch-{}.tar.gz -O /root/ovs/openvswitch-{}.tar.gz && \
(cd /root/ovs && tar zxpvf openvswitch-{}.tar.gz && \
 cd openvswitch-{} && \
 ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && make && make install)
RUN service openvswitch-switch restart || /bin/true
RUN pip install scapy==2.3.2 scapy-ssl_tls==1.2.2 monotonic configObj docker-py pyyaml nsenter pyroute2 netaddr python-daemon
RUN pip install -U cryptography
RUN pip install -U paramiko
RUN mv /usr/sbin/tcpdump /sbin/
RUN ln -sf /sbin/tcpdump /usr/sbin/tcpdump
RUN mv /usr/sbin/dhcpd /sbin/
RUN ln -sf /sbin/dhcpd /usr/sbin/dhcpd
RUN mv /sbin/dhclient /usr/sbin/
RUN ln -sf /usr/sbin/dhclient /sbin/dhclient
WORKDIR /root
RUN wget -nc http://de.archive.ubuntu.com/ubuntu/pool/main/b/bison/bison_2.5.dfsg-2.1_amd64.deb \
         http://de.archive.ubuntu.com/ubuntu/pool/main/b/bison/libbison-dev_2.5.dfsg-2.1_amd64.deb
RUN sudo dpkg -i bison_2.5.dfsg-2.1_amd64.deb libbison-dev_2.5.dfsg-2.1_amd64.deb
RUN rm bison_2.5.dfsg-2.1_amd64.deb libbison-dev_2.5.dfsg-2.1_amd64.deb
RUN wget -nc http://www.nbee.org/download/nbeesrc-jan-10-2013.zip && \
    unzip nbeesrc-jan-10-2013.zip && \
    cd nbeesrc-jan-10-2013/src && cmake . && make && \
    cp ../bin/libn*.so /usr/local/lib && ldconfig && \
    cp -R ../include/* /usr/include/
WORKDIR /root
RUN git clone https://github.com/CPqD/ofsoftswitch13.git && \
    cd ofsoftswitch13 && \
    ./boot.sh && \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && \
    make && make install
CMD ["/bin/bash"]
'''.format(*image_format)
        super(CordTester, cls).build_image(dockerfile, image)
        print('Done building docker image %s' %image)

    def run_tests(self):
        '''Run the list of tests'''
        res = 0
        print('Modifying scapy tool files before running a test: %s' %self.tests)
        self.modify_scapy_files_for_specific_tests()
        print('Running tests: %s' %self.tests)
        for t in self.tests:
            test = t.split(':')[0]
            test_file = '{}Test.py'.format(test)
            if t.find(':') >= 0:
                test_case = '{0}:{1}'.format(test_file, t.split(':')[1])
            else:
                test_case = test_file
            cmd = 'nosetests -v {0}/src/test/{1}/{2}'.format(self.sandbox, test, test_case)
            status = self.execute(cmd, shell = True)
            if status > 255:
                status = 1
            res |= status
            print('Test %s %s' %(test_case, 'Success' if status == 0 else 'Failure'))
        print('Done running tests')
        if self.rm:
            print('Removing test container %s' %self.name)
            self.kill(remove=True)

        return res

    def modify_scapy_files_for_specific_tests(self):
        name = self.name
        container_cmd_exec = Container(name = name, image = CordTester.IMAGE)
        tty = False
        dckr = Client()
        cmd =  'cp test/src/test/scapy/fields.py /usr/local/lib/python2.7/dist-packages/scapy/fields.py '
        i = container_cmd_exec.execute(cmd = cmd, tty= tty, stream = True)

    @classmethod
    def list_tests(cls, tests):
        print('Listing test cases')
        for test in tests:
            test_file = '{}Test.py'.format(test)
            cmd = 'nosetests -v --collect-only {0}/../{1}/{2}'.format(cls.tester_base, test, test_file)
            os.system(cmd)


##default onos/radius/test container images and names
onos_image_default='onosproject/onos:latest'
nose_image_default= '{}:candidate'.format(CordTester.IMAGE)
test_type_default='dhcp'
onos_app_version = '3.0-SNAPSHOT'
cord_tester_base = os.path.dirname(os.path.realpath(__file__))
olt_config_default = os.path.join(cord_tester_base, 'olt_config.json')
onos_app_file = os.path.abspath('{0}/../apps/ciena-cordigmp-multitable-'.format(cord_tester_base) + onos_app_version + '.oar')
cord_test_server_address = '{}:{}'.format(CORD_TEST_HOST, CORD_TEST_PORT)
identity_file_default = '/etc/maas/ansible/id_rsa'
onos_log_level = 'INFO'

##sets up the ssh key file for the test container
def set_ssh_key_file(identity_file):
    ssh_key_file = None
    if os.access(identity_file, os.F_OK):
        ##copy it to setup directory
        identity_dest = os.path.join(CordTester.tester_base, 'id_rsa')
        if os.path.abspath(identity_file) != identity_dest:
            try:
                shutil.copy(identity_file, identity_dest)
                ssh_key_file = os.path.join(CordTester.sandbox_setup, 'id_rsa')
            except: pass

    return ssh_key_file

def openstack_setup(test_cnt_env):
    admin_rc = os.path.join(os.getenv('HOME'), 'admin-openrc.sh')
    if not os.access(admin_rc, os.F_OK):
        admin_rc = os.path.join('/opt/cord_profile', 'admin-openrc.sh')
    if os.access(admin_rc, os.F_OK):
        dest = os.path.join(CordTester.tester_base, 'admin-openrc.sh')
        shutil.copy(admin_rc, dest)
        with open(dest, 'r') as f:
            cfg = {}
            for data in f.read().splitlines():
                try:
                    k, v = data.split('=')
                except:
                    continue

                k = k.split()[-1]
                cfg[k] = v

            if 'REQUESTS_CA_BUNDLE' in cfg:
                #copy the certificate to setup directory
                cert_src = cfg['REQUESTS_CA_BUNDLE']
                shutil.copy(cert_src, CordTester.tester_base)
                test_cert_loc = os.path.join(CordTester.sandbox_setup,
                                             os.path.basename(cert_src))
                cfg['REQUESTS_CA_BUNDLE'] = test_cert_loc

            for key, value in cfg.iteritems():
                test_cnt_env[key] = value

def runTest(args):
    #Start the cord test tcp server
    test_manifest = TestManifest(args = args)
    test_server_params = test_manifest.server.split(':')
    test_host = test_server_params[0]
    test_port = CORD_TEST_PORT
    if len(test_server_params) > 1:
        test_port = int(test_server_params[1])

    test_containers = []
    #These tests end up restarting ONOS/quagga/radius
    tests_exempt = ('vrouter', 'cordSubscriber', 'proxyarp', 'dhcprelay')
    if args.test_type.lower() == 'all':
        tests = CordTester.ALL_TESTS
        args.quagga = True
    else:
        tests = args.test_type.split('-')

    tests_parallel = [ t for t in tests if t.split(':')[0] not in tests_exempt ]
    tests_not_parallel = [ t for t in tests if t.split(':')[0] in tests_exempt ]
    onos_cnt = {'tag':'latest'}
    nose_cnt = {'image': CordTester.IMAGE, 'tag': 'candidate'}
    update_map = { 'quagga' : False, 'test' : False, 'radius' : False }
    update_map[args.update.lower()] = True

    if args.update.lower() == 'all':
       for c in update_map.keys():
           update_map[c] = True

    use_manifest = False
    if args.manifest:
        if os.access(args.manifest, os.F_OK):
            ##copy it to setup directory
            dest = os.path.join(CordTester.tester_base,
                                os.path.basename(args.manifest))
            if os.path.abspath(args.manifest) != dest:
                try:
                    shutil.copy(args.manifest, dest)
                except: pass
            test_manifest = TestManifest(manifest = dest)
            use_manifest = True
        else:
            print('Unable to access test manifest: %s' %args.manifest)

    onos_ip = test_manifest.onos_ip
    radius_ip = test_manifest.radius_ip
    head_node = test_manifest.head_node
    iterations = test_manifest.iterations
    onos_cord_loc = test_manifest.onos_cord
    service_profile = test_manifest.service_profile
    synchronizer = test_manifest.synchronizer
    olt_config_file = test_manifest.olt_config
    voltha_loc = test_manifest.voltha_loc
    voltha_intf = test_manifest.voltha_intf
    if not os.access(olt_config_file, os.F_OK):
        olt_config_file = os.path.join(CordTester.tester_base, 'olt_config.json')
    else:
        dest = os.path.join(CordTester.tester_base,
                            os.path.basename(olt_config_file))
        if os.path.abspath(olt_config_file) != dest:
            try:
                shutil.copy(olt_config_file, dest)
            except: pass

    onos_cord = None
    Onos.update_data_dir(test_manifest.karaf_version)
    Onos.set_expose_port(test_manifest.expose_port)
    if onos_cord_loc:
        if onos_cord_loc.find(os.path.sep) < 0:
            onos_cord_loc = os.path.join(os.getenv('HOME'), onos_cord_loc)
        if not os.access(onos_cord_loc, os.F_OK):
            print('ONOS cord config location %s is not accessible' %onos_cord_loc)
            sys.exit(1)
        if not onos_ip:
            ##Unexpected case. Specify the external controller ip when running on cord node
            print('Specify ONOS ip using \"-e\" option when running the cord-tester on cord node')
            sys.exit(1)
        if not service_profile:
            print('Specify service profile for the ONOS cord instance. Eg: rcord')
            sys.exit(1)
        if not synchronizer:
            print('Specify synchronizer to use for the ONOS cord instance. Eg: vtn, fabric, cord')
            sys.exit(1)
        onos_cord = OnosCord(onos_ip, onos_cord_loc, service_profile, synchronizer, skip = test_manifest.skip_onos_restart)

    try:
        test_server = cord_test_server_start(daemonize = False, cord_test_host = test_host, cord_test_port = test_port,
                                             onos_cord = onos_cord)
    except:
        ##Most likely a server instance is already running (daemonized earlier)
        test_server = None

    Container.IMAGE_PREFIX = test_manifest.image_prefix
    Onos.MAX_INSTANCES = test_manifest.onos_instances
    Onos.JVM_HEAP_SIZE = test_manifest.jvm_heap_size
    cluster_mode = True if test_manifest.onos_instances > 1 else False
    async_mode = cluster_mode and test_manifest.async_mode
    existing_list = [ c['Names'][0][1:] for c in Container.dckr.containers() if c['Image'] == test_manifest.onos_image ]
    setup_cluster = False if len(existing_list) == test_manifest.onos_instances else True
    onos_ips = []
    if cluster_mode is True and len(existing_list) > 1:
        ##don't setup cluster config again
        cluster_mode = False
    if voltha_loc:
        voltha_key = os.path.join(voltha_loc, 'docker', 'onos_cfg', 'onos.jks')
        Onos.update_ssl_key(voltha_key)
    if onos_ip is None:
        image_names = test_manifest.onos_image.rsplit(':', 1)
        onos_cnt['image'] = image_names[0]
        if len(image_names) > 1:
            if image_names[1].find('/') < 0:
                onos_cnt['tag'] = image_names[1]
            else:
                #tag cannot have slashes
                onos_cnt['image'] = test_manifest.onos_image

        Onos.IMAGE = onos_cnt['image']
        Onos.PREFIX = test_manifest.image_prefix
        Onos.TAG = onos_cnt['tag']
        data_volume = '{}-data'.format(Onos.NAME) if test_manifest.shared_volume else None
        onos = Onos(image = Onos.IMAGE,
                    tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode,
                    data_volume = data_volume, async = async_mode, network = test_manifest.docker_network)
        if onos.running:
            onos_ips.append(onos.ipaddr)
    else:
        onos_ips.append(onos_ip)

    num_onos_instances = test_manifest.onos_instances
    if num_onos_instances > 1 and onos is not None:
        onos_instances = []
        onos_instances.append(onos)
        for i in range(1, num_onos_instances):
            name = '{}-{}'.format(Onos.NAME, i+1)
            data_volume = '{}-data'.format(name) if test_manifest.shared_volume else None
            quagga_config = Onos.get_quagga_config(i)
            onos = Onos(name = name, image = Onos.IMAGE, tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode,
                        data_volume = data_volume, async = async_mode,
                        quagga_config = quagga_config, network = test_manifest.docker_network, instance = i)
            onos_instances.append(onos)
            if onos.running:
                onos_ips.append(onos.ipaddr)
        if async_mode is True and cluster_mode is True:
            Onos.start_cluster_async(onos_instances)
        if not onos_ips:
            for onos in onos_instances:
                onos_ips.append(onos.ipaddr)
        if cluster_mode is True:
            try:
                for ip in onos_ips:
                    print('Installing cord tester ONOS app %s in ONOS instance %s' %(args.app,ip))
                    OnosCtrl.install_app(args.app, onos_ip = ip)
            except: pass
        if setup_cluster is True:
            Onos.setup_cluster(onos_instances)
        else:
            print('ONOS instances already running. Skipping ONOS form cluster for %d instances' %num_onos_instances)
    ctlr_addr = ','.join(onos_ips)

    print('Controller IP %s, Test type %s' %(onos_ips, args.test_type))
    if onos_ip is not None:
        print('Installing ONOS cord apps')
        try:
            Onos.install_cord_apps(onos_ip = onos_ip)
        except: pass

    if not cluster_mode:
        print('Installing cord tester ONOS app %s' %args.app)
        try:
	    for ip in onos_ips:
                OnosCtrl.install_app(args.app, onos_ip = ip)
        except: pass

    if voltha_loc:
        #start voltha
        voltha = VolthaService(voltha_loc, onos_ips[0], interface = voltha_intf,
                               olt_config = olt_config_file, container_mode = test_manifest.voltha_container_mode)
        voltha.start()

    if radius_ip is None:
        ##Start Radius container
        radius = Radius(prefix = Container.IMAGE_PREFIX, update = update_map['radius'],
                        network = test_manifest.docker_network)
        radius_ip = radius.ip(network = test_manifest.docker_network)

    print('Radius server running with IP %s' %radius_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(prefix = Container.IMAGE_PREFIX, update = update_map['quagga'],
                        network = test_manifest.docker_network)

    try:
        maas_api_key = FabricMAAS.get_api_key()
    except:
        maas_api_key = 'UNKNOWN'

    ssh_key_file = set_ssh_key_file(args.identity_file)
    test_cnt_env = { 'ONOS_CONTROLLER_IP' : ctlr_addr,
                     'ONOS_AAA_IP' : radius_ip if radius_ip is not None else '',
                     'QUAGGA_IP': test_host,
                     'CORD_TEST_HOST' : test_host,
                     'CORD_TEST_PORT' : test_port,
                     'ONOS_RESTART' : 0 if test_manifest.olt and args.test_controller else 1,
                     'LOG_LEVEL': test_manifest.log_level,
                     'HEAD_NODE': head_node if head_node else CORD_TEST_HOST,
                     'MAAS_API_KEY': maas_api_key,
                     'KARAF_VERSION' : test_manifest.karaf_version,
                     'VOLTHA_ENABLED' : int(test_manifest.voltha_enable)
                   }

    if ssh_key_file:
        test_cnt_env['SSH_KEY_FILE'] = ssh_key_file

    olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, os.path.basename(olt_config_file))
    test_cnt_env['OLT_CONFIG_FILE'] = olt_conf_test_loc
    if test_manifest.olt:
        test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

    if use_manifest:
        test_cnt_env['MANIFEST'] = os.path.join(CordTester.sandbox_setup,
                                                os.path.basename(args.manifest))


    if iterations is not None:
        test_cnt_env['ITERATIONS'] = iterations

    openstack_setup(test_cnt_env)

    if args.num_containers > 1 and args.container:
        print('Cannot specify number of containers with container option')
        sys.exit(1)
    if args.container:
        args.keep = True
    port_num = 0
    num_tests = len(tests_parallel)
    if num_tests > 0 and num_tests < args.num_containers:
        tests_parallel *= args.num_containers/num_tests
        num_tests = len(tests_parallel)
    tests_per_container = max(1, num_tests/args.num_containers)
    last_batch = num_tests % args.num_containers
    test_slice_start = 0
    test_slice_end = test_slice_start + tests_per_container
    num_test_containers = min(num_tests, args.num_containers)
    if tests_parallel:
        print('Running %s tests across %d containers in parallel' %(tests_parallel, num_test_containers))
    for container in xrange(num_test_containers):
        if container + 1 == num_test_containers:
            test_slice_end += last_batch
        test_cnt = CordTester(tests_parallel[test_slice_start:test_slice_end],
                              instance = container, num_instances = num_test_containers,
                              ctlr_ip = ctlr_addr,
                              name = args.container,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'],
                              network = test_manifest.docker_network)
        test_slice_start = test_slice_end
        test_slice_end = test_slice_start + tests_per_container
        update_map['test'] = False
        test_containers.append(test_cnt)
        if not test_cnt.create:
            continue
        if test_cnt.create and (test_manifest.start_switch or not test_manifest.olt):
            if not args.no_switch:
                test_cnt.start_switch(test_manifest)
        if test_cnt.create and test_cnt.olt:
            _, port_num = test_cnt.setup_intfs(port_num = port_num)

    status = 0
    if len(test_containers) > 1:
        thread_pool = ThreadPool(len(test_containers), queue_size = 1, wait_timeout=1)
        for test_cnt in test_containers:
            thread_pool.addTask(test_cnt.run_tests)
        thread_pool.cleanUpThreads()
    else:
        if test_containers:
            status = test_containers[0].run_tests()

    ##Run the linear tests
    if tests_not_parallel:
        test_cnt = CordTester(tests_not_parallel,
                              ctlr_ip = ctlr_addr,
                              name = args.container,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'],
                              network = test_manifest.docker_network)
        if test_cnt.create and (test_manifest.start_switch or not test_manifest.olt):
            #For non parallel tests, we just restart the switch also for OLT's
            CordTester.switch_on_olt = False
            if not args.no_switch:
                test_cnt.start_switch(test_manifest)
        if test_cnt.create and test_cnt.olt:
            test_cnt.setup_intfs(port_num = port_num)
        test_cnt.run_tests()

    if test_server:
        if onos_cord:
            onos_cord.restore()
        cord_test_server_stop(test_server)

    return status

##Starts onos/radius/quagga containers as appropriate
def setupCordTester(args):
    onos_cnt = {'tag':'latest'}
    nose_cnt = {'image': CordTester.IMAGE, 'tag': 'candidate'}
    update_map = { 'quagga' : False, 'radius' : False, 'test': False }
    update_map[args.update.lower()] = True
    test_manifest = TestManifest(args = args)

    if args.update.lower() == 'all':
       for c in update_map.keys():
           update_map[c] = True

    use_manifest = False
    if args.manifest:
        if os.access(args.manifest, os.F_OK):
            ##copy it to setup directory
            dest = os.path.join(CordTester.tester_base,
                                os.path.basename(args.manifest))
            if os.path.abspath(args.manifest) != dest:
                try:
                    shutil.copy(args.manifest, dest)
                except: pass
            test_manifest = TestManifest(manifest = dest)
            use_manifest = True

    onos_ip = test_manifest.onos_ip
    radius_ip = test_manifest.radius_ip
    head_node = test_manifest.head_node
    iterations = test_manifest.iterations
    service_profile = test_manifest.service_profile
    synchronizer = test_manifest.synchronizer
    voltha_loc = test_manifest.voltha_loc
    voltha_intf = test_manifest.voltha_intf
    onos_cord = None
    onos_cord_loc = test_manifest.onos_cord
    Onos.update_data_dir(test_manifest.karaf_version)
    Onos.set_expose_port(test_manifest.expose_port)
    olt_config_file = test_manifest.olt_config
    if not os.access(olt_config_file, os.F_OK):
        olt_config_file = os.path.join(CordTester.tester_base, 'olt_config.json')
    else:
        dest = os.path.join(CordTester.tester_base,
                            os.path.basename(olt_config_file))
        if os.path.abspath(olt_config_file) != dest:
            try:
                shutil.copy(olt_config_file, dest)
            except: pass

    if onos_cord_loc:
        if onos_cord_loc.find(os.path.sep) < 0:
            onos_cord_loc = os.path.join(os.getenv('HOME'), onos_cord_loc)
        if not os.access(onos_cord_loc, os.F_OK):
            print('ONOS cord config location %s is not accessible' %onos_cord_loc)
            sys.exit(1)
        if not onos_ip:
            ##Unexpected case. Specify the external controller ip when running on cord node
            print('Specify ONOS ip using \"-e\" option when running the cord-tester on cord node')
            sys.exit(1)
        if not service_profile:
            print('Specify service profile for the ONOS cord instance. Eg: rcord')
            sys.exit(1)
        if not synchronizer:
            print('Specify synchronizer to use for the ONOS cord instance. Eg: vtn, fabric, cord')
            sys.exit(1)
        onos_cord = OnosCord(onos_ip, onos_cord_loc, service_profile, synchronizer, skip = test_manifest.skip_onos_restart)

    Container.IMAGE_PREFIX = test_manifest.image_prefix
    #don't spawn onos if the user had started it externally
    image_names = test_manifest.onos_image.rsplit(':', 1)
    onos_cnt['image'] = image_names[0]
    if len(image_names) > 1:
        if image_names[1].find('/') < 0:
            onos_cnt['tag'] = image_names[1]
        else:
            #tag cannot have slashes
            onos_cnt['image'] = test_manifest.onos_image

    Onos.IMAGE = onos_cnt['image']
    Onos.PREFIX = test_manifest.image_prefix
    Onos.TAG = onos_cnt['tag']
    Onos.MAX_INSTANCES = test_manifest.onos_instances
    Onos.JVM_HEAP_SIZE = test_manifest.jvm_heap_size
    cluster_mode = True if test_manifest.onos_instances > 1 else False
    async_mode = cluster_mode and test_manifest.async_mode
    existing_list = [ c['Names'][0][1:] for c in Container.dckr.containers() if c['Image'] == test_manifest.onos_image ]
    setup_cluster = False if len(existing_list) == test_manifest.onos_instances else True
    #cleanup existing volumes before forming a new cluster
    if setup_cluster is True:
        print('Cleaning up existing cluster volumes')
        data_dir = os.path.join(Onos.setup_dir, 'cord-onos*-data')
        try:
            os.system('rm -rf {}'.format(data_dir))
        except: pass

    onos = None
    onos_ips = []
    if voltha_loc:
        voltha_key = os.path.join(voltha_loc, 'docker', 'onos_cfg', 'onos.jks')
        Onos.update_ssl_key(voltha_key)
    if onos_ip is None:
        data_volume = '{}-data'.format(Onos.NAME) if test_manifest.shared_volume else None
        onos = Onos(image = Onos.IMAGE, tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode,
                    data_volume = data_volume, async = async_mode, network = test_manifest.docker_network)
        if onos.running:
            onos_ips.append(onos.ipaddr)
    else:
        onos_ips.append(onos_ip)

    num_onos_instances = test_manifest.onos_instances
    if num_onos_instances > 1 and onos is not None:
        onos_instances = []
        onos_instances.append(onos)
        for i in range(1, num_onos_instances):
            name = '{}-{}'.format(Onos.NAME, i+1)
            data_volume = '{}-data'.format(name) if test_manifest.shared_volume else None
            quagga_config = Onos.get_quagga_config(i)
            onos = Onos(name = name, image = Onos.IMAGE, tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode,
                        data_volume = data_volume, async = async_mode,
                        quagga_config = quagga_config, network = test_manifest.docker_network, instance = i)
            onos_instances.append(onos)
            if onos.running:
                onos_ips.append(onos.ipaddr)
        if async_mode is True:
            Onos.start_cluster_async(onos_instances)
        if not onos_ips:
            for onos in onos_instances:
                onos_ips.append(onos.ipaddr)
        if setup_cluster is True:
            Onos.setup_cluster(onos_instances)

    ctlr_addr = ','.join(onos_ips)
    print('Onos IP %s' %ctlr_addr)
    if not test_manifest.skip_onos_restart:
        if onos_ip is not None:
            print('Installing ONOS cord apps')
            try:
                Onos.install_cord_apps(onos_ip = onos_ip)
            except: pass

        print('Installing cord tester ONOS app %s' %args.app)
        try:
            for ip in onos_ips:
                OnosCtrl.install_app(args.app, onos_ip = ip)
        except: pass

    if voltha_loc:
        #start voltha
        voltha = VolthaService(voltha_loc, onos_ips[0], interface = voltha_intf,
                               olt_config = olt_config_file, container_mode = test_manifest.voltha_container_mode)
        voltha.start()

    ##Start Radius container if not started
    if radius_ip is None:
        radius = Radius(prefix = Container.IMAGE_PREFIX, update = update_map['radius'],
                        network = test_manifest.docker_network)
        radius_ip = radius.ip(network = test_manifest.docker_network)

    print('Radius server running with IP %s' %radius_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(prefix = Container.IMAGE_PREFIX, update = update_map['quagga'],
                        network = test_manifest.docker_network)
        print('Quagga started')

    params = test_manifest.server.split(':')
    ip = params[0]
    port = CORD_TEST_PORT
    if len(params) > 1:
        port = int(params[1])

    try:
        maas_api_key = FabricMAAS.get_api_key()
    except:
        maas_api_key = 'UNKNOWN'

    ssh_key_file = set_ssh_key_file(args.identity_file)

    #provision the test container
    if not args.dont_provision:
        test_cnt_env = { 'ONOS_CONTROLLER_IP' : ctlr_addr,
                         'ONOS_AAA_IP' : radius_ip,
                         'QUAGGA_IP': ip,
                         'CORD_TEST_HOST' : ip,
                         'CORD_TEST_PORT' : port,
                         'ONOS_RESTART' : 0 if test_manifest.olt and args.test_controller else 1,
                         'LOG_LEVEL': test_manifest.log_level,
                         'HEAD_NODE': head_node if head_node else CORD_TEST_HOST,
                         'MAAS_API_KEY': maas_api_key,
                         'KARAF_VERSION' : test_manifest.karaf_version,
                         'VOLTHA_ENABLED' : int(test_manifest.voltha_enable)
                       }

        if ssh_key_file:
            test_cnt_env['SSH_KEY_FILE'] = ssh_key_file
        olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, os.path.basename(olt_config_file))
        test_cnt_env['OLT_CONFIG_FILE'] = olt_conf_test_loc
        if test_manifest.olt:
            test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc
        if test_manifest.iterations is not None:
            test_cnt_env['ITERATIONS'] = iterations
        if use_manifest:
            test_cnt_env['MANIFEST'] = os.path.join(CordTester.sandbox_setup,
                                                    os.path.basename(args.manifest))

        openstack_setup(test_cnt_env)

        test_cnt = CordTester((),
                              ctlr_ip = ctlr_addr,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False,
                              update = update_map['test'],
                              network = test_manifest.docker_network)

        if test_manifest.start_switch or not test_manifest.olt:
            test_cnt.start_switch(test_manifest)
        if test_cnt.olt:
            test_cnt.setup_intfs(port_num = 0)
        print('Test container %s started and provisioned to run tests using nosetests' %(test_cnt.name))

    #Finally start the test server and daemonize
    try:
        cord_test_server_start(daemonize = not args.foreground, cord_test_host = ip, cord_test_port = port,
                               onos_cord = onos_cord, foreground = args.foreground)
    except socket.error, e:
        #the test agent address could be remote or already running. Exit gracefully
        sys.exit(0)

    return 0

def cleanupTests(args):
    if args.manifest and os.access(args.manifest, os.F_OK):
        manifest = TestManifest(manifest = args.manifest)
        args.prefix = manifest.image_prefix
        args.olt = manifest.olt
        args.olt_config = manifest.olt_config
        args.onos = manifest.onos_image
        args.server = manifest.server
        args.onos_ip = manifest.onos_ip
        args.radius_ip = manifest.radius_ip
        args.onos_cord = manifest.onos_cord
        args.service_profile = manifest.service_profile
        args.synchronizer = manifest.synchronizer
        args.voltha_loc = manifest.voltha_loc
    else:
        args.onos_ip = None
        args.radius_ip = None
        if args.test_controller:
            ips = args.test_controller.split('/')
            args.onos_ip = ips[0]
            if len(ips) > 1:
                args.radius_ip = ips[1]

    image_name = args.onos
    prefix = args.prefix
    if prefix:
        prefix += '/'
    test_container = '{}{}:candidate'.format(prefix, CordTester.IMAGE)
    print('Cleaning up Test containers ...')
    Container.cleanup(test_container)
    if args.olt:
        print('Cleaning up test container OLT configuration')
        CordTester.cleanup_intfs(args.olt_config)

    onos_list = [ c['Names'][0][1:] for c in Container.dckr.containers() if c['Image'] == image_name ]
    if len(onos_list) > 1:
        for onos in onos_list:
            Container.dckr.kill(onos)
            Container.dckr.remove_container(onos, force=True)
        for index in range(len(onos_list)):
            volume = '{}-data'.format(Onos.NAME) if index == 0 else '{}-{}-data'.format(Onos.NAME, index+1)
            Onos.remove_data_map(volume, Onos.guest_data_dir)
        Onos.cleanup_runtime()

    radius_container = '{}{}:candidate'.format(prefix, Radius.IMAGE)
    quagga_container = '{}{}:candidate'.format(prefix, Quagga.IMAGE)
    Container.cleanup(radius_container)
    Container.cleanup(quagga_container)
    if args.voltha_loc:
        voltha = VolthaService(args.voltha_loc, args.onos_ip)
        voltha.stop()

    if args.onos_cord:
        #try restoring the onos cord instance
        try:
            onos_cord = OnosCord(args.onos_ip, args.onos_cord, args.service_profile, args.synchronizer, start = False, skip = test_manifest.skip_onos_restart)
            onos_cord.restore(force = True)
        except Exception as e:
            print(e)

    if args.xos:
        ##cleanup XOS images
        xos_images = ( '{}:{}'.format(XosServer.IMAGE,XosServer.TAG),
                       '{}:{}'.format(XosSynchronizerOpenstack.IMAGE,
                                      XosSynchronizerOpenstack.TAG),
                       '{}:{}'.format(XosSynchronizerOnboarding.IMAGE,
                                      XosSynchronizerOnboarding.TAG),
                       '{}:{}'.format(XosSynchronizerOpenvpn.IMAGE,
                                      XosSynchronizerOpenvpn.TAG),
                       '{}:{}'.format(XosPostgresql.IMAGE,
                                      XosPostgresql.TAG),
                       '{}:{}'.format(XosSyndicateMs.IMAGE,
                                      XosSyndicateMs.TAG),
                       )
        for img in xos_images:
            print('Cleaning up XOS image: %s' %img)
            Container.cleanup(img)

    server_params = args.server.split(':')
    server_host = server_params[0]
    server_port = CORD_TEST_PORT
    if len(server_params) > 1:
        server_port = int(server_params[1])
    cord_test_server_shutdown(server_host, server_port)
    return 0

def listTests(args):
    if args.test == 'all':
        tests = CordTester.ALL_TESTS
    else:
        tests = args.test.split('-')
    CordTester.list_tests(tests)
    return 0

def getMetrics(args):
    try:
        detail = c.inspect_container(args.container)
    except:
        print('Unknown container %s' %args.container)
        return 0
    user_hz = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    state = detail["State"]
    if bool(state["Paused"]):
       print("Container is in Paused State")
    elif bool(state["Running"]):
       print("Container is in Running State")
    elif int(state["ExitCode"]) == 0:
       print("Container is in Stopped State")
    else:
       print("Container is in Crashed State")

    print("Ip Address of the container: " +detail['NetworkSettings']['IPAddress'])

    if bool(detail["State"]["Running"]):
        container_id = detail['Id']
        cpu_usage = {}
        cur_usage = 0
        last_usage = 0
        for i in range(2):
            with open('/sys/fs/cgroup/cpuacct/docker/' + container_id + '/cpuacct.stat', 'r') as f:
                for line in f:
                    m = re.search(r"(system|user)\s+(\d+)", line)
                    if m:
                        cpu_usage[m.group(1)] = int(m.group(2))
                cpu = cpu_usage["system"] + cpu_usage["user"]
                last_usage = cur_usage
                cur_usage = cpu
                time.sleep(1)
        cpu_percent = (cur_usage - last_usage)*100.0/user_hz
        print("CPU Usage: %.2f %%" %(cpu_percent))
    else:
        print(0)

    if bool(detail["State"]["Running"]):
        container_id = detail['Id']
        print("Docker Port Info:")
        cmd = "sudo docker port {}".format(container_id)
        os.system(cmd)

    if bool(detail["State"]["Running"]):
        container_id = detail['Id']
        with open('/sys/fs/cgroup/memory/docker/' + container_id + '/memory.stat', 'r') as f:
            for line in f:
                m = re.search(r"total_rss\s+(\d+)", line)
                if m:
                    mem = int(m.group(1))
                    print("Memory: %s KB "%(mem/1024.0))
                o = re.search(r"usage\s+(\d+)", line)
                if o:
                    print("Usage: %s "%(o.group(1)))
                p = re.search(r"max_usage\s+(\d+)", line)
                if p:
                    print("Max Usage: %s "%(p.group(1)))

    if bool(detail["State"]["Running"]):
        container_id = detail['Id']
        with open('/sys/fs/cgroup/cpuacct/docker/' + container_id + '/cpuacct.stat', 'r') as f:
            for line in f:
                m = re.search(r"user\s+(\d+)", line)
                if m:
                    user_ticks = int(m.group(1))
                    print("Time spent by running processes: %.2f ms"%(user_ticks*1000.0/user_hz))
    print("List Networks:")
    cmd = "docker network ls"
    os.system(cmd)
    return 0

def buildImages(args):
    tag = 'candidate'
    prefix = args.prefix
    if prefix:
        prefix += '/'
    if args.image == 'all' or args.image == 'quagga':
        image_name = '{}{}:{}'.format(prefix, Quagga.IMAGE, tag)
        Quagga.build_image(image_name)

    if args.image == 'all' or args.image == 'radius':
        image_name = '{}{}:{}'.format(prefix, Radius.IMAGE, tag)
        Radius.build_image(image_name)

    if args.image == 'all' or args.image == 'test':
        image_name = '{}{}:{}'.format(prefix, CordTester.IMAGE, tag)
        CordTester.build_image(image_name)

    return 0

def startImages(args):
    ##starts the latest ONOS image
    onos_cnt = {'tag': 'latest'}
    image_names = args.onos.rsplit(':', 1)
    onos_cnt['image'] = image_names[0]
    if len(image_names) > 1:
        if image_names[1].find('/') < 0:
            onos_cnt['tag'] = image_names[1]
        else:
            #tag cannot have slashes
            onos_cnt['image'] = args.onos

    if args.image == 'all' or args.image == 'onos':
        onos = Onos(image = onos_cnt['image'], tag = onos_cnt['tag'])
        print('ONOS started with ip %s' %(onos.ip()))

    if args.image == 'all' or args.image == 'quagga':
        quagga = Quagga(prefix = args.prefix)
        print('Quagga started with ip %s' %(quagga.ip()))

    if args.image == 'all' or args.image == 'radius':
        radius = Radius(prefix = args.prefix)
        print('Radius started with ip %s' %(radius.ip()))

    return 0

def xosCommand(args):
    update = False
    profile = args.profile
    if args.command == 'update':
        update = True
    xos = XosServiceProfile(profile = profile, update = update)
    if args.command == 'build':
        xos.build_images(force = True)
    if args.command == 'start':
        xos.start_services()
    if args.command == 'stop':
        xos.stop_services(rm = True)
    return 0

if __name__ == '__main__':
    parser = ArgumentParser(description='Cord Tester')
    subparser = parser.add_subparsers()
    parser_run = subparser.add_parser('run', help='Run cord tester')
    parser_run.add_argument('-t', '--test-type', default=test_type_default, help='Specify test type or test case to run')
    parser_run.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser_run.add_argument('-q', '--quagga',action='store_true',help='Provision quagga container for vrouter')
    parser_run.add_argument('-a', '--app', default=onos_app_file, type=str, help='Cord ONOS app filename')
    parser_run.add_argument('-l', '--olt', action='store_true', help='Use OLT config')
    parser_run.add_argument('-olt-config', '--olt-config', default=olt_config_default, type=str, help='Provide OLT configuration')
    parser_run.add_argument('-e', '--test-controller', default='', type=str, help='External test controller ip for Onos and/or radius server. '
                        'Eg: 10.0.0.2/10.0.0.3 to specify ONOS and Radius ip to connect')
    parser_run.add_argument('-r', '--server', default=cord_test_server_address, type=str,
                            help='ip:port address to connect for cord test server for container requests')
    parser_run.add_argument('-k', '--keep', action='store_true', help='Keep test container after tests')
    parser_run.add_argument('-s', '--start-switch', action='store_true', help='Start OVS when running under OLT config')
    parser_run.add_argument('-u', '--update', default='none', choices=['test','quagga','radius', 'all'], type=str, help='Update cord tester container images. '
                        'Eg: --update=quagga to rebuild quagga image.'
                        '    --update=radius to rebuild radius server image.'
                        '    --update=test to rebuild cord test image.(Default)'
                        '    --update=all to rebuild all cord tester images.')
    parser_run.add_argument('-n', '--num-containers', default=1, type=int,
                            help='Specify number of test containers to spawn for tests')
    parser_run.add_argument('-c', '--container', default='', type=str, help='Test container name for running tests')
    parser_run.add_argument('-m', '--manifest', default='', type=str, help='Provide test configuration manifest')
    parser_run.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_run.add_argument('-d', '--no-switch', action='store_true', help='Dont start test switch.')
    parser_run.add_argument('-i', '--identity-file', default=identity_file_default,
                            type=str, help='ssh identity file to access compute nodes from test container')
    parser_run.add_argument('-j', '--onos-instances', default=1, type=int,
                            help='Specify number to test onos instances to form cluster')
    parser_run.add_argument('-v', '--shared-volume', action='store_true', help='Start ONOS cluster instances with shared volume')
    parser_run.add_argument('-async', '--async-mode', action='store_true',
                            help='Start ONOS cluster instances in async mode')
    parser_run.add_argument('-log', '--log-level', default=onos_log_level,
                            choices=['DEBUG','TRACE','ERROR','WARN','INFO'],
                            type=str,
                            help='Specify the log level for the test cases')
    parser_run.add_argument('-jvm-heap-size', '--jvm-heap-size', default='', type=str, help='ONOS JVM heap size')
    parser_run.add_argument('-network', '--network', default='', type=str, help='Docker network to attach')
    parser_run.add_argument('-onos-cord', '--onos-cord', default='', type=str,
                            help='Specify config location for ONOS cord when running on podd')
    parser_run.add_argument('-service-profile', '--service-profile', default='', type=str,
                            help='Specify config location for ONOS cord service profile when running on podd.'
                            'Eg: $HOME/service-profile/cord-pod')
    parser_run.add_argument('-synchronizer', '--synchronizer', default='', type=str,
                            help='Specify the synchronizer to use for ONOS cord instance when running on podd.'
                            'Eg: vtn,fabric,cord')
    parser_run.add_argument('-karaf', '--karaf', default='3.0.8', type=str, help='Karaf version for ONOS')
    parser_run.add_argument('-voltha-loc', '--voltha-loc', default='', type=str,
                            help='Specify the voltha location in order to start voltha')
    parser_run.add_argument('-voltha-intf', '--voltha-intf', default='eth0', type=str,
                            help='Specify the voltha interface for voltha to listen')
    parser_run.add_argument('-voltha-enable', '--voltha-enable', action='store_true',
                            help='Run the tests with voltha environment enabled')
    parser_run.add_argument('-voltha-container-mode', '--voltha-container-mode', action='store_true',
                            help='Run the tests with voltha container environment enabled')
    parser_run.add_argument('-expose-port', '--expose-port', action='store_true',
                            help='Start ONOS by exposing the controller ports to the host.'
                            'Add +1 for every other onos/cluster instance when running more than 1 ONOS instances')
    parser_run.add_argument('-skip-onos-restart', '--skip-onos-restart', action='store_true',
                            help = 'Skips restarting/configuring of onoscord')
    parser_run.set_defaults(func=runTest)

    parser_setup = subparser.add_parser('setup', help='Setup cord tester environment')
    parser_setup.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser_setup.add_argument('-r', '--server', default=cord_test_server_address, type=str,
                              help='ip:port address for cord test server to listen for container restart requests')
    parser_setup.add_argument('-q', '--quagga',action='store_true',help='Provision quagga container for vrouter')
    parser_setup.add_argument('-a', '--app', default=onos_app_file, type=str, help='Cord ONOS app filename')
    parser_setup.add_argument('-e', '--test-controller', default='', type=str, help='External test controller ip for Onos and/or radius server. '
                        'Eg: 10.0.0.2/10.0.0.3 to specify ONOS and Radius ip to connect')
    parser_setup.add_argument('-u', '--update', default='none', choices=['quagga','radius', 'all'], type=str, help='Update cord tester container images. '
                        'Eg: --update=quagga to rebuild quagga image.'
                        '    --update=radius to rebuild radius server image.'
                        '    --update=all to rebuild all cord tester images.')
    parser_setup.add_argument('-d', '--dont-provision', action='store_true', help='Dont start test container.')
    parser_setup.add_argument('-l', '--olt', action='store_true', help='Use OLT config')
    parser_setup.add_argument('-olt-config', '--olt-config', default=olt_config_default, type=str, help='Provide OLT configuration')
    parser_setup.add_argument('-log', '--log-level', default=onos_log_level, type=str,
                              choices=['DEBUG','TRACE','ERROR','WARN','INFO'],
                              help='Specify the log level for the test cases')
    parser_setup.add_argument('-s', '--start-switch', action='store_true', help='Start OVS when running under OLT config')
    parser_setup.add_argument('-onos-cord', '--onos-cord', default='', type=str,
                              help='Specify config location for ONOS cord when running on podd')
    parser_setup.add_argument('-service-profile', '--service-profile', default='', type=str,
                              help='Specify config location for ONOS cord service profile when running on podd.'
                              'Eg: $HOME/service-profile/cord-pod')
    parser_setup.add_argument('-synchronizer', '--synchronizer', default='', type=str,
                              help='Specify the synchronizer to use for ONOS cord instance when running on podd.'
                              'Eg: vtn,fabric,cord')
    parser_setup.add_argument('-m', '--manifest', default='', type=str, help='Provide test configuration manifest')
    parser_setup.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_setup.add_argument('-i', '--identity-file', default=identity_file_default,
                              type=str, help='ssh identity file to access compute nodes from test container')
    parser_setup.add_argument('-n', '--onos-instances', default=1, type=int,
                              help='Specify number of test onos instances to spawn')
    parser_setup.add_argument('-v', '--shared-volume', action='store_true',
                              help='Start ONOS cluster instances with shared volume')
    parser_setup.add_argument('-async', '--async-mode', action='store_true',
                              help='Start ONOS cluster instances in async mode')
    parser_setup.add_argument('-f', '--foreground', action='store_true', help='Run in foreground')
    parser_setup.add_argument('-jvm-heap-size', '--jvm-heap-size', default='', type=str, help='ONOS JVM heap size')
    parser_setup.add_argument('-network', '--network', default='', type=str, help='Docker network to attach')
    parser_setup.add_argument('-karaf', '--karaf', default='3.0.8', type=str, help='Karaf version for ONOS')
    parser_setup.add_argument('-voltha-loc', '--voltha-loc', default='', type=str,
                              help='Specify the voltha location in order to start voltha')
    parser_setup.add_argument('-voltha-intf', '--voltha-intf', default='eth0', type=str,
                              help='Specify the voltha interface for voltha to listen')
    parser_setup.add_argument('-voltha-enable', '--voltha-enable', action='store_true',
                              help='Run the tests with voltha environment enabled')
    parser_setup.add_argument('-voltha-container-mode', '--voltha-container-mode', action='store_true',
                              help='Run the tests with voltha container environment enabled')
    parser_setup.add_argument('-expose-port', '--expose-port', action='store_true',
                              help='Start ONOS by exposing the controller ports to the host.'
                              'Add +1 for every other onos/cluster instance when running more than 1 ONOS instances')
    parser_setup.add_argument('-skip-onos-restart', '--skip-onos-restart', action='store_true',
                            help = 'Skips restarting/configuring of onoscord')
    parser_setup.set_defaults(func=setupCordTester)

    parser_xos = subparser.add_parser('xos', help='Building xos into cord tester environment')
    parser_xos.add_argument('command', choices=['build', 'update', 'start', 'stop'])
    parser_xos.add_argument('-p', '--profile', default='cord-pod', type=str, help='Provide service profile')
    parser_xos.set_defaults(func=xosCommand)

    parser_list = subparser.add_parser('list', help='List test cases')
    parser_list.add_argument('-t', '--test', default='all', help='Specify test type to list test cases. '
                             'Eg: -t tls to list tls test cases.'
                             '    -t tls-dhcp-vrouter to list tls,dhcp and vrouter test cases.'
                             '    -t all to list all test cases.')
    parser_list.set_defaults(func=listTests)

    parser_build = subparser.add_parser('build', help='Build cord test container images')
    parser_build.add_argument('image', choices=['quagga', 'radius', 'test','all'])
    parser_build.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_build.set_defaults(func=buildImages)

    parser_metrics = subparser.add_parser('metrics', help='Info of container')
    parser_metrics.add_argument("container", help="Container name")
    parser_metrics.set_defaults(func=getMetrics)

    parser_start = subparser.add_parser('start', help='Start cord tester containers')
    parser_start.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_start.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser_start.add_argument('image', choices=['onos', 'quagga', 'radius', 'all'])
    parser_start.set_defaults(func=startImages)

    parser_cleanup = subparser.add_parser('cleanup', help='Cleanup test containers')
    parser_cleanup.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_cleanup.add_argument('-l', '--olt', action = 'store_true', help = 'Cleanup OLT config')
    parser_cleanup.add_argument('-olt-config', '--olt-config', default=olt_config_default, type=str, help='Provide OLT configuration')
    parser_cleanup.add_argument('-o', '--onos', default=onos_image_default, type=str,
                                help='ONOS container image to cleanup')
    parser_cleanup.add_argument('-x', '--xos', action='store_true',
                                help='Cleanup XOS containers')
    parser_cleanup.add_argument('-r', '--server', default=cord_test_server_address, type=str,
                                help='ip:port address for cord test server to cleanup')
    parser_cleanup.add_argument('-e', '--test-controller', default='', type=str,
                                help='External test controller ip for Onos and/or radius server. '
                                'Eg: 10.0.0.2/10.0.0.3 to specify ONOS and Radius ip')
    parser_cleanup.add_argument('-onos-cord', '--onos-cord', default='', type=str,
                                help='Specify config location for ONOS cord instance when running on podd to restore')
    parser_cleanup.add_argument('-service-profile', '--service-profile', default='', type=str,
                                help='Specify config location for ONOS cord service profile when running on podd.'
                                'Eg: $HOME/service-profile/cord-pod')
    parser_cleanup.add_argument('-synchronizer', '--synchronizer', default='', type=str,
                                help='Specify the synchronizer to use for ONOS cord instance when running on podd.'
                                'Eg: vtn,fabric,cord')
    parser_cleanup.add_argument('-m', '--manifest', default='', type=str, help='Provide test manifest')
    parser_cleanup.add_argument('-voltha-loc', '--voltha-loc', default='', type=str,
                                help='Specify the voltha location')
    parser_cleanup.add_argument('-skip-onos-restart', '--skip-onos-restart', action='store_true',
                            help = 'Skips restarting/configuring of onoscord')
    parser_cleanup.set_defaults(func=cleanupTests)

    c = Client(**(kwargs_from_env()))

    args = parser.parse_args()
    res = args.func(args)
    sys.exit(res)
