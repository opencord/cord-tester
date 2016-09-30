#!/usr/bin/env python
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
from argparse import ArgumentParser
import os,sys,time,socket,errno
import shutil, platform, re
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
sys.path.append(utils_dir)
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from threadPool import ThreadPool
from CordContainer import *
from CordTestServer import cord_test_server_start,cord_test_server_stop,cord_test_server_shutdown,CORD_TEST_HOST,CORD_TEST_PORT
from TestManifest import TestManifest
from docker import Client
from docker.utils import kwargs_from_env

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
    IMAGE = 'cord-test/nose'
    ALL_TESTS = ('tls', 'dhcp', 'dhcprelay','igmp', 'subscriber',
    'cordSubscriber', 'vrouter', 'flows', 'proxyarp', 'acl', 'xos', 'fabric',
    'cbench', 'cluster')

    def __init__(self, tests, instance = 0, num_instances = 1, ctlr_ip = None,
                 name = '', image = IMAGE, prefix = '', tag = 'candidate',
                 env = None, rm = False, update = False):
        self.tests = tests
        self.ctlr_ip = ctlr_ip
        self.rm = rm
        self.name = name or self.get_name()
        super(CordTester, self).__init__(self.name, image = image, prefix = prefix, tag = tag)
        host_config = self.create_host_config(host_guest_map = self.host_guest_map, privileged = True)
        volumes = []
        for _, g in self.host_guest_map:
            volumes.append(g)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
        self.create = True
        #check if are trying to run tests on existing container
        if not name or not self.exists():
            ##Remove test container if any
            self.remove_container(self.name, force=True)
        else:
            self.create = False
        self.olt = False
        if env is not None and env.has_key('OLT_CONFIG'):
            self.olt = True
        olt_conf_file = os.path.join(self.tester_base, 'olt_config.json')
        olt_config = OltConfig(olt_conf_file)
        self.port_map, _ = olt_config.olt_port_map()
        #Try using the host interface in olt conf to setup the switch
        if self.port_map.has_key('host'):
            self.switch = self.port_map['host']
        else:
            self.switch = 'ovsbr0'
        if env is not None:
            env['TEST_SWITCH'] = self.switch
            env['TEST_HOST'] = self.name
            env['TEST_INSTANCE'] = instance
            env['TEST_INSTANCES'] = num_instances
        if self.create:
            print('Starting test container %s, image %s, tag %s' %(self.name, self.image, self.tag))
            self.start(rm = False, volumes = volumes, environment = env,
                       host_config = host_config, tty = True)

    def execute_switch(self, cmd, shell = False):
        if self.olt:
            return os.system(cmd)
        return self.execute(cmd, shell = shell)

    def start_switch(self, boot_delay = 2):
        """Start OVS"""
        ##Determine if OVS has to be started locally or not
        s_file,s_sandbox = ('of-bridge-local.sh',self.tester_base) if self.olt else ('of-bridge.sh',self.sandbox_setup)
        ovs_cmd = os.path.join(s_sandbox, s_file) + ' {0}'.format(self.switch)
        if self.olt:
            if CordTester.switch_on_olt is True:
                return
            CordTester.switch_on_olt = True
            ovs_cmd += ' {0}'.format(self.ctlr_ip)
            print('Starting OVS on the host with controller: %s' %(self.ctlr_ip))
        else:
            print('Starting OVS on test container %s' %self.name)
        self.execute_switch(ovs_cmd)
        status = 1
        ## Wait for the LLDP flows to be added to the switch
        tries = 0
        while status != 0 and tries < 200:
            cmd = 'sudo ovs-ofctl dump-flows {0} | grep \"type=0x8942\"'.format(self.switch)
            status = self.execute_switch(cmd, shell = True)
            tries += 1
            if tries % 10 == 0:
                print('Waiting for test switch to be connected to ONOS controller ...')

        if status != 0:
            print('Test Switch not connected to ONOS container.'
                  'Please remove ONOS container and restart the test')
            if self.rm:
                self.kill()
            sys.exit(1)

        if boot_delay:
            time.sleep(boot_delay)

    def setup_intfs(self, port_num = 0):
        tester_intf_subnet = '192.168.100'
        res = 0
        host_intf = self.port_map['host']
        start_vlan = self.port_map['start_vlan']
        start_vlan += port_num
        uplink = self.port_map['uplink']
        wan = self.port_map['wan']
        port_list = self.port_map['ports'] + self.port_map['relay_ports']
        for port in port_list:
            guest_if = port
            local_if = '{0}_{1}'.format(guest_if, port_num+1)
            guest_ip = '{0}.{1}/24'.format(tester_intf_subnet, port_num+1)
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

            res += os.system(pipework_cmd)
            port_num += 1

        return res, port_num

    @classmethod
    def cleanup_intfs(cls):
        olt_conf_file = os.path.join(cls.tester_base, 'olt_config.json')
        olt_config = OltConfig(olt_conf_file)
        port_map, _ = olt_config.olt_port_map()
        port_num = 0
        intf_host = port_map['host']
        start_vlan = port_map['start_vlan']
        uplink = port_map['uplink']
        wan = port_map['wan']
        intf_type = 0
        if os.path.isdir('/sys/class/net/{}/bridge'.format(intf_host)):
            intf_type = 1 ##linux bridge
        else:
            cmd = 'ovs-vsctl list-br | grep -q "^{0}$"'.format(intf_host)
            res = os.system(cmd)
            if res == 0: ##ovs bridge
                intf_type = 2
        cmds = ()
        res = 0
        for port in port_map['ports']:
            local_if = '{0}_{1}'.format(port, port_num+1)
            if wan and port_map[uplink] == port:
                    continue
            if intf_type == 0:
                if start_vlan != 0:
                    cmds = ('ip link del {}.{}'.format(intf_host, start_vlan),)
                    start_vlan += 1
            else:
                if intf_type == 1:
                    cmds = ('brctl delif {} {}'.format(intf_host, local_if),
                            'ip link del {}'.format(local_if))
                else:
                    cmds = ('ovs-vsctl del-port {} {}'.format(intf_host, local_if),)

            for cmd in cmds:
                res += os.system(cmd)

            port_num += 1

    @classmethod
    def get_name(cls):
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
        python-paramiko python-maas-client
RUN easy_install nose
RUN mkdir -p /root/ovs
WORKDIR /root
RUN wget http://openvswitch.org/releases/openvswitch-{}.tar.gz -O /root/ovs/openvswitch-{}.tar.gz && \
(cd /root/ovs && tar zxpvf openvswitch-{}.tar.gz && \
 cd openvswitch-{} && \
 ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && make && make install)
RUN service openvswitch-switch restart || /bin/true
RUN pip install -U scapy scapy-ssl_tls monotonic configObj docker-py pyyaml nsenter pyroute2 netaddr python-daemon
RUN mv /usr/sbin/tcpdump /sbin/
RUN ln -sf /sbin/tcpdump /usr/sbin/tcpdump
RUN mv /usr/sbin/dhcpd /sbin/
RUN ln -sf /sbin/dhcpd /usr/sbin/dhcpd
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
onos_app_version = '2.0-SNAPSHOT'
cord_tester_base = os.path.dirname(os.path.realpath(__file__))
onos_app_file = os.path.abspath('{0}/../apps/ciena-cordigmp-'.format(cord_tester_base) + onos_app_version + '.oar')
cord_test_server_address = '{}:{}'.format(CORD_TEST_HOST, CORD_TEST_PORT)
identity_file_default = '/etc/maas/ansible/id_rsa'

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

def runTest(args):
    #Start the cord test tcp server
    test_server_params = args.server.split(':')
    test_host = test_server_params[0]
    test_port = CORD_TEST_PORT
    if len(test_server_params) > 1:
        test_port = int(test_server_params[1])
    try:
        test_server = cord_test_server_start(daemonize = False, cord_test_host = test_host, cord_test_port = test_port)
    except:
        ##Most likely a server instance is already running (daemonized earlier)
        test_server = None

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

    onos_ip = None
    radius_ip = None
    head_node = platform.node()
    use_manifest = False
    if args.manifest:
        if os.access(args.manifest, os.F_OK):
            ##copy it to setup directory
            dest = os.path.join(CordTester.tester_base, 'manifest.json')
            if os.path.abspath(args.manifest) != dest:
                try:
                    shutil.copy(args.manifest, dest)
                except: pass
            test_manifest = TestManifest(dest)
            onos_ip = test_manifest.onos_ip
            radius_ip = test_manifest.radius_ip
            head_node = test_manifest.head_node
            use_manifest = True
        else:
            print('Unable to access test manifest: %s' %args.manifest)

    #don't spawn onos if the user has specified external test controller with test interface config
    if args.test_controller:
        ips = args.test_controller.split('/')
        onos_ip = ips[0]
        if len(ips) > 1:
            radius_ip = ips[1]
        else:
            radius_ip = None

    Container.IMAGE_PREFIX = args.prefix
    if onos_ip is None:
        image_names = args.onos.rsplit(':', 1)
        onos_cnt['image'] = image_names[0]
        if len(image_names) > 1:
            if image_names[1].find('/') < 0:
                onos_cnt['tag'] = image_names[1]
            else:
                #tag cannot have slashes
                onos_cnt['image'] = args.onos

        Onos.IMAGE = onos_cnt['image']
        Onos.PREFIX = args.prefix
        Onos.TAG = onos_cnt['tag']
        onos = Onos(image = Onos.IMAGE,
                    tag = Onos.TAG, boot_delay = 60)
        onos_ip = onos.ip()

    print('Onos IP %s, Test type %s' %(onos_ip, args.test_type))
    if use_manifest or args.test_controller:
        print('Installing ONOS cord apps')
        try:
            Onos.install_cord_apps(onos_ip = onos_ip)
        except: pass

    print('Installing cord tester ONOS app %s' %args.app)
    try:
        OnosCtrl.install_app(args.app, onos_ip = onos_ip)
    except: pass

    if radius_ip is None:
        ##Start Radius container
        radius = Radius(prefix = Container.IMAGE_PREFIX, update = update_map['radius'])
        radius_ip = radius.ip()

    print('Radius server running with IP %s' %radius_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(prefix = Container.IMAGE_PREFIX, update = update_map['quagga'])

    try:
        maas_api_key = FabricMAAS.get_api_key()
    except:
        maas_api_key = 'UNKNOWN'

    ssh_key_file = set_ssh_key_file(args.identity_file)
    test_cnt_env = { 'ONOS_CONTROLLER_IP' : onos_ip,
                     'ONOS_AAA_IP' : radius_ip if radius_ip is not None else '',
                     'QUAGGA_IP': test_host,
                     'CORD_TEST_HOST' : test_host,
                     'CORD_TEST_PORT' : test_port,
                     'ONOS_RESTART' : 0 if args.olt and args.test_controller else 1,
                     'MANIFEST': int(use_manifest),
                     'HEAD_NODE': head_node if head_node else CORD_TEST_HOST,
                     'MAAS_API_KEY': maas_api_key
                   }

    if ssh_key_file:
        test_cnt_env['SSH_KEY_FILE'] = ssh_key_file

    if args.olt:
        olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
        test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

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
    test_slice_start = 0
    test_slice_end = test_slice_start + tests_per_container
    num_test_containers = min(num_tests, args.num_containers)
    if tests_parallel:
        print('Running %s tests across %d containers in parallel' %(tests_parallel, num_test_containers))
    for container in range(num_test_containers):
        test_cnt = CordTester(tests_parallel[test_slice_start:test_slice_end],
                              instance = container, num_instances = num_test_containers,
                              ctlr_ip = onos_ip,
                              name = args.container,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'])
        test_slice_start = test_slice_end
        test_slice_end = test_slice_start + tests_per_container
        update_map['test'] = False
        test_containers.append(test_cnt)
        if not test_cnt.create:
            continue
        if test_cnt.create and (args.start_switch or not args.olt):
            if not args.no_switch:
                test_cnt.start_switch()
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
                              ctlr_ip = onos_ip,
                              name = args.container,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'])
        if test_cnt.create and (args.start_switch or not args.olt):
            #For non parallel tests, we just restart the switch also for OLT's
            CordTester.switch_on_olt = False
            if not args.no_switch:
                test_cnt.start_switch()
        if test_cnt.create and test_cnt.olt:
            test_cnt.setup_intfs(port_num = port_num)
        test_cnt.run_tests()

    if test_server:
        cord_test_server_stop(test_server)

    return status

##Starts onos/radius/quagga containers as appropriate
def setupCordTester(args):
    onos_cnt = {'tag':'latest'}
    nose_cnt = {'image': CordTester.IMAGE, 'tag': 'candidate'}
    update_map = { 'quagga' : False, 'radius' : False, 'test': False }
    update_map[args.update.lower()] = True

    if args.update.lower() == 'all':
       for c in update_map.keys():
           update_map[c] = True

    onos_ip = None
    radius_ip = None
    onos_cord_loc = args.onos_cord
    if onos_cord_loc:
        if onos_cord_loc.find(os.path.sep) < 0:
            onos_cord_loc = os.path.join(os.getenv('HOME'), onos_cord_loc)
        if not os.access(onos_cord_loc, os.F_OK):
            print('ONOS cord config location %s is not accessible' %onos_cord_loc)
            sys.exit(1)
        #Disable test container provisioning on the ONOS compute node
        args.dont_provision = True

    head_node = platform.node()
    use_manifest = False
    if args.manifest:
        if os.access(args.manifest, os.F_OK):
            ##copy it to setup directory
            dest = os.path.join(CordTester.tester_base, 'manifest.json')
            if os.path.abspath(args.manifest) != dest:
                try:
                    shutil.copy(args.manifest, dest)
                except: pass
            test_manifest = TestManifest(dest)
            onos_ip = test_manifest.onos_ip
            radius_ip = test_manifest.radius_ip
            head_node = test_manifest.head_node
            use_manifest = True

    ##If onos/radius was already started
    if args.test_controller:
        ips = args.test_controller.split('/')
        onos_ip = ips[0]
        if len(ips) > 1:
            radius_ip = ips[1]
        else:
            radius_ip = None

    onos_cord = None
    if onos_cord_loc:
        if not args.test_controller:
            ##Unexpected case. Specify the external controller ip when running on cord node
            print('Specify ONOS ip using \"-e\" option when running the cord-tester on cord node')
            sys.exit(1)
        onos_cord = OnosCord(onos_ip, onos_cord_loc)

    Container.IMAGE_PREFIX = args.prefix
    #don't spawn onos if the user had started it externally
    image_names = args.onos.rsplit(':', 1)
    onos_cnt['image'] = image_names[0]
    if len(image_names) > 1:
        if image_names[1].find('/') < 0:
            onos_cnt['tag'] = image_names[1]
        else:
            #tag cannot have slashes
            onos_cnt['image'] = args.onos

    Onos.IMAGE = onos_cnt['image']
    Onos.PREFIX = args.prefix
    Onos.TAG = onos_cnt['tag']
    cluster_mode = True if args.onos_instances > 1 else False
    onos = None
    if onos_ip is None:
        onos = Onos(image = Onos.IMAGE, tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode)
        onos_ip = onos.ip()

    num_onos_instances = args.onos_instances
    onos_ips = [ onos_ip ]
    if num_onos_instances > 1 and onos is not None:
        onos_instances = []
        onos_instances.append(onos)
        for i in range(1, num_onos_instances):
            name = '{}-{}'.format(Onos.NAME, i+1)
            onos = Onos(name = name, image = Onos.IMAGE, tag = Onos.TAG, boot_delay = 60, cluster = cluster_mode)
            onos_instances.append(onos)
            onos_ips.append(onos.ipaddr)
        Onos.setup_cluster(onos_instances)

    ctlr_addr = ','.join(onos_ips)
    print('Onos IP %s' %ctlr_addr)
    if use_manifest or args.test_controller:
        print('Installing ONOS cord apps')
        try:
            Onos.install_cord_apps(onos_ip = onos_ip)
        except: pass

    print('Installing cord tester ONOS app %s' %args.app)
    try:
        for ip in onos_ips:
            OnosCtrl.install_app(args.app, onos_ip = ip)
    except: pass

    ##Start Radius container if not started
    if radius_ip is None:
        radius = Radius(prefix = Container.IMAGE_PREFIX, update = update_map['radius'])
        radius_ip = radius.ip()

    print('Radius server running with IP %s' %radius_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(prefix = Container.IMAGE_PREFIX, update = update_map['quagga'])
        print('Quagga started')

    params = args.server.split(':')
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
                         'ONOS_RESTART' : 0 if args.olt and args.test_controller else 1,
                         'MANIFEST': int(use_manifest),
                         'HEAD_NODE': head_node if head_node else CORD_TEST_HOST,
                         'MAAS_API_KEY': maas_api_key
                       }

        if ssh_key_file:
            test_cnt_env['SSH_KEY_FILE'] = ssh_key_file
        if args.olt:
            olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
            test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

        test_cnt = CordTester((),
                              ctlr_ip = ctlr_addr,
                              image = nose_cnt['image'],
                              prefix = Container.IMAGE_PREFIX,
                              tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False,
                              update = update_map['test'])

        if args.start_switch or not args.olt:
            test_cnt.start_switch()
        if test_cnt.olt:
            test_cnt.setup_intfs(port_num = 0)
        print('Test container %s started and provisioned to run tests using nosetests' %(test_cnt.name))

    #Finally start the test server and daemonize
    try:
        cord_test_server_start(daemonize = True, cord_test_host = ip, cord_test_port = port,
                               onos_cord = onos_cord)
    except socket.error, e:
        #the test agent address could be remote or already running. Exit gracefully
        sys.exit(0)

    return 0

def cleanupTests(args):
    image_name = args.onos
    prefix = args.prefix
    if prefix:
        prefix += '/'
    test_container = '{}{}:candidate'.format(prefix, CordTester.IMAGE)
    print('Cleaning up Test containers ...')
    Container.cleanup(test_container)
    if args.olt:
        print('Cleaning up test container OLT configuration')
        CordTester.cleanup_intfs()

    onos_list = [ c['Names'][0][1:] for c in Container.dckr.containers() if c['Image'] == image_name ]
    if len(onos_list) > 1:
        for onos in onos_list:
            Container.dckr.kill(onos)
            Container.dckr.remove_container(onos, force=True)
        Onos.cleanup_runtime()
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

def xosContainers(args):
    update_map = {  'xos-server' : False, 'xos-synchronizer-openstack' : False, 'openvpn' : False, 'postgresql' :False,
                    'syndicate-ms': False, 'xos-synchronizer-onboarding' : False }

    if args.xosAllContainers == True or args.xosServer == True:
        xosServer = XosServer(prefix = Container.IMAGE_PREFIX, update = update_map['xos-server'])

    if args.xosAllContainers == True or args.xosSyncOpenstack == True:
        #Start xos base container. Builds container if required
        xosSyncOpenstack = XosSynchronizerOpenstack(prefix = Container.IMAGE_PREFIX,
                                                    update = update_map['xos-synchronizer-openstack'])

    if args.xosAllContainers == True or args.xosOpenvpn == True:
        xosOpenvpn = XosSynchronizerOpenvpn(prefix = Container.IMAGE_PREFIX, update = update_map['openvpn'])

    if args.xosAllContainers == True or args.xosPostgresql == True:
        xosPostgresql = XosPostgresql(prefix = Container.IMAGE_PREFIX, update = update_map['postgresql'])

    if args.xosAllContainers == True or args.xosSyndicateMs == True:
        #Start xos syndicateMs container. Builds container if required
        xosSyndicateMs = XosSyndicateMs(prefix = Container.IMAGE_PREFIX, update = update_map['syndicate-ms'])

    if args.xosAllContainers == True or args.xosSyncOnboarding == True:
        #Start xos synchronizer Onboarding container. Builds container if required
        xosSyncOnboarding = XosSynchronizerOnboarding(prefix = Container.IMAGE_PREFIX,
                                                      update = update_map['xos-synchronizer-onboarding'])

    print('Done building xos containers')
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
    parser_setup.add_argument('-s', '--start-switch', action='store_true', help='Start OVS when running under OLT config')
    parser_setup.add_argument('-c', '--onos-cord', default='', type=str,
                              help='Specify cord location for ONOS cord when running on podd')
    parser_setup.add_argument('-m', '--manifest', default='', type=str, help='Provide test configuration manifest')
    parser_setup.add_argument('-p', '--prefix', default='', type=str, help='Provide container image prefix')
    parser_setup.add_argument('-i', '--identity-file', default=identity_file_default,
                              type=str, help='ssh identity file to access compute nodes from test container')
    parser_setup.add_argument('-n', '--onos-instances', default=1, type=int,
                            help='Specify number of test onos instances to spawn')
    parser_setup.set_defaults(func=setupCordTester)

    parser_xos = subparser.add_parser('xos', help='Building xos into cord tester environment')
    parser_xos.add_argument('-x', '--xosAllContainers', action='store_true',help='Provision all containers of XOS for CORD')
    parser_xos.add_argument('-xserver', '--xosServer',action='store_true',help='Provision xos server container')
    parser_xos.add_argument('-xsos', '--xosSyncOpenstack',action='store_true',help='Provision xos synchronizer openstack container')
    parser_xos.add_argument('-xo', '--xosOpenvpn',action='store_true',help='Provision xos openvpn container')
    parser_xos.add_argument('-xp', '--xosPostgresql',action='store_true',help='Provision xos postgresql')
    parser_xos.add_argument('-xs', '--xosSynchronizer',action='store_true',help='Provision xos synchronizer')
    parser_xos.add_argument('-xsm', '--xosSyndicateMs',action='store_true',help='Provision xos syndicate-ms')
    parser_xos.add_argument('-xsonb', '--xosSyncOnboarding',action='store_true',help='Provision xos synchronizer onboarding container')
    parser_xos.set_defaults(func=xosContainers)

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
    parser_cleanup.add_argument('-o', '--onos', default=onos_image_default, type=str,
                                help='ONOS container image to cleanup')
    parser_cleanup.add_argument('-x', '--xos', action='store_true',
                                help='Cleanup XOS containers')
    parser_cleanup.add_argument('-r', '--server', default=cord_test_server_address, type=str,
                                help='ip:port address for cord test server to cleanup')
    parser_cleanup.set_defaults(func=cleanupTests)

    c = Client(**(kwargs_from_env()))

    args = parser.parse_args()
    res = args.func(args)
    sys.exit(res)
