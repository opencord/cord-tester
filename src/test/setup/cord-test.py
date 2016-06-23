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
import os,sys,time
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
sys.path.append(utils_dir)
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from threadPool import ThreadPool
from CordContainer import *
from CordTestServer import cord_test_server_start, cord_test_server_stop, CORD_TEST_HOST, CORD_TEST_PORT

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
    IMAGE = 'cord-test/nose'
    ALL_TESTS = ('tls', 'dhcp', 'igmp', 'subscriber', 'vrouter', 'flows')

    def __init__(self, tests, instance = 0, num_instances = 1, ctlr_ip = None, image = IMAGE, tag = 'latest',
                 env = None, rm = False, update = False):
        self.tests = tests
        self.ctlr_ip = ctlr_ip
        self.rm = rm
        self.name = self.get_name()
        super(CordTester, self).__init__(self.name, image = image, tag = tag)
        host_config = self.create_host_config(host_guest_map = self.host_guest_map, privileged = True)
        volumes = []
        for _, g in self.host_guest_map:
            volumes.append(g)
        if update is True or not self.img_exists():
            self.build_image(image)
        ##Remove test container if any
        self.remove_container(self.name, force=True)
        if env is not None and env.has_key('OLT_CONFIG'):
            self.olt = True
            olt_conf_file = os.path.join(self.tester_base, 'olt_config.json')
            olt_config = OltConfig(olt_conf_file)
            self.port_map = olt_config.olt_port_map()
        else:
            self.olt = False
            self.port_map = None
        if env is not None:
            env['TEST_HOST'] = self.name
            env['TEST_INSTANCE'] = instance
            env['TEST_INSTANCES'] = num_instances
        print('Starting test container %s, image %s, tag %s' %(self.name, self.image, self.tag))
        self.start(rm = False, volumes = volumes, environment = env,
                   host_config = host_config, tty = True)

    def execute_switch(self, cmd, shell = False):
        if self.olt:
            return os.system(cmd)
        return self.execute(cmd, shell = shell)

    def start_switch(self, bridge = 'ovsbr0', boot_delay = 2):
        """Start OVS"""
        ##Determine if OVS has to be started locally or not
        s_file,s_sandbox = ('of-bridge-local.sh',self.tester_base) if self.olt else ('of-bridge.sh',self.sandbox_setup)
        ovs_cmd = os.path.join(s_sandbox, '{0}'.format(s_file)) + ' {0}'.format(bridge)
        if self.olt:
            ovs_cmd += ' {0}'.format(self.ctlr_ip)
            print('Starting OVS on the host')
        else:
            print('Starting OVS on test container %s' %self.name)
        self.execute_switch(ovs_cmd)
        status = 1
        ## Wait for the LLDP flows to be added to the switch
        tries = 0
        while status != 0 and tries < 200:
            cmd = 'sudo ovs-ofctl dump-flows {0} | grep \"type=0x8942\"'.format(bridge)
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
        for port in self.port_map['ports']:
            guest_if = port
            local_if = '{0}_{1}'.format(guest_if, port_num+1)
            guest_ip = '{0}.{1}/24'.format(tester_intf_subnet, port_num+1)
            ##Use pipeworks to configure container interfaces on host/bridge interfaces
            pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4}'.format(host_intf, guest_if, local_if, self.name, guest_ip)
            if start_vlan != 0:
                pipework_cmd += ' @{}'.format(start_vlan + port_num)

            res += os.system(pipework_cmd)
            port_num += 1

        return res, port_num

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
        python-twisted python-sqlite sqlite3 python-pexpect telnet arping
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
            print('Test %s %s' %(test_case, 'Success' if status == 0 else 'Failure'))
        print('Done running tests')
        if self.rm:
            print('Removing test container %s' %self.name)
            self.kill(remove=True)

    @classmethod
    def list_tests(cls, tests):
        print('Listing test cases')
        for test in tests:
            test_file = '{}Test.py'.format(test)
            cmd = 'nosetests -v --collect-only {0}/../{1}/{2}'.format(cls.tester_base, test, test_file)
            os.system(cmd)

##default onos/radius/test container images and names
onos_image_default='onosproject/onos:latest'
nose_image_default= '{}:latest'.format(CordTester.IMAGE)
test_type_default='dhcp'
onos_app_version = '2.0-SNAPSHOT'
cord_tester_base = os.path.dirname(os.path.realpath(__file__))
onos_app_file = os.path.abspath('{0}/../apps/ciena-cordigmp-'.format(cord_tester_base) + onos_app_version + '.oar')
cord_test_server_address = '{}:{}'.format(CORD_TEST_HOST, CORD_TEST_PORT)

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
    tests_exempt = ('vrouter',)
    if args.test_type.lower() == 'all':
        tests = CordTester.ALL_TESTS
        args.quagga = True
    else:
        tests = args.test_type.split('-')

    tests_parallel = [ t for t in tests if t.split(':')[0] not in tests_exempt ]
    tests_not_parallel = [ t for t in tests if t.split(':')[0] in tests_exempt ]
    onos_cnt = {'tag':'latest'}
    nose_cnt = {'image': CordTester.IMAGE, 'tag': 'latest'}
    update_map = { 'quagga' : False, 'test' : False, 'radius' : False }
    update_map[args.update.lower()] = True

    if args.update.lower() == 'all':
       for c in update_map.keys():
           update_map[c] = True

    radius_ip = None
    quagga_ip = None

    #don't spawn onos if the user has specified external test controller with test interface config
    if args.test_controller:
        ips = args.test_controller.split('/')
        onos_ip = ips[0]
        if len(ips) > 1:
            radius_ip = ips[1]
        else:
            radius_ip = None
    else:
        onos_cnt['image'] = args.onos.split(':')[0]
        if args.onos.find(':') >= 0:
            onos_cnt['tag'] = args.onos.split(':')[1]

        onos = Onos(image = onos_cnt['image'], tag = onos_cnt['tag'], boot_delay = 60)
        onos_ip = onos.ip()

        ##Start Radius container
        radius = Radius( update = update_map['radius'])
        radius_ip = radius.ip()
        print('Radius server running with IP %s' %radius_ip)

    print('Onos IP %s, Test type %s' %(onos_ip, args.test_type))
    print('Installing cord tester ONOS app %s' %onos_app_file)
    OnosCtrl.install_app(args.app, onos_ip = onos_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(update = update_map['quagga'])
        quagga_ip = quagga.ip()


    test_cnt_env = { 'ONOS_CONTROLLER_IP' : onos_ip,
                     'ONOS_AAA_IP' : radius_ip if radius_ip is not None else '',
                     'QUAGGA_IP': quagga_ip if quagga_ip is not None else '',
                     'CORD_TEST_HOST' : test_host,
                     'CORD_TEST_PORT' : test_port,
                   }
    if args.olt:
        olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
        test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

    port_num = 0
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
                              ctlr_ip = onos_ip, image = nose_cnt['image'], tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'])
        test_slice_start = test_slice_end
        test_slice_end = test_slice_start + tests_per_container
        update_map['test'] = False
        test_containers.append(test_cnt)
        if args.start_switch or not args.olt:
            test_cnt.start_switch()
        if test_cnt.olt:
            _, port_num = test_cnt.setup_intfs(port_num = port_num)

    thread_pool = ThreadPool(len(test_containers), queue_size = 1, wait_timeout=1)
    for test_cnt in test_containers:
        thread_pool.addTask(test_cnt.run_tests)
    thread_pool.cleanUpThreads()

    ##Run the linear tests
    if tests_not_parallel:
        test_cnt = CordTester(tests_not_parallel,
                              ctlr_ip = onos_ip, image = nose_cnt['image'], tag = nose_cnt['tag'],
                              env = test_cnt_env,
                              rm = False if args.keep else True,
                              update = update_map['test'])
        if args.start_switch or not args.olt:
            test_cnt.start_switch()
        if test_cnt.olt:
            test_cnt.setup_intfs(port_num = port_num)
        test_cnt.run_tests()

    if test_server:
        cord_test_server_stop(test_server)

##Starts onos/radius/quagga containers as appropriate
def setupCordTester(args):
    onos_cnt = {'tag':'latest'}
    nose_cnt = {'image': CordTester.IMAGE, 'tag': 'latest'}
    update_map = { 'quagga' : False, 'radius' : False, 'test': False }
    update_map[args.update.lower()] = True

    if args.update.lower() == 'all':
       for c in update_map.keys():
           update_map[c] = True

    onos_ip = None
    radius_ip = None
    quagga_ip = None

    ##If onos/radius was already started
    if args.test_controller:
        ips = args.test_controller.split('/')
        onos_ip = ips[0]
        if len(ips) > 1:
            radius_ip = ips[1]
        else:
            radius_ip = None

    #don't spawn onos if the user had started it externally
    onos_cnt['image'] = args.onos.split(':')[0]
    if args.onos.find(':') >= 0:
        onos_cnt['tag'] = args.onos.split(':')[1]

    if onos_ip is None:
        onos = Onos(image = onos_cnt['image'], tag = onos_cnt['tag'], boot_delay = 60)
        onos_ip = onos.ip()

    ##Start Radius container if not started
    if radius_ip is None:
        radius = Radius( update = update_map['radius'])
        radius_ip = radius.ip()

    print('Radius server running with IP %s' %radius_ip)
    print('Onos IP %s' %onos_ip)
    print('Installing cord tester ONOS app %s' %onos_app_file)
    OnosCtrl.install_app(args.app, onos_ip = onos_ip)

    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga(update = update_map['quagga'])
        quagga_ip = quagga.ip()
        print('Quagga running with IP %s' %quagga_ip)

    params = args.server.split(':')
    ip = params[0]
    port = CORD_TEST_PORT
    if len(params) > 1:
        port = int(params[1])

    #provision the test container
    if not args.dont_provision:
        test_cnt_env = { 'ONOS_CONTROLLER_IP' : onos_ip,
                         'ONOS_AAA_IP' : radius_ip,
                         'QUAGGA_IP': quagga_ip if quagga_ip is not None else '',
                         'CORD_TEST_HOST' : ip,
                         'CORD_TEST_PORT' : port,
                       }
        if args.olt:
            olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
            test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

        test_cnt = CordTester((),
                              ctlr_ip = onos_ip,
                              image = nose_cnt['image'],
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
    cord_test_server_start(daemonize = True, cord_test_host = ip, cord_test_port = port)

def cleanupTests(args):
    test_container = '{}:latest'.format(CordTester.IMAGE)
    print('Cleaning up Test containers ...')
    Container.cleanup(test_container)

def listTests(args):
    if args.test == 'all':
        tests = CordTester.ALL_TESTS
    else:
        tests = args.test.split('-')
    CordTester.list_tests(tests)

def buildImages(args):
    if args.image == 'all' or args.image == 'quagga':
        Quagga.build_image(Quagga.IMAGE)

    if args.image == 'all' or args.image == 'radius':
        Radius.build_image(Radius.IMAGE)

    if args.image == 'all' or args.image == 'test':
        CordTester.build_image(CordTester.IMAGE)

if __name__ == '__main__':
    parser = ArgumentParser(description='Cord Tester')
    subparser = parser.add_subparsers()
    parser_run = subparser.add_parser('run', help='Run cord tester')
    parser_run.add_argument('-t', '--test-type', default=test_type_default, help='Specify test type or test case to run')
    parser_run.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser_run.add_argument('-q', '--quagga',action='store_true',help='Provision quagga container for vrouter')
    parser_run.add_argument('-a', '--app', default=onos_app_file, type=str, help='Cord ONOS app filename')
    parser_run.add_argument('-p', '--olt', action='store_true', help='Use OLT config')
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
    parser_setup.add_argument('-p', '--olt', action='store_true', help='Use OLT config')
    parser_setup.add_argument('-s', '--start-switch', action='store_true', help='Start OVS when running under OLT config')
    parser_setup.set_defaults(func=setupCordTester)

    parser_list = subparser.add_parser('list', help='List test cases')
    parser_list.add_argument('-t', '--test', default='all', help='Specify test type to list test cases. '
                             'Eg: -t tls to list tls test cases.'
                             '    -t tls-dhcp-vrouter to list tls,dhcp and vrouter test cases.'
                             '    -t all to list all test cases.')
    parser_list.set_defaults(func=listTests)

    parser_build = subparser.add_parser('build', help='Build cord test container images')
    parser_build.add_argument('image', choices=['quagga', 'radius', 'test', 'all'])
    parser_build.set_defaults(func=buildImages)

    parser_cleanup = subparser.add_parser('cleanup', help='Cleanup test containers')
    parser_cleanup.set_defaults(func=cleanupTests)

    args = parser.parse_args()
    args.func(args)
