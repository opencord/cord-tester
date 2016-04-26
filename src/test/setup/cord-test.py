#!/usr/bin/env python
from argparse import ArgumentParser
import os,sys,time
utils_dir = os.path.join( os.path.dirname(os.path.realpath(__file__)), '../utils')
sys.path.append(utils_dir)
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig
from CordContainer import *
from CordTestServer import cord_test_server_start, cord_test_server_stop

test_server = cord_test_server_start()

class CordTester(Container):
    sandbox = '/root/test'
    sandbox_setup = '/root/test/src/test/setup'
    tester_base = os.path.dirname(os.path.realpath(__file__))
    tester_paths = os.path.realpath(__file__).split(os.path.sep)
    tester_path_index = tester_paths.index('cord-tester')
    sandbox_host = os.path.sep.join(tester_paths[:tester_path_index+1])

    host_guest_map = ( (sandbox_host, sandbox),
                       ('/lib/modules', '/lib/modules'),
                       ('/var/run/docker.sock', '/var/run/docker.sock')
                       )
    basename = 'cord-tester'

    def __init__(self, ctlr_ip = None, image = 'cord-test/nose', tag = 'latest',
                 env = None, rm = False, update = False):
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
        while status != 0 and tries < 100:
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

    def setup_intfs(self):
        if not self.olt:
            return 0
        tester_intf_subnet = '192.168.100'
        res = 0
        port_num = 0
        host_intf = self.port_map['host']
        start_vlan = self.port_map['start_vlan']
        for port in self.port_map['ports']:
            guest_if = port
            local_if = guest_if
            guest_ip = '{0}.{1}/24'.format(tester_intf_subnet, str(port_num+1))
            ##Use pipeworks to configure container interfaces on host/bridge interfaces
            pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4}'.format(host_intf, guest_if, local_if, self.name, guest_ip)
            if start_vlan != 0:
                pipework_cmd += ' @{}'.format(str(start_vlan + port_num))
                
            res += os.system(pipework_cmd)
            port_num += 1

        return res

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
        dockerfile = '''
FROM ubuntu:14.04
MAINTAINER chetan@ciena.com
RUN apt-get update 
RUN apt-get -y install git python python-pip python-setuptools python-scapy tcpdump doxygen doxypy wget
RUN easy_install nose
RUN apt-get -y install openvswitch-common openvswitch-switch
RUN mkdir -p /root/ovs
WORKDIR /root
RUN wget http://openvswitch.org/releases/openvswitch-2.4.0.tar.gz -O /root/ovs/openvswitch-2.4.0.tar.gz && \
(cd /root/ovs && tar zxpvf openvswitch-2.4.0.tar.gz && \
 cd openvswitch-2.4.0 && \
 ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-ssl && make && make install)
RUN service openvswitch-switch restart || /bin/true
RUN apt-get -y install python-twisted python-sqlite sqlite3 python-pexpect telnet
RUN pip install scapy-ssl_tls
RUN pip install -U scapy
RUN pip install monotonic
RUN pip install configObj
RUN pip install -U docker-py
RUN pip install -U pyyaml
RUN pip install -U nsenter
RUN pip install -U pyroute2
RUN pip install -U netaddr
RUN apt-get -y install arping
RUN mv /usr/sbin/tcpdump /sbin/
RUN ln -sf /sbin/tcpdump /usr/sbin/tcpdump
CMD ["/bin/bash"]
'''
        super(CordTester, cls).build_image(dockerfile, image)
        print('Done building docker image %s' %image)

    def run_tests(self, tests):
        '''Run the list of tests'''
        for t in tests:
            test = t.split(':')[0]
            if test == 'tls':
                test_file = test + 'AuthTest.py'
            else:
                test_file = test + 'Test.py'

            if t.find(':') >= 0:
                test_case = test_file + ':' + t.split(':')[1]
            else:
                test_case = test_file
            cmd = 'nosetests -v {0}/src/test/{1}/{2}'.format(self.sandbox, test, test_case)
            status = self.execute(cmd, shell = True)
            print('Test %s %s' %(test_case, 'Success' if status == 0 else 'Failure'))
        print('Done running tests')
        if self.rm:
            print('Removing test container %s' %self.name)
            self.kill(remove=True)

##default onos/radius/test container images and names
onos_image_default='onosproject/onos:latest'
nose_image_default='cord-test/nose:latest'
test_type_default='dhcp'
onos_app_version = '1.0-SNAPSHOT'
cord_tester_base = os.path.dirname(os.path.realpath(__file__))
onos_app_file = os.path.abspath('{0}/../apps/ciena-cordigmp-'.format(cord_tester_base) + onos_app_version + '.oar')

def runTest(args):
    global test_server
    onos_cnt = {'tag':'latest'}
    radius_cnt = {'tag':'latest'}
    nose_cnt = {'image': 'cord-test/nose','tag': 'latest'}
    radius_ip = None
    quagga_ip = None
    if args.cleanup:
        cleanup_container = args.cleanup
        if cleanup_container.find(':') < 0:
            cleanup_container += ':latest'
        print('Cleaning up containers %s' %cleanup_container)
        Container.cleanup(cleanup_container)
        sys.exit(0)

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

        ##Start Radius container if specified
        if args.radius:
            radius_cnt['image'] = args.radius.split(':')[0]
            if args.radius.find(':') >= 0:
                radius_cnt['tag'] = args.radius.split(':')[1]
            radius = Radius(image = radius_cnt['image'], tag = radius_cnt['tag'])
            radius_ip = radius.ip()
            print('Started Radius server with IP %s' %radius_ip)
        else:
            radius_ip = None
            
    print('Onos IP %s, Test type %s' %(onos_ip, args.test_type))
    print('Installing ONOS app %s' %onos_app_file)
    OnosCtrl.install_app(args.app, onos_ip = onos_ip)
    
    if args.quagga == True:
        #Start quagga. Builds container if required
        quagga = Quagga()
        quagga_ip = quagga.ip()
        
    test_cnt_env = { 'ONOS_CONTROLLER_IP' : onos_ip,
                     'ONOS_AAA_IP' : radius_ip if radius_ip is not None else '',
                     'QUAGGA_IP': quagga_ip if quagga_ip is not None else '',
                   }
    if args.olt:
        olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
        test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

    test_cnt = CordTester(ctlr_ip = onos_ip, image = nose_cnt['image'], tag = nose_cnt['tag'],
                          env = test_cnt_env,
                          rm = False if args.keep else True,
                          update = args.update)
    if args.start_switch or not args.olt:
        test_cnt.start_switch()
    test_cnt.setup_intfs()
    tests = args.test_type.split('-')
    test_cnt.run_tests(tests)
    cord_test_server_stop(test_server)

if __name__ == '__main__':
    parser = ArgumentParser(description='Cord Tester')
    parser.add_argument('-t', '--test-type', default=test_type_default, type=str)
    parser.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser.add_argument('-r', '--radius',default='',type=str, help='Radius container image')
    parser.add_argument('-q', '--quagga',action='store_true',help='Provision quagga container for vrouter')
    parser.add_argument('-a', '--app', default=onos_app_file, type=str, help='Cord ONOS app filename')
    parser.add_argument('-l', '--olt', action='store_true', help='Use OLT config')
    parser.add_argument('-e', '--test-controller', default='', type=str, help='External test controller ip for Onos and/or radius server.'
                        'Eg: 10.0.0.2/10.0.0.3 to specify ONOS and Radius ip to connect')
    parser.add_argument('-c', '--cleanup', default='', type=str, help='Cleanup test containers')
    parser.add_argument('-k', '--keep', action='store_true', help='Keep test container after tests')
    parser.add_argument('-s', '--start-switch', action='store_true', help='Start OVS when running under OLT config')
    parser.add_argument('-u', '--update', action='store_true', help='Update test container image')
    parser.set_defaults(func=runTest)
    args = parser.parse_args()
    args.func(args)
