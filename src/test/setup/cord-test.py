#!/usr/bin/env python
from argparse import ArgumentParser
import os,sys,time
import io
import yaml
from pyroute2 import IPRoute
from itertools import chain
from nsenter import Namespace
from docker import Client
from shutil import copy
utils_dir = os.path.join( os.path.dirname(os.path.realpath(sys.argv[0])), '../utils')
sys.path.append(utils_dir)
from OnosCtrl import OnosCtrl
from OltConfig import OltConfig

class docker_netns(object):

    dckr = Client()
    def __init__(self, name):
        pid = int(self.dckr.inspect_container(name)['State']['Pid'])
        if pid == 0:
            raise Exception('no container named {0}'.format(name))
        self.pid = pid

    def __enter__(self):
        pid = self.pid
        if not os.path.exists('/var/run/netns'):
            os.mkdir('/var/run/netns')
        os.symlink('/proc/{0}/ns/net'.format(pid), '/var/run/netns/{0}'.format(pid))
        return str(pid)

    def __exit__(self, type, value, traceback):
        pid = self.pid
        os.unlink('/var/run/netns/{0}'.format(pid))

flatten = lambda l: chain.from_iterable(l)

class Container(object):
    dckr = Client()
    def __init__(self, name, image, tag = 'latest', command = 'bash', quagga_config = None):
        self.name = name
        self.image = image
        self.tag = tag
        self.image_name = image + ':' + tag
        self.id = None
        self.command = command
        if quagga_config is not None:
            self.bridge = quagga_config['bridge']
            self.ipaddress = quagga_config['ip']
            self.mask = quagga_config['mask']
        else:
            self.bridge = None
            self.ipaddress = None
            self.mask = None

    @classmethod
    def build_image(cls, dockerfile, tag, force=True, nocache=False):
        f = io.BytesIO(dockerfile.encode('utf-8'))
        if force or not cls.image_exists(tag):
            print('Build {0}...'.format(tag))
            for line in cls.dckr.build(fileobj=f, rm=True, tag=tag, decode=True, nocache=nocache):
                if 'stream' in line:
                    print(line['stream'].strip())

    @classmethod
    def image_exists(cls, name):
        return name in [ctn['RepoTags'][0] for ctn in cls.dckr.images()]

    @classmethod
    def create_host_config(cls, port_list = None, host_guest_map = None, privileged = False):
        port_bindings = None
        binds = None
        if port_list:
            port_bindings = {}
            for p in port_list:
                port_bindings[str(p)] = str(p)

        if host_guest_map:
            binds = []
            for h, g in host_guest_map:
                binds.append('{0}:{1}'.format(h, g))

        return cls.dckr.create_host_config(binds = binds, port_bindings = port_bindings, privileged = privileged)

    @classmethod
    def cleanup(cls, image):
        cnt_list = filter(lambda c: c['Image'] == image, cls.dckr.containers())
        for cnt in cnt_list:
            print('Cleaning container %s' %cnt['Id'])
            cls.dckr.kill(cnt['Id'])
            cls.dckr.remove_container(cnt['Id'], force=True)

    @classmethod
    def remove_container(cls, name, force=True):
        try:
            cls.dckr.remove_container(name, force = force)
        except: pass

    def exists(self):
        return '/{0}'.format(self.name) in list(flatten(n['Names'] for n in self.dckr.containers()))

    def img_exists(self):
        return self.image_name in [ctn['RepoTags'][0] for ctn in self.dckr.images()]

    def ip(self):
        cnt_list = filter(lambda c: c['Image'] == self.image_name, self.dckr.containers())
        cnt_settings = cnt_list.pop()
        return cnt_settings['NetworkSettings']['Networks']['bridge']['IPAddress']

    def kill(self, remove = True):
        self.dckr.kill(self.name)
        self.dckr.remove_container(self.name, force=True)

    def start(self, rm = True, ports = None, volumes = None, host_config = None, 
              environment = None, tty = False, stdin_open = True):

        if rm and self.exists():
            print('Removing container:', self.name)
            self.dckr.remove_container(self.name, force=True)

        ctn = self.dckr.create_container(image=self.image_name, ports = ports, command=self.command, 
                                         detach=True, name=self.name,
                                         environment = environment, 
                                         volumes = volumes, 
                                         host_config = host_config, stdin_open=stdin_open, tty = tty)
        self.dckr.start(container=self.name)
        if self.bridge:
            self.connect_to_br()
        self.id = ctn['Id']
        return ctn

    def connect_to_br(self):
        with docker_netns(self.name) as pid:
            ip = IPRoute()
            br = ip.link_lookup(ifname=self.bridge)
            if len(br) == 0:
                ip.link_create(ifname=self.bridge, kind='bridge')
                br = ip.link_lookup(ifname=self.bridge)
            br = br[0]
            ip.link('set', index=br, state='up')

            ifs = ip.link_lookup(ifname=self.name)
            if len(ifs) > 0:
               ip.link_remove(ifs[0])

            ip.link_create(ifname=self.name, kind='veth', peer=pid)
            host = ip.link_lookup(ifname=self.name)[0]
            ip.link('set', index=host, master=br)
            ip.link('set', index=host, state='up')
            guest = ip.link_lookup(ifname=pid)[0]
            ip.link('set', index=guest, net_ns_fd=pid)
            with Namespace(pid, 'net'):
                ip = IPRoute()
                ip.link('set', index=guest, ifname='eth1')
                ip.link('set', index=guest, state='up')
                ip.addr('add', index=guest, address=self.ipaddress, mask=self.mask)

    def execute(self, cmd, tty = True, stream = False, shell = False):
        res = 0
        if type(cmd) == str:
            cmds = (cmd,)
        else:
            cmds = cmd
        if shell:
            for c in cmds:
                res += os.system('docker exec {0} {1}'.format(self.name, c))
            return res
        for c in cmds:
            i = self.dckr.exec_create(container=self.name, cmd=c, tty = tty, privileged = True)
            self.dckr.exec_start(i['Id'], stream = stream)
            result = self.dckr.exec_inspect(i['Id'])
            res += 0 if result['ExitCode'] == None else result['ExitCode']
        return res

class Onos(Container):

    quagga_config = { 'bridge' : 'quagga-br', 'ip': '10.10.0.4', 'mask' : 16 }
    env = { 'ONOS_APPS' : 'drivers,openflow,proxyarp,aaa,igmp,vrouter' }
    ports = [ 8181, 8101, 9876, 6653, 6633, 2000, 2620 ]

    def __init__(self, name = 'cord-onos', image = 'onosproject/onos', tag = 'latest', boot_delay = 60):
        super(Onos, self).__init__(name, image, tag = tag, quagga_config = self.quagga_config)
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports)
            print('Starting ONOS container %s' %self.name)
            self.start(ports = self.ports, environment = self.env, 
                       host_config = host_config, tty = True)
            print('Waiting %d seconds for ONOS to boot' %(boot_delay))
            time.sleep(boot_delay)

class Radius(Container):
    ports = [ 1812, 1813 ]
    env = {'TIMEZONE':'America/Los_Angeles', 
           'DEBUG': 'true', 'cert_password':'whatever', 'primary_shared_secret':'radius_password'
           }
    host_db_dir = os.path.join(os.getenv('HOME'), 'services', 'radius', 'data', 'db')
    guest_db_dir = os.path.join(os.path.sep, 'opt', 'db')
    host_config_dir = os.path.join(os.getenv('HOME'), 'services', 'radius', 'freeradius')
    guest_config_dir = os.path.join(os.path.sep, 'etc', 'freeradius')
    start_command = '/root/start-radius.py'
    host_guest_map = ( (host_db_dir, guest_db_dir),
                       (host_config_dir, guest_config_dir)
                       )
    def __init__(self, name = 'cord-radius', image = 'freeradius', tag = 'podd'):
        super(Radius, self).__init__(name, image, tag = tag, command = self.start_command)
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports,
                                                  host_guest_map = self.host_guest_map)
            volumes = []
            for h,g in self.host_guest_map:
                volumes.append(g)
            self.start(ports = self.ports, environment = self.env, 
                       volumes = volumes, 
                       host_config = host_config, tty = True)

class CordTester(Container):

    sandbox = '/root/test'
    sandbox_setup = '/root/test/src/test/setup'
    tester_base = os.path.dirname(os.path.realpath(sys.argv[0]))
    tester_paths = os.path.realpath(sys.argv[0]).split(os.path.sep)
    tester_path_index = tester_paths.index('cord-tester')
    sandbox_host = os.path.sep.join(tester_paths[:tester_path_index+1])

    host_guest_map = ( (sandbox_host, sandbox),
                      ('/lib/modules', '/lib/modules')
                       )
    basename = 'cord-tester'

    def __init__(self, ctlr_ip = None, image = 'cord-test/nose', tag = 'latest', env = None, rm = False):
        self.ctlr_ip = ctlr_ip
        self.rm = rm
        self.name = self.get_name()
        super(CordTester, self).__init__(self.name, image = image, tag = tag)
        host_config = self.create_host_config(host_guest_map = self.host_guest_map, privileged = True)
        volumes = []
        for h, g in self.host_guest_map:
            volumes.append(g)
        ##Remove test container if any
        self.remove_container(self.name, force=True)
        if env is not None and env.has_key('OLT_CONFIG'):
            self.olt = True
        else:
            self.olt = False
        self.intf_ports = (1, 2)
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

        return self.setup_intfs(bridge)

    def setup_intfs(self, bridge = 'ovsbr0'):
        if not self.olt:
            return 0
        olt_conf_file = os.path.join(self.tester_base, 'olt_config.json')
        olt_config = OltConfig(olt_conf_file)
        port_map = olt_config.olt_port_map()
        tester_intf_subnet = '192.168.100'
        res = 0
        for port in self.intf_ports:
            guest_if = port_map[port]
            local_if = guest_if
            guest_ip = '{0}.{1}/24'.format(tester_intf_subnet, str(port))
            ##Use pipeworks to configure container interfaces on OVS bridge
            pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4}'.format(bridge, guest_if, local_if, self.name, guest_ip)
            res += os.system(pipework_cmd)

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
RUN apt-get -y install python-twisted python-sqlite sqlite3 python-pexpect
RUN pip install scapy-ssl_tls
RUN pip install -U scapy
RUN pip install monotonic
RUN pip install configObj
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
cord_tester_base = os.path.dirname(os.path.realpath(sys.argv[0]))
onos_app_file = os.path.abspath('{0}/../apps/ciena-cordigmp-'.format(cord_tester_base) + onos_app_version + '.oar')
zebra_quagga_config = { 'bridge' : 'quagga-br', 'ip': '10.10.0.1', 'mask': 16 }

def runTest(args):
    onos_cnt = {'tag':'latest'}
    radius_cnt = {'tag':'latest'}
    nose_cnt = {'image': 'cord-test/nose','tag': 'latest'}

    #print('Test type %s, onos %s, radius %s, app %s, olt %s, cleanup %s, kill flag %s, build image %s'
    #      %(args.test_type, args.onos, args.radius, args.app, args.olt, args.cleanup, args.kill, args.build))
    if args.cleanup:
        cleanup_container = args.cleanup
        if cleanup_container.find(':') < 0:
            cleanup_container += ':latest'
        print('Cleaning up containers %s' %cleanup_container)
        Container.cleanup(cleanup_container)
        sys.exit(0)

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

    OnosCtrl.install_app(args.app)

    build_cnt_image = args.build.strip()
    if build_cnt_image:
        CordTester.build_image(build_cnt_image)
        nose_cnt['image']= build_cnt_image.split(':')[0]
        if build_cnt_image.find(':') >= 0:
            nose_cnt['tag'] = build_cnt_image.split(':')[1]

    test_cnt_env = { 'ONOS_CONTROLLER_IP' : onos_ip,
                     'ONOS_AAA_IP' : radius_ip,
                   }
    if args.olt:
        olt_conf_test_loc = os.path.join(CordTester.sandbox_setup, 'olt_config.json')
        test_cnt_env['OLT_CONFIG'] = olt_conf_test_loc

    test_cnt = CordTester(ctlr_ip = onos_ip, image = nose_cnt['image'], tag = nose_cnt['tag'],
                          env = test_cnt_env,
                          rm = args.kill)
    if args.start_switch or not args.olt:
        test_cnt.start_switch()
    tests = args.test_type.split('-')
    test_cnt.run_tests(tests)

if __name__ == '__main__':
    parser = ArgumentParser(description='Cord Tester for ONOS')
    parser.add_argument('-t', '--test-type', default=test_type_default, type=str)
    parser.add_argument('-o', '--onos', default=onos_image_default, type=str, help='ONOS container image')
    parser.add_argument('-r', '--radius',default='',type=str, help='Radius container image')
    parser.add_argument('-a', '--app', default=onos_app_file, type=str, help='Cord ONOS app filename')
    parser.add_argument('-l', '--olt', action='store_true', help='Use OLT config')
    parser.add_argument('-c', '--cleanup', default='', type=str, help='Cleanup test containers')
    parser.add_argument('-k', '--kill', action='store_true', help='Remove test container after tests')
    parser.add_argument('-b', '--build', default='', type=str)
    parser.add_argument('-s', '--start-switch', action='store_true', help='Start OVS')
    parser.set_defaults(func=runTest)
    args = parser.parse_args()
    args.func(args)
