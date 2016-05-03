import os,time
import io
import json
from pyroute2 import IPRoute
from itertools import chain
from nsenter import Namespace
from docker import Client
from shutil import copy

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
        self.quagga_config = quagga_config

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
        if self.quagga_config:
            self.connect_to_br()
        self.id = ctn['Id']
        return ctn

    def connect_to_br(self):
        index = 0
        with docker_netns(self.name) as pid:
            for quagga_config in self.quagga_config:
                ip = IPRoute()
                br = ip.link_lookup(ifname=quagga_config['bridge'])
                if len(br) == 0:
                    ip.link_create(ifname=quagga_config['bridge'], kind='bridge')
                    br = ip.link_lookup(ifname=quagga_config['bridge'])
                br = br[0]
                ip.link('set', index=br, state='up')
                ifname = '{0}-{1}'.format(self.name, index)
                ifs = ip.link_lookup(ifname=ifname)
                if len(ifs) > 0:
                   ip.link_remove(ifs[0])
                peer_ifname = '{0}-{1}'.format(pid, index)
                ip.link_create(ifname=ifname, kind='veth', peer=peer_ifname)
                host = ip.link_lookup(ifname=ifname)[0]
                ip.link('set', index=host, master=br)
                ip.link('set', index=host, state='up')
                guest = ip.link_lookup(ifname=peer_ifname)[0]
                ip.link('set', index=guest, net_ns_fd=pid)
                with Namespace(pid, 'net'):
                    ip = IPRoute()
                    ip.link('set', index=guest, ifname='eth{}'.format(index+1))
                    ip.addr('add', index=guest, address=quagga_config['ip'], mask=quagga_config['mask'])
                    ip.link('set', index=guest, state='up')
                index += 1

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
            self.dckr.exec_start(i['Id'], stream = stream, detach=True)
            result = self.dckr.exec_inspect(i['Id'])
            res += 0 if result['ExitCode'] == None else result['ExitCode']
        return res

class Onos(Container):

    quagga_config = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.4', 'mask' : 16 }, )
    env = { 'ONOS_APPS' : 'drivers,openflow,proxyarp,aaa,igmp,vrouter' }
    ports = [ 8181, 8101, 9876, 6653, 6633, 2000, 2620 ]
    host_config_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/onos-config')
    guest_config_dir = '/root/onos/config'
    host_guest_map = ( (host_config_dir, guest_config_dir), )

    def __init__(self, name = 'cord-onos', image = 'onosproject/onos', tag = 'latest', 
                 boot_delay = 60, restart = False, network_cfg = None):
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Onos, self).__init__(name, image, tag = tag, quagga_config = self.quagga_config)
        if restart is True and self.exists():
            self.kill()
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports,
                                                  host_guest_map = self.host_guest_map)
            volumes = []
            for _,g in self.host_guest_map:
                volumes.append(g)
            if network_cfg is not None:
                json_data = json.dumps(network_cfg)
                with open('{}/network-cfg.json'.format(self.host_config_dir), 'w') as f:
                    f.write(json_data)
            print('Starting ONOS container %s' %self.name)
            self.start(ports = self.ports, environment = self.env, 
                       host_config = host_config, volumes = volumes, tty = True)
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
            for _,g in self.host_guest_map:
                volumes.append(g)
            self.start(ports = self.ports, environment = self.env, 
                       volumes = volumes, 
                       host_config = host_config, tty = True)

class Quagga(Container):
    quagga_config = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.3', 'mask' : 16 }, 
                      { 'bridge' : 'quagga-br', 'ip': '192.168.10.3', 'mask': 16 },
                      )
    ports = [ 179, 2601, 2602, 2603, 2604, 2605, 2606 ]
    host_quagga_config = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/quagga-config')
    guest_quagga_config = '/root/config'
    quagga_config_file = os.path.join(guest_quagga_config, 'testrib.conf')
    host_guest_map = ( (host_quagga_config, guest_quagga_config), )
    
    def __init__(self, name = 'cord-quagga', image = 'cord-test/quagga', tag = 'latest', 
                 boot_delay = 30, restart = False, config_file = quagga_config_file):
        super(Quagga, self).__init__(name, image, tag = tag, quagga_config = self.quagga_config)
        if not self.img_exists():
            self.build_image(image)
        if restart is True and self.exists():
            self.kill()
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports, 
                                                  host_guest_map = self.host_guest_map, 
                                                  privileged = True)
            volumes = []
            for _,g in self.host_guest_map:
                volumes.append(g)
            self.start(ports = self.ports,
                       host_config = host_config, 
                       volumes = volumes, tty = True)
            print('Starting Quagga on container %s' %self.name)
            self.execute('{0}/start.sh {1}'.format(self.guest_quagga_config, config_file))
            time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        onos_quagga_ip = Onos.quagga_config[0]['ip']
        print('Building Quagga image %s' %image)
        dockerfile = '''
FROM ubuntu:latest
WORKDIR /root
RUN useradd -M quagga
RUN mkdir /var/log/quagga && chown quagga:quagga /var/log/quagga
RUN mkdir /var/run/quagga && chown quagga:quagga /var/run/quagga
RUN apt-get update && apt-get install -qy git autoconf libtool gawk make telnet libreadline6-dev
RUN git clone git://git.sv.gnu.org/quagga.git quagga && \
(cd quagga && git checkout HEAD && ./bootstrap.sh && \
sed -i -r 's,htonl.*?\(INADDR_LOOPBACK\),inet_addr\("{0}"\),g' zebra/zebra_fpm.c && \
./configure --enable-fpm --disable-doc --localstatedir=/var/run/quagga && make && make install)
RUN ldconfig
'''.format(onos_quagga_ip)
        super(Quagga, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

