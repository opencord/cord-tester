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
import os,time
import io
import json
from pyroute2 import IPRoute
from itertools import chain
from nsenter import Namespace
from docker import Client
from shutil import copy
from OnosCtrl import OnosCtrl

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
        cnt_list = filter(lambda c: c['Image'] == image, cls.dckr.containers(all=True))
        for cnt in cnt_list:
            print('Cleaning container %s' %cnt['Id'])
            if cnt.has_key('State') and cnt['State'] == 'running':
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

def get_mem():
    with open('/proc/meminfo', 'r') as fd:
        meminfo = fd.readlines()
        mem = 0
        for m in meminfo:
            if m.startswith('MemTotal:') or m.startswith('SwapTotal:'):
                mem += int(m.split(':')[1].strip().split()[0])

        mem = max(mem/1024/1024/2, 1)
        mem = min(mem, 16)
        return str(mem) + 'G'

class Onos(Container):

    quagga_config = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.4', 'mask' : 16 }, )
    SYSTEM_MEMORY = (get_mem(),) * 2
    JAVA_OPTS = '-Xms{} -Xmx{} -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode'.format(*SYSTEM_MEMORY)#-XX:+PrintGCDetails -XX:+PrintGCTimeStamps'
    env = { 'ONOS_APPS' : 'drivers,openflow,proxyarp,vrouter', 'JAVA_OPTS' : JAVA_OPTS }
    onos_cord_apps = ( ('cord-config', '1.0-SNAPSHOT'),
                       ('aaa', '1.0-SNAPSHOT'),
                       ('igmp', '1.0-SNAPSHOT'),
                       )
    ports = [ 8181, 8101, 9876, 6653, 6633, 2000, 2620 ]
    host_config_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/onos-config')
    guest_config_dir = '/root/onos/config'
    cord_apps_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'apps')
    host_guest_map = ( (host_config_dir, guest_config_dir), )
    NAME = 'cord-onos'

    def __init__(self, name = NAME, image = 'onosproject/onos', tag = 'latest',
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
                json_data = json.dumps(network_cfg, indent=4)
                with open('{}/network-cfg.json'.format(self.host_config_dir), 'w') as f:
                    f.write(json_data)
            print('Starting ONOS container %s' %self.name)
            self.start(ports = self.ports, environment = self.env,
                       host_config = host_config, volumes = volumes, tty = True)
            print('Waiting %d seconds for ONOS to boot' %(boot_delay))
            time.sleep(boot_delay)

    @classmethod
    def install_cord_apps(cls, onos_ip = None):
        for app, version in cls.onos_cord_apps:
            app_file = '{}/{}-{}.oar'.format(cls.cord_apps_dir, app, version)
            ok, code = OnosCtrl.install_app(app_file, onos_ip = onos_ip)
            ##app already installed (conflicts)
            if code in [ 409 ]:
                ok = True
            print('ONOS app %s, version %s %s' %(app, version, 'installed' if ok else 'failed to install'))
            time.sleep(2)

class Radius(Container):
    ports = [ 1812, 1813 ]
    env = {'TIMEZONE':'America/Los_Angeles',
           'DEBUG': 'true', 'cert_password':'whatever', 'primary_shared_secret':'radius_password'
           }
    host_db_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/radius-config/db')
    guest_db_dir = os.path.join(os.path.sep, 'opt', 'db')
    host_config_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/radius-config/freeradius')
    guest_config_dir = os.path.join(os.path.sep, 'etc', 'freeradius')
    start_command = os.path.join(guest_config_dir, 'start-radius.py')
    host_guest_map = ( (host_db_dir, guest_db_dir),
                       (host_config_dir, guest_config_dir)
                       )
    IMAGE = 'cord-test/radius'
    NAME = 'cord-radius'

    def __init__(self, name = NAME, image = IMAGE, tag = 'latest',
                 boot_delay = 10, restart = False, update = False):
        super(Radius, self).__init__(name, image, tag = tag, command = self.start_command)
        if update is True or not self.img_exists():
            self.build_image(image)
        if restart is True and self.exists():
            self.kill()
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
            time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building Radius image %s' %image)
        dockerfile = '''
FROM hbouvier/docker-radius
MAINTAINER chetan@ciena.com
LABEL RUN docker pull hbouvier/docker-radius
LABEL RUN docker run -it --name cord-radius hbouvier/docker-radius
RUN apt-get update && \
    apt-get -y install python python-pexpect strace
WORKDIR /root
CMD ["/etc/freeradius/start-radius.py"]
'''
        super(Radius, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Quagga(Container):
    quagga_config = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.3', 'mask' : 16 },
                      { 'bridge' : 'quagga-br', 'ip': '192.168.10.3', 'mask': 16 },
                      )
    ports = [ 179, 2601, 2602, 2603, 2604, 2605, 2606 ]
    host_quagga_config = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup/quagga-config')
    guest_quagga_config = '/root/config'
    quagga_config_file = os.path.join(guest_quagga_config, 'testrib.conf')
    host_guest_map = ( (host_quagga_config, guest_quagga_config), )
    IMAGE = 'cord-test/quagga'
    NAME = 'cord-quagga'

    def __init__(self, name = NAME, image = IMAGE, tag = 'latest',
                 boot_delay = 15, restart = False, config_file = quagga_config_file, update = False):
        super(Quagga, self).__init__(name, image, tag = tag, quagga_config = self.quagga_config)
        if update is True or not self.img_exists():
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
FROM ubuntu:14.04
MAINTAINER chetan@ciena.com
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

def reinitContainerClients():
    docker_netns.dckr = Client()
    Container.dckr = Client()
