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
import yaml
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
    IMAGE_PREFIX = '' ##for saving global prefix for all test classes

    def __init__(self, name, image, prefix='', tag = 'candidate', command = 'bash', quagga_config = None):
        self.name = name
        self.prefix = prefix
        if prefix:
            self.prefix += '/'
            image = '{}{}'.format(self.prefix, image)
        self.image = image
        self.tag = tag
        if tag:
            self.image_name = image + ':' + tag
        else:
            self.image_name = image
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
        return self.image_name in [ctn['RepoTags'][0] if ctn['RepoTags'] else '' for ctn in self.dckr.images()]

    def ip(self):
        cnt_list = filter(lambda c: c['Names'][0] == '/{}'.format(self.name), self.dckr.containers())
        #if not cnt_list:
        #    cnt_list = filter(lambda c: c['Image'] == self.image_name, self.dckr.containers())
        cnt_settings = cnt_list.pop()
        return cnt_settings['NetworkSettings']['Networks']['bridge']['IPAddress']

    @classmethod
    def ips(cls, image_name):
        cnt_list = filter(lambda c: c['Image'] == image_name, cls.dckr.containers())
        ips = [ cnt['NetworkSettings']['Networks']['bridge']['IPAddress'] for cnt in cnt_list ]
        return ips

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

    def restart(self, timeout =10):
        return self.dckr.restart(self.name, timeout)

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

class OnosCord(Container):
    """Use this when running the cord tester agent on the onos compute node"""
    onos_cord_dir = os.path.join(os.getenv('HOME'), 'cord-tester-cord')
    onos_config_dir_guest = '/root/onos/config'
    onos_config_dir = os.path.join(onos_cord_dir, 'config')
    docker_yaml = os.path.join(onos_cord_dir, 'docker-compose.yml')

    def __init__(self, onos_ip, conf, boot_delay = 60):
        self.onos_ip = onos_ip
        self.cord_conf_dir = conf
        self.boot_delay = boot_delay
        if os.access(self.cord_conf_dir, os.F_OK) and not os.access(self.onos_cord_dir, os.F_OK):
            os.mkdir(self.onos_cord_dir)
            os.mkdir(self.onos_config_dir)
            ##copy the config file from cord-tester-config
            cmd = 'cp {}/* {}'.format(self.cord_conf_dir, self.onos_cord_dir)
            os.system(cmd)

        ##update the docker yaml with the config volume
        with open(self.docker_yaml, 'r') as f:
            yaml_config = yaml.load(f)
            image = yaml_config['services'].keys()[0]
            name = 'cordtestercord_{}_1'.format(image)
            volumes = yaml_config['services'][image]['volumes']
            config_volumes = filter(lambda e: e.find(self.onos_config_dir_guest) >= 0, volumes)
            if not config_volumes:
                config_volume = '{}:{}'.format(self.onos_config_dir, self.onos_config_dir_guest)
                volumes.append(config_volume)
                docker_yaml_changed = '{}-changed'.format(self.docker_yaml)
                with open(docker_yaml_changed, 'w') as wf:
                    yaml.dump(yaml_config, wf)

                os.rename(docker_yaml_changed, self.docker_yaml)
            self.volumes = volumes

        super(OnosCord, self).__init__(name, image, tag = '')
        cord_conf_dir_basename = os.path.basename(self.cord_conf_dir.replace('-', ''))
        self.xos_onos_name = '{}_{}_1'.format(cord_conf_dir_basename, image)
        ##Create an container instance of xos onos
        self.xos_onos = Container(self.xos_onos_name, image, tag = '')

    def start(self, restart = False, network_cfg = None):
        if restart is True:
            if self.exists():
                ##Kill the existing instance
                print('Killing container %s' %self.name)
                self.kill()
            if self.xos_onos.exists():
                print('Killing container %s' %self.xos_onos.name)
                self.xos_onos.kill()

        if network_cfg is not None:
            json_data = json.dumps(network_cfg, indent=4)
            with open('{}/network-cfg.json'.format(self.onos_config_dir), 'w') as f:
                f.write(json_data)

        #start the container using docker-compose
        cmd = 'cd {} && docker-compose up -d'.format(self.onos_cord_dir)
        os.system(cmd)
        #Delay to make sure ONOS fully boots
        time.sleep(self.boot_delay)
        Onos.install_cord_apps(onos_ip = self.onos_ip)

    def build_image(self):
        build_cmd = 'cd {} && docker-compose build'.format(self.onos_cord_dir)
        os.system(build_cmd)

class Onos(Container):

    quagga_config = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.4', 'mask' : 16 }, )
    SYSTEM_MEMORY = (get_mem(),) * 2
    JAVA_OPTS = '-Xms{} -Xmx{} -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode'.format(*SYSTEM_MEMORY)#-XX:+PrintGCDetails -XX:+PrintGCTimeStamps'
    env = { 'ONOS_APPS' : 'drivers,openflow,proxyarp,vrouter', 'JAVA_OPTS' : JAVA_OPTS }
    onos_cord_apps = ( ('cord-config', '1.0-SNAPSHOT'),
                       ('aaa', '1.0-SNAPSHOT'),
                       ('igmp', '1.0-SNAPSHOT'),
                       #('vtn', '1.0-SNAPSHOT'),
                       )
    ports = [ 8181, 8101, 9876, 6653, 6633, 2000, 2620 ]
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    host_config_dir = os.path.join(setup_dir, 'onos-config')
    guest_config_dir = '/root/onos/config'
    onos_gen_partitions = os.path.join(setup_dir, 'onos-gen-partitions')
    onos_form_cluster = os.path.join(setup_dir, 'onos-form-cluster')
    cord_apps_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'apps')
    host_guest_map = ( (host_config_dir, guest_config_dir), )
    cluster_cfg = os.path.join(host_config_dir, 'cluster.json')
    cluster_mode = False
    cluster_instances = []
    NAME = 'cord-onos'
    ##the ip of ONOS in default cluster.json in setup/onos-config
    CLUSTER_CFG_IP = '172.17.0.2'
    IMAGE = 'onosproject/onos'
    TAG = 'latest'
    PREFIX = ''

    @classmethod
    def generate_cluster_cfg(cls, ip):
        if type(ip) in [ list, tuple ]:
            ips = ' '.join(ip)
        else:
            ips = ip
        try:
            cmd = '{} {} {}'.format(cls.onos_gen_partitions, cls.cluster_cfg, ips)
            os.system(cmd)
        except: pass

    @classmethod
    def form_cluster(cls, ips):
        nodes = ' '.join(ips)
        try:
            cmd = '{} {}'.format(cls.onos_form_cluster, nodes)
            os.system(cmd)
        except: pass

    @classmethod
    def cleanup_runtime(cls):
        '''Cleanup ONOS runtime generated files'''
        files = ( Onos.cluster_cfg, os.path.join(Onos.host_config_dir, 'network-cfg.json') )
        for f in files:
            if os.access(f, os.F_OK):
                try:
                    os.unlink(f)
                except: pass

    def __init__(self, name = NAME, image = 'onosproject/onos', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, cluster = False):
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Onos, self).__init__(name, image, prefix = prefix, tag = tag, quagga_config = self.quagga_config)
        self.boot_delay = boot_delay
        if cluster is True:
            self.ports = []
            if os.access(self.cluster_cfg, os.F_OK):
                try:
                    os.unlink(self.cluster_cfg)
                except: pass

        self.host_config = self.create_host_config(port_list = self.ports,
                                                   host_guest_map = self.host_guest_map)
        self.volumes = []
        for _,g in self.host_guest_map:
            self.volumes.append(g)

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
                       host_config = self.host_config, volumes = self.volumes, tty = True)
            if not restart:
                ##wait a bit before fetching IP to regenerate cluster cfg
                time.sleep(5)
                ip = self.ip()
                ##Just a quick hack/check to ensure we don't regenerate in the common case.
                ##As ONOS is usually the first test container that is started
                if cluster is False:
                    if ip != self.CLUSTER_CFG_IP or not os.access(self.cluster_cfg, os.F_OK):
                        print('Regenerating ONOS cluster cfg for ip %s' %ip)
                        self.generate_cluster_cfg(ip)
                        self.kill()
                        self.remove_container(self.name, force=True)
                        print('Restarting ONOS container %s' %self.name)
                        self.start(ports = self.ports, environment = self.env,
                                   host_config = self.host_config, volumes = self.volumes, tty = True)
            print('Waiting %d seconds for ONOS to boot' %(boot_delay))
            time.sleep(boot_delay)
        self.ipaddr = self.ip()
        if cluster is False:
            self.install_cord_apps(self.ipaddr)

    @classmethod
    def setup_cluster_deprecated(cls, onos_instances, image_name = None):
        if not onos_instances or len(onos_instances) < 2:
            return
        ips = []
        if image_name is not None:
            ips = Container.ips(image_name)
        else:
            for onos in onos_instances:
                ips.append(onos.ipaddr)
        Onos.cluster_instances = onos_instances
        Onos.cluster_mode = True
        ##regenerate the cluster json with the 3 instance ips before restarting them back
        print('Generating cluster cfg for ONOS instances with ips %s' %ips)
        Onos.generate_cluster_cfg(ips)
        for onos in onos_instances:
            onos.kill()
            onos.remove_container(onos.name, force=True)
            print('Restarting ONOS container %s for forming cluster' %onos.name)
            onos.start(ports = onos.ports, environment = onos.env,
                       host_config = onos.host_config, volumes = onos.volumes, tty = True)
            print('Waiting %d seconds for ONOS %s to boot' %(onos.boot_delay, onos.name))
            time.sleep(onos.boot_delay)
            onos.ipaddr = onos.ip()
            onos.install_cord_apps(onos.ipaddr)

    @classmethod
    def setup_cluster(cls, onos_instances, image_name = None):
        if not onos_instances or len(onos_instances) < 2:
            return
        ips = []
        if image_name is not None:
            ips = Container.ips(image_name)
        else:
            for onos in onos_instances:
                ips.append(onos.ipaddr)
        Onos.cluster_instances = onos_instances
        Onos.cluster_mode = True
        ##regenerate the cluster json with the 3 instance ips before restarting them back
        print('Forming cluster for ONOS instances with ips %s' %ips)
        Onos.form_cluster(ips)
        ##wait for the cluster to be formed
        print('Waiting for the cluster to be formed')
        time.sleep(60)
        for onos in onos_instances:
            onos.install_cord_apps(onos.ipaddr)

    @classmethod
    def restart_cluster(cls, network_cfg = None):
        if cls.cluster_mode is False:
            return
        if not cls.cluster_instances:
            return

        if network_cfg is not None:
            json_data = json.dumps(network_cfg, indent=4)
            with open('{}/network-cfg.json'.format(cls.host_config_dir), 'w') as f:
                f.write(json_data)

        for onos in cls.cluster_instances:
            if onos.exists():
                onos.kill()
            onos.remove_container(onos.name, force=True)
            print('Restarting ONOS container %s' %onos.name)
            onos.start(ports = onos.ports, environment = onos.env,
                       host_config = onos.host_config, volumes = onos.volumes, tty = True)
            print('Waiting %d seconds for ONOS %s to boot' %(onos.boot_delay, onos.name))
            time.sleep(onos.boot_delay)
            onos.ipaddr = onos.ip()

        ##form the cluster
        cls.setup_cluster(cls.cluster_instances)

    @classmethod
    def cluster_ips(cls):
        if cls.cluster_mode is False:
            return []
        if not cls.cluster_instances:
            return []
        ips = [ onos.ipaddr for onos in cls.cluster_instances ]
        return ips

    @classmethod
    def cleanup_cluster(cls):
        if cls.cluster_mode is False:
            return
        if not cls.cluster_instances:
            return
        for onos in cls.cluster_instances:
            if onos.exists():
                onos.kill()
            onos.remove_container(onos.name, force=True)

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

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = 'candidate',
                 boot_delay = 10, restart = False, update = False):
        super(Radius, self).__init__(name, image, prefix = prefix, tag = tag, command = self.start_command)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
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

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = 'candidate',
                 boot_delay = 15, restart = False, config_file = quagga_config_file, update = False):
        super(Quagga, self).__init__(name, image, prefix = prefix, tag = tag, quagga_config = self.quagga_config)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
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
RUN git clone git://git.savannah.nongnu.org/quagga.git quagga && \
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

class Xos(Container):
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name, image, dockerfile = None, prefix = PREFIX, tag = TAG,
                 boot_delay = 30, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, check github repo')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              print('Waiting %d seconds for XOS Base Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS base image %s' %image)
        super(Xos, cls).build_image(self.dockerfile, image)
        print('Done building image %s' %image)

class Xos_base(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8000,9998,9999 ]
    env = { 'XOS_GIT_REPO' : 'https://github.com/opencord/xos.git', 'XOS_GIT_BRANCH' : 'master', 'NG_XOS_LIB_URL' : ' https://github.com/opencord/ng-xos-lib.git', 'NG_XOS_LIB_VERSION' : '1.0.0',}
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-base'
    IMAGE = 'xosproject/xos-base'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-base', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_base, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS base container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS Base Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS base image %s' %image)
        dockerfile = '''
FROM xosproject/xos-base
MAINTAINER chetan@ciena.com
ADD local_certs.crt /usr/local/share/ca-certificates/local_certs.crt
RUN update-ca-certificates
RUN git clone $XOS_GIT_REPO -b $XOS_GIT_BRANCH /tmp/xos && \
    mv /tmp/xos/xos /opt/ && \
    chmod +x /opt/xos/tools/xos-manage && \
    /opt/xos/tools/xos-manage genkeys

RUN git clone $NG_XOS_LIB_URL /tmp/ng-xos-lib
RUN cd /tmp/ng-xos-lib && git checkout tags/$NG_XOS_LIB_VERSION
RUN cp /tmp/ng-xos-lib/dist/ngXosHelpers.min.js /opt/xos/core/xoslib/static/vendor/
RUN cp /tmp/ng-xos-lib/dist/ngXosVendor.min.js /opt/xos/core/xoslib/static/vendor/
WORKDIR /opt/xos
CMD python /opt/xos/manage.py runserver 0.0.0.0:8000 --insecure --makemigrations
'''
        super(Xos_base, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_openstack(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 2375 ]
    env = {'DOCKER_URL' : 'https://get.docker.com/builds/Linux/x86_64/docker-1.10.3', 'DOCKER_SHA256' : 'd0df512afa109006a450f41873634951e19ddabf8c7bd419caeb5a526032d86d', 'DOCKER_COMPOSE_URL' : ' https://github.com/docker/compose/releases/download/1.5.2/docker-compose-Linux-x86_64', 'DOCKER_COMPOSE_SHA256' : ' b6b975badc5389647ef1c16fe8a33bdc5935c61f6afd5a15a28ff765427d01e3' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-openstack'
    IMAGE = 'xosproject/xos-synchronizer-openstack'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-openstack', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_openstack, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS Synchronizer Openstack container %s' %self.name)
              self.start(environment = self.env,
                       tty = True)
              if not restart:
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS Synchronizer Openstack Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer Openstack image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-openstack
RUN curl -fLsS $DOCKER_URL -o docker && \
    echo "${DOCKER_SHA256}  docker" | sha256sum -c - && \
    mv docker /usr/local/bin/docker && \
    chmod +x /usr/local/bin/docker
RUN curl -fLsS $DOCKER_COMPOSE_URL -o docker-compose && \
    echo "${DOCKER_COMPOSE_SHA256}  docker-compose" | sha256sum -c - && \
    mv docker-compose /usr/local/bin/docker-compose && \
    chmod +x /usr/local/bin/docker-compose
CMD /usr/bin/supervisord -c /etc/supervisor/conf.d/synchronizer.conf
'''
        super(Xos_sync_openstack, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_openvpn(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [8000]
    env = {'DOCKER_URL' : 'https://get.docker.com/builds/Linux/x86_64/docker-1.10.3', 'DOCKER_SHA256' : 'd0df512afa109006a450f41873634951e19ddabf8c7bd419caeb5a526032d86d', 'DOCKER_COMPOSE_URL' : ' https://github.com/docker/compose/releases/download/1.5.2/docker-compose-Linux-x86_64', 'DOCKER_COMPOSE_SHA256' : ' b6b975badc5389647ef1c16fe8a33bdc5935c61f6afd5a15a28ff765427d01e3' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'openvpn'
    IMAGE = 'xosproject/xos-synchronizer-openstack'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-openstack', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_openvpn, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS Openvpn container %s' %self.name)
              self.start(ports = self.ports, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS Openvpn Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer Openstack image %s' %image)
        dockerfile = '''
FROM       xosproject/xos-synchronizer-openstack
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y \
    openvpn
RUN mkdir -p /opt/openvpn
RUN chmod 777 /opt/openvpn
RUN git clone https://github.com/OpenVPN/easy-rsa.git /opt/openvpn
RUN git -C /opt/openvpn pull origin master
RUN echo 'set_var EASYRSA	"/opt/openvpn/easyrsa3"' | tee /opt/openvpn/vars
RUN echo 'set_var EASYRSA_BATCH	"true"' | tee -a /opt/openvpn/vars
'''
        super(Xos_openvpn, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_postgresql(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 5432 ]
    NAME = 'xos-postgresql'
    IMAGE = 'xosproject/xos-postgres'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'ubuntu', prefix = '', tag = '14.04',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_postgresql, self).__init__(name, image, prefix = prefix, tag = tag)
        if restart is True and self.exists():
            self.kill()
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports)
            volumes = ["/etc/postgresql", "/var/log/postgresql", "/var/lib/postgresql"]
            print('Starting Xos postgresql container %s' %self.name)
            self.start(ports = self.ports, host_config = host_config, volumes = volumes, tty = True)
            if not restart:
                ##wait a bit before fetching IP to regenerate cluster cfg
                time.sleep(5)
                ip = self.ip()
            print('Waiting %d seconds for Xos postgresql to boot' %(boot_delay))
            time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS postgresql image %s' %image)
        dockerfile = '''
FROM ubuntu:14.04
RUN apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8
RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ precise-pgdg main" > /etc/apt/sources.list.d/pgdg.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    python-software-properties \
    software-properties-common \
    postgresql-9.3 \
    postgresql-client-9.3 \
    postgresql-contrib-9.3

RUN mkdir /etc/ssl/private-copy; mv /etc/ssl/private/* /etc/ssl/private-copy/; rm -r /etc/ssl/private; mv /etc/ssl/private-copy /etc/ssl/private; chmod -R 0700 /etc/ssl/private; chown -R postgres /etc/ssl/private
USER postgres
RUN /etc/init.d/postgresql start && \
    psql --command "ALTER USER postgres WITH SUPERUSER PASSWORD 'password' " && \
    psql --command "CREATE DATABASE xos"
RUN echo "host all  all    0.0.0.0/0  md5" >> /etc/postgresql/9.3/main/pg_hba.conf
RUN echo "host all  all    0.0.0.0/0  password" >> /etc/postgresql/9.3/main/pg_hba.conf
RUN echo "listen_addresses='*'" >> /etc/postgresql/9.3/main/postgresql.conf
VOLUME  ["/etc/postgresql", "/var/log/postgresql", "/var/lib/postgresql"]
CMD ["/usr/lib/postgresql/9.3/bin/postgres", "-D", "/var/lib/postgresql/9.3/main", "-c", "config_file=/etc/postgresql/9.3/main/postgresql.conf"]
'''
        super(Xos_postgresql, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_synchronizer(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8000 ]
    env = { 'XOS_GIT_REPO' : 'https://github.com/opencord/xos.git', 'XOS_GIT_BRANCH' : 'master', 'NG_XOS_LIB_URL' : ' https://github.com/opencord/ng-xos-lib.git', 'NG_XOS_LIB_VERSION' : '1.0.0',}
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos'
    IMAGE = 'xosproject/xos'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_synchronizer, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS synchronizer container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS Synchronizer Container to boot' %(boot_delay))
              time.sleep(boot_delay)


    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer image %s' %image)
        dockerfile = '''
FROM xosproject/xos
MAINTAINER chetan@ciena.com
COPY conf/synchronizer.conf /etc/supervisor/conf.d/
CMD /usr/bin/supervisord -c /etc/supervisor/conf.d/synchronizer.conf
'''
        super(Xos_synchronizer, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_syndicate_ms(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'syndicate-ms'
    IMAGE = 'xosproject/syndicate-ms'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'ubuntu', prefix = '', tag = '14.04.4',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_syndicate_ms, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS syndicate-ms container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS syndicate-ms Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Syndicate-ms image %s' %image)
        dockerfile = '''
FROM ubuntu:14.04.4
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_syndicate_ms, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_vtr(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-vtr'
    IMAGE = 'xosproject/xos-synchronizer-vtr'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-vtr', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_vtr, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-vtr container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-vtr Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-vtr image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-vtr
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_vtr, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_vsg(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-vsg'
    IMAGE = 'xosproject/xos-synchronizer-vsg'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-vsg', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_vsg, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-vsg container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-vsg Container to boot' %(boot_delay))
              time.sleep(boot_delay)


    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-vsg image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-vsg
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_vsg, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_onos(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-onos'
    IMAGE = 'xosproject/xos-synchronizer-onos'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-onos', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_onos, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-onos container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-onos Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-onos image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-onos
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_onos, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_fabric(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-fabric'
    IMAGE = 'xosproject/xos-synchronizer-fabric'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-fabric', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_fabric, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-fabric container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-fabric Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-fabric image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-fabric
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_fabric, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_vtn(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-vtn'
    IMAGE = 'xosproject/xos-synchronizer-vtn'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-vtn', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_vtn, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-vtn container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-vtn Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-vtn image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-vtn
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_vtn, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class Xos_sync_onboarding(Container):
    SYSTEM_MEMORY = (get_mem(),) * 2
    ports = [ 8080 ]
    env = { 'APT_KEY' : 'butler_opencloud_cs_arizona_edu_pub.gpg', 'MS_PORT': '8080', 'GAE_SDK' : 'google_appengine_1.9.35.zip', 'HOME' : '/home/syndicate' }
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    NAME = 'xos-synchronizer-onboarding'
    IMAGE = 'xosproject/xos-synchronizer-onboarding'
    TAG = 'latest'
    PREFIX = ''

    def __init__(self, name = NAME, image = 'xosproject/xos-synchronizer-onboarding', prefix = '', tag = 'latest',
                 boot_delay = 60, restart = False, network_cfg = None, update = False):
        GITHUB_ERROR = False
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        super(Xos_sync_onboarding, self).__init__(name, image, prefix = prefix, tag = tag)
        if update is True or not self.img_exists():
            self.build_image(self.image_name)
            if not self.img_exists():
               print ('Xos base container image is not built on host, have to check github repository ')
               GITHUB_ERROR = True
        if GITHUB_ERROR is not True:
           if restart is True and self.exists():
              self.kill()
           if not self.exists():
              self.remove_container(name, force=True)
              host_config = self.create_host_config(port_list = self.ports)
              print('Starting XOS xos-synchronizer-onboarding container %s' %self.name)
              self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       tty = True)
              if not restart:
                 ##wait a bit before fetching IP to regenerate cluster cfg
                 time.sleep(5)
                 ip = self.ip()
              print('Waiting %d seconds for XOS synchronizer-onboarding Container to boot' %(boot_delay))
              time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        print('Building XOS Synchronizer-onboarding image %s' %image)
        dockerfile = '''
FROM xosproject/xos-synchronizer-onboarding
MAINTAINER chetan@ciena.com
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    apt-transport-https
COPY butler.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
COPY $APT_KEY /tmp/
RUN apt-key add /tmp/$APT_KEY
RUN echo "deb https://butler.opencloud.cs.arizona.edu/repos/release/syndicate syndicate main" > /etc/apt/sources.list.d/butler.list
RUN DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --force-yes\
    syndicate-core \
    syndicate-ms \
    wget \
    unzip

RUN groupadd -r syndicate && useradd -m -r -g syndicate syndicate
USER syndicate
ENV HOME /home/syndicate
WORKDIR $HOME
RUN wget -nv https://storage.googleapis.com/appengine-sdks/featured/$GAE_SDK
RUN unzip -q $GAE_SDK
RUN mkdir $HOME/datastore
CMD $HOME/google_appengine/dev_appserver.py --admin_host=0.0.0.0 --host=0.0.0.0 --storage_path=$HOME/datastore --skip_sdk_update_check=true /usr/src/syndicate/ms
'''
        super(Xos_sync_onboarding, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)


