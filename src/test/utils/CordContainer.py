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
import errno
import copy
from pyroute2 import IPRoute
from pyroute2.netlink import NetlinkError
from itertools import chain
from nsenter import Namespace
from docker import Client
from docker import utils as dockerutils
from shutil import rmtree
from OnosCtrl import OnosCtrl
from OnosLog import OnosLog
from threadPool import ThreadPool
from threading import Lock

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
    CONFIG_LOCK = Lock()

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
    def connect_to_network(cls, name, network):
        try:
            cls.dckr.connect_container_to_network(name, network)
            return True
        except:
            return False

    @classmethod
    def create_network(cls, network, subnet = None, gateway = None):
        ipam_config = None
        if subnet is not None and gateway is not None:
            ipam_pool = dockerutils.create_ipam_pool(subnet = subnet, gateway = gateway)
            ipam_config = dockerutils.create_ipam_config(pool_configs = [ipam_pool])
        cls.dckr.create_network(network, driver='bridge', ipam = ipam_config)

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

    def ip(self, network = None):
        cnt_list = filter(lambda c: c['Names'][0] == '/{}'.format(self.name), self.dckr.containers())
        #if not cnt_list:
        #    cnt_list = filter(lambda c: c['Image'] == self.image_name, self.dckr.containers())
        cnt_settings = cnt_list.pop()
        if network is not None and cnt_settings['NetworkSettings']['Networks'].has_key(network):
            return cnt_settings['NetworkSettings']['Networks'][network]['IPAddress']
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

    @classmethod
    def pause_container(cls, image, delay):
        cnt_list = filter(lambda c: c['Image'] == image, cls.dckr.containers(all=True))
        for cnt in cnt_list:
            print('Pause the container %s' %cnt['Id'])
            if cnt.has_key('State') and cnt['State'] == 'running':
                cls.dckr.pause(cnt['Id'])
        if delay != 0:
           time.sleep(delay)
           for cnt in cnt_list:
               print('Unpause the container %s' %cnt['Id'])
               cls.dckr.unpause(cnt['Id'])
        else:
            print('Infinity time pause the container %s' %cnt['Id'])
        return 'success'

    def connect_to_br(self):
        index = 0
        self.CONFIG_LOCK.acquire()
        try:
            with docker_netns(self.name) as pid:
                for quagga_config in self.quagga_config:
                    ip = IPRoute()
                    br = ip.link_lookup(ifname=quagga_config['bridge'])
                    if len(br) == 0:
                        try:
                            ip.link_create(ifname=quagga_config['bridge'], kind='bridge')
                        except NetlinkError as e:
                            err, _ = e.args
                            if err == errno.EEXIST:
                                pass
                            else:
                                raise NetlinkError(*e.args)
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
        finally:
            self.CONFIG_LOCK.release()

    def execute(self, cmd, tty = True, stream = False, shell = False, detach = True):
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
            self.dckr.exec_start(i['Id'], stream = stream, detach=detach)
            result = self.dckr.exec_inspect(i['Id'])
            res += 0 if result['ExitCode'] == None else result['ExitCode']
        return res

    def restart(self, timeout =10):
        return self.dckr.restart(self.name, timeout)

def get_mem(jvm_heap_size = None, instances = 1):
    if instances <= 0:
        instances = 1
    heap_size = jvm_heap_size
    heap_size_i = 0
    #sanitize the heap size config
    if heap_size is not None:
        if not heap_size.isdigit():
            try:
                heap_size_i = int(heap_size[:-1])
                suffix = heap_size[-1]
                if suffix == 'M':
                    heap_size_i /= 1024 #convert to gigs
            except:
                ##invalid suffix length probably. Fall back to default
                heap_size = None
        else:
            heap_size_i = int(heap_size)

    with open('/proc/meminfo', 'r') as fd:
        meminfo = fd.readlines()
        mem = 0
        for m in meminfo:
            if m.startswith('MemTotal:') or m.startswith('SwapTotal:'):
                mem += int(m.split(':')[1].strip().split()[0])

        mem = max(mem/1024/1024/2/instances, 1)
        mem = min(mem, 16)

    if heap_size_i:
        #we take the minimum of the provided heap size and max allowed heap size
        heap_size_i = min(heap_size_i, mem)
    else:
        heap_size_i = mem

    return '{}G'.format(heap_size_i)

class OnosCord(Container):
    """Use this when running the cord tester agent on the onos compute node"""
    onos_cord_dir = os.path.join(os.getenv('HOME'), 'cord-tester-cord')
    onos_config_dir_guest = '/root/onos/config'
    onos_config_dir = os.path.join(onos_cord_dir, 'config')
    docker_yaml = os.path.join(onos_cord_dir, 'docker-compose.yml')
    onos_cfg_save_loc = os.path.join(onos_cord_dir, 'network-cfg.json.saved')

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
        #fetch the current config of onos cord instance
        try:
            self.last_cfg = OnosCtrl.get_config(controller = onos_ip)
        except:
            self.last_cfg = None

    def start(self, restart = False, network_cfg = None):
        if restart is True:
            if self.exists():
                ##Kill the existing instance
                print('Killing container %s' %self.name)
                self.kill()
            if self.xos_onos.exists():
                if self.last_cfg is not None:
                    #save the current network config of onos cord instance
                    json_data = json.dumps(self.last_cfg, indent=4)
                    with open(self.onos_cfg_save_loc, 'w') as f:
                        f.write(json_data)
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

    @classmethod
    def restore_onos_cord(cls, onos_cord, onos_ip):
        #bring down the onos cord wrapper container
        #if there is no saved config, there is nothing to restore as it was never restarted
        if not os.access(cls.onos_cfg_save_loc, os.F_OK):
            return
        if not onos_cord or not os.access(onos_cord, os.F_OK):
            return

        print('Stopping the existing ONOS cord wrapper instance at %s' %(cls.onos_cord_dir))
        cmd = 'cd {} && docker-compose down'.format(cls.onos_cord_dir)
        try:
            os.system(cmd)
        except:pass

        print('Starting the ONOS cord instance at %s' %(onos_cord))
        #bring back up the onos cord container
        cmd = 'cd {} && docker-compose up -d'.format(onos_cord)
        try:
            os.system(cmd)
            time.sleep(30)
        except:
            pass

        #now restore back the old config
        print('Restoring back the saved ONOS cord config at %s for ONOS cord instance' %(cls.onos_cfg_save_loc))
        with open(cls.onos_cfg_save_loc, 'r') as f:
            config = json.load(f)
            try:
                OnosCtrl.config(config, controller = onos_ip)
                os.unlink(cls.onos_cfg_save_loc)
            except: pass

        print('Cleaning up the ONOS cord wrapper directory at %s' %(cls.onos_cord_dir))
        try:
            os.system('rm -rf {}'.format(cls.onos_cord_dir))
        except:
            pass

class OnosCordStopWrapper(Container):
    onos_cord_dir = os.path.join(os.getenv('HOME'), 'cord-tester-cord')
    docker_yaml = os.path.join(onos_cord_dir, 'docker-compose.yml')

    def __init__(self):
        if os.access(self.docker_yaml, os.F_OK):
            with open(self.docker_yaml, 'r') as f:
                yaml_config = yaml.load(f)
                image = yaml_config['services'].keys()[0]
                name = 'cordtestercord_{}_1'.format(image)
            super(OnosCordStopWrapper, self).__init__(name, image, tag = '')
            if self.exists():
                print('Killing container %s' %self.name)
                self.kill()

class Onos(Container):
    QUAGGA_CONFIG = [ { 'bridge' : 'quagga-br', 'ip': '10.10.0.4', 'mask' : 16 }, ]
    MAX_INSTANCES = 3
    JVM_HEAP_SIZE = None
    SYSTEM_MEMORY = (get_mem(),) * 2
    INSTANCE_MEMORY = (get_mem(instances=MAX_INSTANCES),) * 2
    JAVA_OPTS_FORMAT = '-Xms{} -Xmx{} -XX:+UseConcMarkSweepGC -XX:+CMSIncrementalMode'
    JAVA_OPTS_DEFAULT = JAVA_OPTS_FORMAT.format(*SYSTEM_MEMORY) #-XX:+PrintGCDetails -XX:+PrintGCTimeStamps'
    JAVA_OPTS_CLUSTER_DEFAULT = JAVA_OPTS_FORMAT.format(*INSTANCE_MEMORY)
    env = { 'ONOS_APPS' : 'drivers,openflow,proxyarp,vrouter', 'JAVA_OPTS' : JAVA_OPTS_DEFAULT }
    onos_cord_apps = ( ('cord-config', '1.1-SNAPSHOT'),
                       ('aaa', '1.1-SNAPSHOT'),
                       ('igmp', '1.1-SNAPSHOT'),
                       #('vtn', '1.1-SNAPSHOT'),
                       )
    ports = [] #[ 8181, 8101, 9876, 6653, 6633, 2000, 2620 ]
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    host_config_dir = os.path.join(setup_dir, 'onos-config')
    guest_config_dir = '/root/onos/config'
    guest_data_dir = '/root/onos/apache-karaf-3.0.5/data'
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

    @classmethod
    def get_data_map(cls, host_volume, guest_volume_dir):
        host_volume_dir = os.path.join(cls.setup_dir, os.path.basename(host_volume))
        if not os.path.exists(host_volume_dir):
            os.mkdir(host_volume_dir)
        return ( (host_volume_dir, guest_volume_dir), )

    @classmethod
    def remove_data_map(cls, host_volume, guest_volume_dir):
        host_volume_dir = os.path.join(cls.setup_dir, os.path.basename(host_volume))
        if os.path.exists(host_volume_dir):
            rmtree(host_volume_dir)

    def remove_data_volume(self):
        if self.data_map is not None:
            self.remove_data_map(*self.data_map)

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX, tag = TAG,
                 boot_delay = 20, restart = False, network_cfg = None,
                 cluster = False, data_volume = None, async = False, quagga_config = None,
                 network = None):
        if restart is True:
            ##Find the right image to restart
            running_image = filter(lambda c: c['Names'][0] == '/{}'.format(name), self.dckr.containers())
            if running_image:
                image_name = running_image[0]['Image']
                try:
                    image = image_name.split(':')[0]
                    tag = image_name.split(':')[1]
                except: pass

        if quagga_config is None:
            quagga_config = Onos.QUAGGA_CONFIG
        super(Onos, self).__init__(name, image, prefix = prefix, tag = tag, quagga_config = quagga_config)
        self.boot_delay = boot_delay
        self.data_map = None
        instance_memory = (get_mem(jvm_heap_size = Onos.JVM_HEAP_SIZE, instances = Onos.MAX_INSTANCES),) * 2
        self.env['JAVA_OPTS'] = self.JAVA_OPTS_FORMAT.format(*instance_memory)
        if cluster is True:
            self.ports = []
            if data_volume is not None:
                self.data_map = self.get_data_map(data_volume, self.guest_data_dir)
                self.host_guest_map = self.host_guest_map + self.data_map
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
            if cluster is False or async is False:
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
                print('Waiting for ONOS to boot')
                time.sleep(boot_delay)
                self.wait_for_onos_start(self.ip())
                self.running = True
            else:
                self.running = False
        else:
            self.running = True
        if self.running:
            self.ipaddr = self.ip()
            if cluster is False:
                self.install_cord_apps(self.ipaddr)

    @classmethod
    def get_quagga_config(cls, instance = 0):
        quagga_config = copy.deepcopy(cls.QUAGGA_CONFIG)
        if instance == 0:
            return quagga_config
        ip = quagga_config[0]['ip']
        octets = ip.split('.')
        octets[3] = str((int(octets[3]) + instance) & 255)
        ip = '.'.join(octets)
        quagga_config[0]['ip'] = ip
        return quagga_config

    @classmethod
    def start_cluster_async(cls, onos_instances):
        instances = filter(lambda o: o.running == False, onos_instances)
        if not instances:
            return
        tpool = ThreadPool(len(instances), queue_size = 1, wait_timeout = 1)
        for onos in instances:
            tpool.addTask(onos.start_async)
        tpool.cleanUpThreads()

    def start_async(self):
        print('Starting ONOS container %s' %self.name)
        self.start(ports = self.ports, environment = self.env,
                   host_config = self.host_config, volumes = self.volumes, tty = True)
        time.sleep(3)
        self.ipaddr = self.ip()
        print('Waiting for ONOS container %s to start' %self.name)
        self.wait_for_onos_start(self.ipaddr)
        self.running = True
        print('ONOS container %s started' %self.name)

    @classmethod
    def wait_for_onos_start(cls, ip, tries = 30):
        onos_log = OnosLog(host = ip)
        num_tries = 0
        started = None
        while not started and num_tries < tries:
            time.sleep(3)
            started = onos_log.search_log_pattern('ApplicationManager .* Started')
            num_tries += 1

        if not started:
            print('ONOS did not start')
        else:
            print('ONOS started')
        return started

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
    def add_cluster(cls, count = 1, network_cfg = None):
        if not cls.cluster_instances or Onos.cluster_mode is False:
            return
        for i in range(count):
            name = '{}-{}'.format(Onos.NAME, len(cls.cluster_instances)+1)
            onos = cls(name = name, image = Onos.IMAGE, tag = Onos.TAG, prefix = Container.IMAGE_PREFIX,
                       cluster = True, network_cfg = network_cfg)
            cls.cluster_instances.append(onos)

        cls.setup_cluster(cls.cluster_instances)

    @classmethod
    def restart_cluster(cls, network_cfg = None, timeout = 10, setup = False):
        if cls.cluster_mode is False:
            return
        if not cls.cluster_instances:
            return

        if network_cfg is not None:
            json_data = json.dumps(network_cfg, indent=4)
            with open('{}/network-cfg.json'.format(cls.host_config_dir), 'w') as f:
                f.write(json_data)

        cls.cleanup_cluster()
        if timeout > 0:
            time.sleep(timeout)

        #start the instances asynchronously
        cls.start_cluster_async(cls.cluster_instances)
        time.sleep(5)
        ##form the cluster as appropriate
        if setup is True:
            cls.setup_cluster(cls.cluster_instances)
        else:
            for onos in cls.cluster_instances:
                onos.install_cord_apps(onos.ipaddr)

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
            onos.running = False
            onos.remove_container(onos.name, force=True)

    @classmethod
    def restart_node(cls, node = None, network_cfg = None, timeout = 10):
        if node is None:
            cls(restart = True, network_cfg = network_cfg, image = cls.IMAGE, tag = cls.TAG)
        else:
            #Restarts a node in the cluster
            valid_node = filter(lambda onos: node in [ onos.ipaddr, onos.name ], cls.cluster_instances)
            if valid_node:
                onos = valid_node.pop()
                if onos.exists():
                    onos.kill()
                onos.remove_container(onos.name, force=True)
                if timeout > 0:
                    time.sleep(timeout)
                print('Restarting ONOS container %s' %onos.name)
                onos.start(ports = onos.ports, environment = onos.env,
                           host_config = onos.host_config, volumes = onos.volumes, tty = True)
                onos.ipaddr = onos.ip()
                onos.wait_for_onos_start(onos.ipaddr)
                onos.install_cord_apps(onos.ipaddr)

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

class OnosStopWrapper(Container):
    def __init__(self, name):
        super(OnosStopWrapper, self).__init__(name, Onos.IMAGE, tag = Onos.TAG, prefix = Container.IMAGE_PREFIX)
        if self.exists():
            self.kill()
            self.running = False
        else:
            if Onos.cluster_mode is True:
                valid_node = filter(lambda onos: name in [ onos.ipaddr, onos.name ], Onos.cluster_instances)
                if valid_node:
                    onos = valid_node.pop()
                    if onos.exists():
                        onos.kill()
                    onos.running = False

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
                 boot_delay = 10, restart = False, update = False, network = None):
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
            if network is not None:
                Container.connect_to_network(self.name, network)
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
    QUAGGA_CONFIG = ( { 'bridge' : 'quagga-br', 'ip': '10.10.0.3', 'mask' : 16 },
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
                 boot_delay = 15, restart = False, config_file = quagga_config_file, update = False,
                 network = None):
        super(Quagga, self).__init__(name, image, prefix = prefix, tag = tag, quagga_config = self.QUAGGA_CONFIG)
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
            if network is not None:
                Container.connect_to_network(self.name, network)
            print('Starting Quagga on container %s' %self.name)
            self.execute('{0}/start.sh {1}'.format(self.guest_quagga_config, config_file))
            time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image):
        onos_quagga_ip = Onos.QUAGGA_CONFIG[0]['ip']
        print('Building Quagga image %s' %image)
        dockerfile = '''
FROM ubuntu:14.04
MAINTAINER chetan@ciena.com
WORKDIR /root
RUN useradd -M quagga
RUN mkdir /var/log/quagga && chown quagga:quagga /var/log/quagga
RUN mkdir /var/run/quagga && chown quagga:quagga /var/run/quagga
RUN apt-get update && apt-get install -qy git autoconf libtool gawk make telnet libreadline6-dev pkg-config protobuf-c-compiler
RUN git clone git://git.savannah.nongnu.org/quagga.git quagga && \
(cd quagga && git checkout quagga-1.0.20160315 && ./bootstrap.sh && \
sed -i -r 's,htonl.*?\(INADDR_LOOPBACK\),inet_addr\("{0}"\),g' zebra/zebra_fpm.c && \
./configure --enable-fpm --disable-doc --localstatedir=/var/run/quagga && make && make install)
RUN ldconfig
'''.format(onos_quagga_ip)
        super(Quagga, cls).build_image(dockerfile, image)
        print('Done building image %s' %image)

class QuaggaStopWrapper(Container):
    def __init__(self, name = Quagga.NAME, image = Quagga.IMAGE, tag = 'candidate'):
        super(QuaggaStopWrapper, self).__init__(name, image, prefix = Container.IMAGE_PREFIX, tag = tag)
        if self.exists():
            self.kill()


def reinitContainerClients():
    docker_netns.dckr = Client()
    Container.dckr = Client()

class Xos(Container):
    setup_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', 'setup')
    TAG = 'latest'
    PREFIX = ''
    host_guest_map = None
    env = None
    ports = None
    volumes = None

    @classmethod
    def get_cmd(cls, img_name):
        cmd = cls.dckr.inspect_image(img_name)['Config']['Cmd']
        return ' '.join(cmd)

    def __init__(self, name, image, prefix = PREFIX, tag = TAG,
                 boot_delay = 20, restart = False, network_cfg = None, update = False):
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
        self.command = self.get_cmd(self.image_name).strip() or None
        if restart is True and self.exists():
            self.kill()
        if not self.exists():
            self.remove_container(name, force=True)
            host_config = self.create_host_config(port_list = self.ports,
                                                  host_guest_map = self.host_guest_map,
                                                  privileged = True)
            print('Starting XOS container %s' %self.name)
            self.start(ports = self.ports, environment = self.env, host_config = host_config,
                       volumes = self.volumes, tty = True)
            print('Waiting %d seconds for XOS Base Container to boot' %(boot_delay))
            time.sleep(boot_delay)

    @classmethod
    def build_image(cls, image, dockerfile_path, image_target = 'build'):
        cmd = 'cd {} && make {}'.format(dockerfile_path, image_target)
        print('Building XOS %s' %image)
        res = os.system(cmd)
        print('Done building image %s. Image build %s' %(image, 'successful' if res == 0 else 'failed'))
        return res

class XosServer(Xos):
    ports = [8000,9998,9999]
    NAME = 'xos-server'
    IMAGE = 'xosproject/xos'
    BASE_IMAGE = 'xosproject/xos-base'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'xos')

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX, tag = TAG,
                 boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        ##build the base image and then build the server image
        Xos.build_image(cls.BASE_IMAGE, cls.dockerfile_path, image_target = 'base')
        Xos.build_image(image, cls.dockerfile_path)

class XosSynchronizerOpenstack(Xos):
    ports = [2375,]
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer')
    NAME = 'xos-synchronizer'
    IMAGE = 'xosproject/xos-synchronizer-openstack'
    TAG = 'latest'
    PREFIX = ''
    host_guest_map = ( ('/usr/local/share/ca-certificates', '/usr/local/share/ca-certificates'),)

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX,
                 tag = TAG, boot_delay = 20, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        XosServer.build_image()
        Xos.build_image(image, cls.dockerfile_path)

class XosSynchronizerOnboarding(Xos):
    NAME = 'xos-synchronizer-onboarding'
    IMAGE = 'xosproject/xos-synchronizer-onboarding'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'onboarding_synchronizer')
    host_guest_map = ( ('/usr/local/share/ca-certificates', '/usr/local/share/ca-certificates'),)

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX,
                 tag = TAG, boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        XosSynchronizerOpenstack.build_image()
        Xos.build_image(image, cls.dockerfile_path)

class XosSynchronizerOpenvpn(Xos):
    NAME = 'xos-synchronizer-openvpn'
    IMAGE = 'xosproject/xos-openvpn'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'openvpn')
    host_guest_map = ( ('/usr/local/share/ca-certificates', '/usr/local/share/ca-certificates'),)

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX,
                 tag = TAG, boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        XosSynchronizerOpenstack.build_image()
        Xos.build_image(image, cls.dockerfile_path)

class XosPostgresql(Xos):
    ports = [5432,]
    NAME = 'xos-db-postgres'
    IMAGE = 'xosproject/xos-postgres'
    TAG = 'latest'
    PREFIX = ''
    volumes = ["/etc/postgresql", "/var/log/postgresql", "/var/lib/postgresql"]
    dockerfile_path = os.path.join(Xos.setup_dir, 'postgresql')

    def __init__(self, name = NAME, image = IMAGE, prefix = PREFIX,
                 tag = TAG, boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

class XosSyndicateMs(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-syndicate-ms'
    IMAGE = 'xosproject/syndicate-ms'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'syndicate-ms')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

class XosSyncVtn(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-synchronizer-vtn'
    IMAGE = 'xosproject/xos-synchronizer-vtn'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer-vtn')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

class XosSyncVtr(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-synchronizer-vtr'
    IMAGE = 'xosproject/xos-synchronizer-vtr'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer-vtr')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

class XosSyncVsg(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-synchronizer-vsg'
    IMAGE = 'xosproject/xos-synchronizer-vsg'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer-vsg')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 10, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)


class XosSyncOnos(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-synchronizer-onos'
    IMAGE = 'xosproject/xos-synchronizer-onos'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer-onos')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 30, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

class XosSyncFabric(Xos):
    ports = [8080,]
    env = None
    NAME = 'xos-synchronizer-fabric'
    IMAGE = 'xosproject/xos-synchronizer-fabric'
    TAG = 'latest'
    PREFIX = ''
    dockerfile_path = os.path.join(Xos.setup_dir, 'synchronizer-fabric')

    def __init__(self, name = NAME, image = IMAGE, prefix = '', tag = TAG,
                 boot_delay = 30, restart = False, network_cfg = None, update = False):
        Xos.__init__(self, name, image, prefix, tag, boot_delay, restart, network_cfg, update)

    @classmethod
    def build_image(cls, image = IMAGE):
        Xos.build_image(image, cls.dockerfile_path)

if __name__ == '__main__':
    onos = Onos(boot_delay = 10, restart = True)
