
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
from CordContainer import Container, Onos, OnosStopWrapper, OnosCord, OnosCordStopWrapper, Quagga, QuaggaStopWrapper, Radius, reinitContainerClients
from OltConfig import OltConfig
from EapolAAA import get_radius_macs, get_radius_networks
from nose.tools import nottest
from SimpleXMLRPCServer import SimpleXMLRPCServer
from resource import getrlimit, RLIMIT_NOFILE
import daemon
import xmlrpclib
import os
import signal
import json
import time
import threading

##Server to handle container restart/stop requests from test container.
##Used now to restart ONOS from vrouter test container

CORD_TEST_HOST = '172.17.0.1'
CORD_TEST_PORT = 25000

class CordTestServer(object):

    onos_cord = None

    def __restart_onos(self, node = None, config = None, timeout = 10):
        if self.onos_cord:
            onos_config = '{}/network-cfg.json'.format(self.onos_cord.onos_config_dir)
        else:
            onos_config = '{}/network-cfg.json'.format(Onos.host_config_dir)
        if config is None:
            try:
                os.unlink(onos_config)
            except:
                pass
        print('Restarting ONOS')
        if self.onos_cord:
            self.onos_cord.start(restart = True, network_cfg = config)
        else:
            Onos.restart_node(node = node, network_cfg = config, timeout = timeout)
        return 'DONE'

    def restart_onos(self, kwargs):
        return self.__restart_onos(**kwargs)

    def __shutdown_onos(self, node = None):
        if node is None:
            node = Onos.NAME
        OnosStopWrapper(node)
        return 'DONE'

    def shutdown_onos(self, kwargs):
        return self.__shutdown_onos(**kwargs)

    def __restart_cluster(self, config = None, timeout = 10, setup = False):
        Onos.restart_cluster(network_cfg = config, timeout = timeout, setup = setup)
        return 'DONE'

    def restart_cluster(self, kwargs):
        return self.__restart_cluster(**kwargs)

    def __add_cluster_onos(self, count = 1, config = None):
        Onos.add_cluster(count = count, network_cfg = config)
        return 'DONE'

    def add_cluster_onos(self, kwargs):
        return self.__add_cluster_onos(**kwargs)

    def __restart_quagga(self, config = None, boot_delay = 30 ):
        config_file = Quagga.quagga_config_file
        if config is not None:
            quagga_config = '{}/testrib_gen.conf'.format(Quagga.host_quagga_config)
            config_file = '{}/testrib_gen.conf'.format(Quagga.guest_quagga_config)
            with open(quagga_config, 'w+') as fd:
                fd.write(str(config))
        print('Restarting QUAGGA with config file %s, delay %d' %(config_file, boot_delay))
        Quagga(prefix = Container.IMAGE_PREFIX, restart = True, config_file = config_file, boot_delay = boot_delay)
        return 'DONE'

    def restart_quagga(self, kwargs):
        return self.__restart_quagga(**kwargs)

    def stop_quagga(self):
        quaggaStop = QuaggaStopWrapper()
        time.sleep(5)
        try:
            quagga_config_gen = '{}/testrib_gen.conf'.format(Quagga.host_quagga_config)
            os.unlink(quagga_config_gen)
        except: pass
        return 'DONE'

    def __run_shell_quagga(self, cmd = None):
        ret = 0
        if cmd is not None:
            exec_cmd = 'docker exec {} {}'.format(Quagga.NAME, cmd)
            ret = os.system(exec_cmd)
        return ret

    def __run_shell(self, cmd = None):
        ret = 0
        if cmd is not None:
            ret = os.system(cmd)
        return ret

    def run_shell_quagga(self, kwargs):
        return self.__run_shell_quagga(**kwargs)

    def run_shell(self, kwargs):
        return self.__run_shell(**kwargs)

    def __restart_radius(self, olt_conf_file = ''):
        olt_conf = os.path.join(Onos.setup_dir, os.path.basename(olt_conf_file))
        olt = OltConfig(olt_conf_file = olt_conf)
        port_map, _ = olt.olt_port_map()
        Radius(prefix = Container.IMAGE_PREFIX, restart = True)
        radius_macs = get_radius_macs(len(port_map['radius_ports']))
        radius_networks = get_radius_networks(len(port_map['switch_radius_port_list']))
        radius_intf_index = 0
        index = 0
        for host_intf, ports in port_map['switch_radius_port_list']:
            prefix, subnet, _ = radius_networks[index]
            mask = subnet.split('/')[-1]
            index += 1
            for port in ports:
                guest_if = 'eth{}'.format(radius_intf_index + 2)
                port_index = port_map[port]
                local_if = 'r{}'.format(port_index)
                guest_ip = '{}.{}/{}'.format(prefix, port_index, mask)
                mac = radius_macs[radius_intf_index]
                radius_intf_index += 1
                pipework_cmd = 'pipework {0} -i {1} -l {2} {3} {4} {5}'.format(host_intf, guest_if,
                                                                               local_if, Radius.NAME,
                                                                               guest_ip, mac)
                print('Configuring Radius port %s on OVS bridge %s' %(guest_if, host_intf))
                print('Running pipework command: %s' %(pipework_cmd))
                res = os.system(pipework_cmd)

    def restart_radius(self, kwargs):
        print('Restarting RADIUS Server')
        self.__restart_radius(**kwargs)
        return 'DONE'

    def shutdown(self):
        print('Shutting down cord test server')
        os.kill(0, signal.SIGKILL)
        return 'DONE'

def find_files_by_path(*paths):
    wanted = []
    for p in paths:
        try:
            fd = os.open(p, os.O_RDONLY)
            wanted.append(os.fstat(fd)[1:3])
        finally:
            os.close(fd)

    def fd_wanted(fd):
        try:
            return os.fstat(fd)[1:3] in wanted
        except OSError:
            return False

    max_fd = getrlimit(RLIMIT_NOFILE)[1]
    return [ fd for fd in xrange(max_fd) if fd_wanted(fd) ]

@nottest
def cord_test_server_start(daemonize = True,
                           cord_test_host = CORD_TEST_HOST,
                           cord_test_port = CORD_TEST_PORT,
                           onos_cord = None,
                           foreground=False):
    server = SimpleXMLRPCServer( (cord_test_host, cord_test_port) )
    server.register_instance(CordTestServer())
    CordTestServer.onos_cord = onos_cord
    if daemonize is True:
        ##before daemonizing, preserve urandom needed by paramiko
        preserve_list = find_files_by_path('/dev/urandom')
        preserve_list.append(server)
        d = daemon.DaemonContext(files_preserve = preserve_list,
                                 detach_process = True)
        with d:
            reinitContainerClients()
            server.serve_forever()
    else:
        if foreground:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                return server
        else:
            task = threading.Thread(target = server.serve_forever)
            ##terminate when main thread exits
            task.daemon = True
            task.start()
    return server

@nottest
def cord_test_server_stop(server):
    server.shutdown()
    server.server_close()

@nottest
def get_cord_test_loc():
    host = os.getenv('CORD_TEST_HOST', CORD_TEST_HOST)
    port = int(os.getenv('CORD_TEST_PORT', CORD_TEST_PORT))
    return host, port

def rpc_server_instance():
    '''Stateless'''
    host, port = get_cord_test_loc()
    rpc_server = 'http://{}:{}'.format(host, port)
    return xmlrpclib.Server(rpc_server, allow_none = True)

@nottest
def __cord_test_onos_restart(**kwargs):
    return rpc_server_instance().restart_onos(kwargs)

@nottest
def cord_test_onos_restart(node = None, config = None, timeout = 10):
    '''Send ONOS restart to server'''
    for i in range(3):
        try:
            data = __cord_test_onos_restart(node = node, config = config, timeout = timeout)
            if data == 'DONE':
                return True
        except:
            time.sleep(2)

    return False

@nottest
def __cord_test_onos_shutdown(**kwargs):
    return rpc_server_instance().shutdown_onos(kwargs)

@nottest
def cord_test_onos_shutdown(node = None):
    data = __cord_test_onos_shutdown(node = node)
    if data == 'DONE':
        return True
    return False

@nottest
def __cord_test_restart_cluster(**kwargs):
    return rpc_server_instance().restart_cluster(kwargs)

@nottest
def cord_test_restart_cluster(config = None, timeout = 10, setup = False):
    for i in range(3):
        try:
            data = __cord_test_restart_cluster(config = config, timeout = timeout, setup = setup)
            if data == 'DONE':
                return True
        except:
            time.sleep(2)

    return False

@nottest
def __cord_test_onos_add_cluster(**kwargs):
    return rpc_server_instance().add_cluster_onos(kwargs)

@nottest
def cord_test_onos_add_cluster(count = 1, config = None):
    data = __cord_test_onos_add_cluster(count = count, config = config)
    if data == 'DONE':
        return True
    return False

@nottest
def __cord_test_quagga_restart(**kwargs):
    return rpc_server_instance().restart_quagga(kwargs)

@nottest
def __cord_test_radius_restart(**kwargs):
    return rpc_server_instance().restart_radius(kwargs)

@nottest
def cord_test_quagga_restart(config = None, boot_delay = 30):
    '''Send QUAGGA restart to server'''
    data = __cord_test_quagga_restart(config = config, boot_delay = boot_delay)
    if data == 'DONE':
        return True
    return False

@nottest
def __cord_test_quagga_shell(**kwargs):
    return rpc_server_instance().run_shell_quagga(kwargs)

@nottest
def cord_test_quagga_shell(cmd = None):
    '''Send QUAGGA shell cmd to server'''
    return __cord_test_quagga_shell(cmd = cmd)

@nottest
def __cord_test_shell(**kwargs):
    return rpc_server_instance().run_shell(kwargs)

@nottest
def cord_test_shell(cmd = None):
    '''Send shell cmd to run remotely'''
    return __cord_test_shell(cmd = cmd)

@nottest
def cord_test_quagga_stop():
    data = rpc_server_instance().stop_quagga()
    if data == 'DONE':
        return True
    return False

@nottest
def cord_test_radius_restart(olt_conf_file = ''):
    '''Send Radius server restart to server'''
    if not olt_conf_file:
        olt_conf_file = os.getenv('OLT_CONFIG')
    olt_conf_file = os.path.basename(olt_conf_file)
    data = __cord_test_radius_restart(olt_conf_file = olt_conf_file)
    if data == 'DONE':
        return True
    return False

@nottest
def cord_test_server_shutdown(host, port):
    '''Shutdown the cord test server'''
    rpc_server = 'http://{}:{}'.format(host, port)
    try:
        xmlrpclib.Server(rpc_server, allow_none = True).shutdown()
    except: pass

    return True
