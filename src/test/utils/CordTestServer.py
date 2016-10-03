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
from CordContainer import Container, Onos, OnosCord, Quagga, Radius, reinitContainerClients
from nose.tools import nottest
from SimpleXMLRPCServer import SimpleXMLRPCServer
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

class QuaggaStopWrapper(Container):
    def __init__(self, name = Quagga.NAME, image = Quagga.IMAGE, tag = 'candidate'):
        super(QuaggaStopWrapper, self).__init__(name, image, prefix = Container.IMAGE_PREFIX, tag = tag)
        if self.exists():
            self.kill()

class CordTestServer(object):

    onos_cord = None

    def __restart_onos(self, node = None, config = None):
        if self.onos_cord:
            onos_config = '{}/network-cfg.json'.format(OnosCord.onos_config_dir)
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
            Onos.restart_node(node = node, network_cfg = config)
        return 'DONE'

    def restart_onos(self, kwargs):
        return self.__restart_onos(**kwargs)

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

    def restart_radius(self):
        print('Restarting RADIUS Server')
        Radius(prefix = Container.IMAGE_PREFIX, restart = True)
        return 'DONE'

    def shutdown(self):
        print('Shutting down cord test server')
        os.kill(0, signal.SIGKILL)
        return 'DONE'

@nottest
def cord_test_server_start(daemonize = True, cord_test_host = CORD_TEST_HOST,
                           cord_test_port = CORD_TEST_PORT, onos_cord = None):
    server = SimpleXMLRPCServer( (cord_test_host, cord_test_port) )
    server.register_instance(CordTestServer())
    CordTestServer.onos_cord = onos_cord
    if daemonize is True:
        d = daemon.DaemonContext(files_preserve = [server],
                                 detach_process = True)
        with d:
            reinitContainerClients()
            server.serve_forever()
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
def cord_test_onos_restart(node = None, config = None):
    '''Send ONOS restart to server'''
    data = __cord_test_onos_restart(node = node, config = config)
    if data == 'DONE':
        return True
    return False

@nottest
def __cord_test_quagga_restart(**kwargs):
    return rpc_server_instance().restart_quagga(kwargs)

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
def cord_test_radius_restart():
    '''Send Radius server restart to server'''
    data = rpc_server_instance().restart_radius()
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
