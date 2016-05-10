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
import SocketServer as socketserver
import threading
import socket
from CordContainer import Onos, Quagga
from nose.tools import nottest

##Server to handle container restart requests from test container.
##Used now to restart ONOS from vrouter test container

CORD_TEST_HOST = '172.17.0.1'
CORD_TEST_PORT = 25000

class CordTestServer(socketserver.BaseRequestHandler):

    def restart_onos(self, *args):
        print('Restarting ONOS')
        onos = Onos(restart = True)
        self.request.sendall('DONE')

    def restart_quagga(self, *args):
        config_file = Quagga.quagga_config_file
        boot_delay = 15
        if args:
            config_file = args[0]
            if len(args) > 1:
                boot_delay = int(args[1])
        print('Restarting QUAGGA with config file %s, delay %d secs'%(config_file, boot_delay))
        quagga = Quagga(restart = True, config_file = config_file, boot_delay = boot_delay)
        self.request.sendall('DONE')

    def restart_radius(self, *args):
        print('Restarting RADIUS Server')
        radius = Radius(restart = True)
        self.request.sendall('DONE')

    callback_table = { 'RESTART_ONOS' : restart_onos,
                       'RESTART_QUAGGA' : restart_quagga,
                       'RESTART_RADIUS' : restart_radius,
                     }

    def handle(self):
        data = self.request.recv(1024).strip()
        cmd = data.split()[0]
        try:
            #args = ' '.join(data.split()[1:])
            args = data.split()[1:]
        except:
            args = None

        if self.callback_table.has_key(cmd):
            self.callback_table[cmd](self, *args)

class ThreadedTestServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

@nottest
def cord_test_server_start():
    server = ThreadedTestServer( (CORD_TEST_HOST, CORD_TEST_PORT), CordTestServer)
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
def cord_test_onos_restart():
    '''Send ONOS restart to server'''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect( (CORD_TEST_HOST, CORD_TEST_PORT) )
    s.sendall('RESTART_ONOS\n')
    data = s.recv(1024).strip()
    s.close()
    if data == 'DONE':
        return True
    return False

@nottest
def cord_test_quagga_restart(config_file = None, boot_delay = 30):
    '''Send QUAGGA restart to server'''
    if config_file is None:
        config_file = Quagga.quagga_config_file
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect( (CORD_TEST_HOST, CORD_TEST_PORT) )
    s.sendall('RESTART_QUAGGA {0} {1}\n'.format(config_file, boot_delay))
    data = s.recv(1024).strip()
    s.close()
    if data == 'DONE':
        return True
    return False

@nottest
def cord_test_radius_restart():
    '''Send Radius server restart to server'''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect( (CORD_TEST_HOST, CORD_TEST_PORT) )
    s.sendall('RESTART_RADIUS\n')
    data = s.recv(1024).strip()
    s.close()
    if data == 'DONE':
        return True
    return False
