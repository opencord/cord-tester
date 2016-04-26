import SocketServer as socketserver
import threading
import socket
from CordContainer import Onos
from nose.tools import nottest

##Server to handle container restart requests from test container.
##Used now to restart ONOS from vrouter test container

CORD_TEST_HOST = '172.17.0.1'
CORD_TEST_PORT = 25000

class CordTestServer(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024).strip()
        if data == 'RESTART_ONOS':
            print('Restarting ONOS')
            onos = Onos(restart = True)
            self.request.sendall('DONE')

class ThreadedTestServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

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
    if data == 'DONE':
        return True
    return False
