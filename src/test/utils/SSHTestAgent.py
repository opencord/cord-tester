import os, sys
from paramiko import SSHClient, WarningPolicy, AutoAddPolicy
from CordTestServer import CORD_TEST_HOST
from scapy.all import *

class SSHTestAgent(object):
    key_file = os.getenv('SSH_KEY_FILE', None)
    host = os.getenv('CORD_TEST_HOST', CORD_TEST_HOST)
    user = 'ubuntu'
    password = None

    def __init__(self, user = user, password = password):
        self.user = user
        self.password = password
        self.client = SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(AutoAddPolicy())

    def run_cmd(self, cmd, timeout = 5):
        """Run the command on the test host"""
        try:
            self.client.connect(self.host, username = self.user, password = self.password,
                                key_filename = self.key_file, timeout=timeout)
        except:
            log.error('Unable to connect to test host %s' %self.host)
            return False, None
        
        channel = self.client.get_transport().open_session()
        channel.exec_command(cmd)
        status = channel.recv_exit_status()
        output = None
        st = status == 0
        if st:
            output = ''
            while True:
                data = channel.recv(4096)
                if data:
                    output += data
                else:
                    break
        channel.close()
        return st, output

if __name__ == '__main__':
    agent = SSHTestAgent(user = 'ubuntu', password = 'ubuntu')
    cmds = ('docker images', 'docker ps')
    for cmd in cmds:
        st, output = agent.run_cmd(cmd)
        print('Command \"%s\" returned with status: %s' %(cmd, st))
        if st:
            print('%s\n' %output)
