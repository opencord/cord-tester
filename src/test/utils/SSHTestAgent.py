
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


import os, sys, time
from paramiko import SSHClient, WarningPolicy, AutoAddPolicy
import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from CordTestUtils import log_test

class SSHTestAgent(object):
    key_file = os.getenv('SSH_KEY_FILE', None)
    host = os.getenv('CORD_TEST_HOST', '172.17.0.1')
    hosts_file = os.path.join(os.getenv('HOME'), '.ssh', 'known_hosts')
    user = 'ubuntu'
    password = None

    def __init__(self, host = host, user = user, password = password, port = 22):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.client = SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy())

    def run_cmd(self, cmd, timeout = 5):
        """Run the command on the test host"""
        host_remove = 'ssh-keygen -f "%s" -R [%s]:8101 2>/dev/null' %(self.hosts_file, self.host)
        try:
            os.system(host_remove)
        except: pass

        try:
            self.client.connect(self.host, username = self.user, password = self.password,
                                key_filename = self.key_file, timeout=timeout, port = self.port)
        except:
            log_test.error('Unable to connect to test host %s' %self.host)
            return False, None

        channel = self.client.get_transport().open_session()
        channel.exec_command(cmd)
        status_ready = False
        if channel.exit_status_ready():
            status = channel.recv_exit_status()
            status_ready = True
        else:
            status = 0
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
        if status_ready is False:
            status = channel.recv_exit_status()
            st = status == 0
        time.sleep(0.1)
        channel.close()
        self.client.close()
        return st, output

if __name__ == '__main__':
    agent = SSHTestAgent(user = 'ubuntu', password = 'ubuntu')
    cmds = ('docker images', 'docker ps')
    for cmd in cmds:
        st, output = agent.run_cmd(cmd)
        print('Command \"%s\" returned with status: %s' %(cmd, st))
        if st:
            print('%s\n' %output)
