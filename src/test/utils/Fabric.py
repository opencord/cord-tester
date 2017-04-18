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
import os, sys
import json
import platform
import subprocess
from apiclient.maas_client import MAASOAuth, MAASDispatcher, MAASClient
from paramiko import SSHClient, WarningPolicy, AutoAddPolicy

class FabricMAAS(object):
    CORD_TEST_HOST = '172.17.0.1'
    head_node = os.getenv('HEAD_NODE', CORD_TEST_HOST)
    maas_url = 'http://{}/MAAS/api/1.0/'.format(head_node)

    def __init__(self, api_key = None, url = maas_url):
        if api_key == None:
            self.api_key = self.get_api_key()
        else:
            self.api_key = api_key
        self.auth = MAASOAuth(*self.api_key.split(':'))
        self.url = url
        self.client = MAASClient(self.auth, MAASDispatcher(), self.url)

    @classmethod
    def get_api_key(cls):
        api_key = os.getenv('MAAS_API_KEY', None)
        if api_key:
            return api_key
        cmd = ['maas-region-admin', 'apikey', '--username=cord']
        try:
            p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        except:
            return 'UNKNOWN'
        out, err = p.communicate()
        if err:
            raise Exception('Cannot get api key for MAAS')
        return out.strip()

    def get_node_list(self):
        nodes = self.client.get(u'nodes/', 'list').read()
        node_list = json.loads(nodes)
        hosts = [ self.head_node ] +  map(lambda n: n['hostname'], node_list)
        return hosts

class Fabric(object):
    entropy = 1
    simulation = False
    def __init__(self, node_list, user = 'ubuntu', passwd = 'ubuntu', key_file = None, verbose = False):
        self.cur_node = None
        if Fabric.simulation:
            self.cur_node = FabricMAAS.head_node
        self.node_list = node_list
        self.users = [ user ]
        if 'vagrant' not in self.users:
            self.users.append('vagrant')
        if 'ubuntu' not in self.users:
            self.users.append('ubuntu')
        self.passwd = passwd
        self.key_file = key_file
        self.verbose = verbose
        self.client = SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(AutoAddPolicy())

    def run_cmd(self, node, neighbor, cmd, simulation = False):
        if simulation is True:
            Fabric.entropy = Fabric.entropy ^ 1
            return bool(Fabric.entropy)
        if node == self.cur_node:
            res = os.system(cmd)
            return res == 0
        ssh_user = None
        for user in self.users:
            try:
                self.client.connect(node, username = user, key_filename = self.key_file, timeout = 5)
                ssh_user = user
                break
            except:
                continue

        if ssh_user is None:
            print('Unable to ssh to node %s for neighbor %s' %(node, neighbor))
            return False
        else:
            if self.verbose:
                print('ssh connection to node %s with user %s' %(node, ssh_user))
        channel = self.client.get_transport().open_session()
        channel.exec_command(cmd)
        status = channel.recv_exit_status()
        channel.close()
        if self.verbose:
            print('Cmd %s returned with status %d on node %s for neighbor %s' %(cmd, status, node, neighbor))
        return status == 0

    def ping_neighbor(self, node, neighbor):
        cmd = 'ping -c 1 -w 2 {}'.format(neighbor)
        return self.run_cmd(node, neighbor, cmd, Fabric.simulation)

    def ping_neighbors(self):
        result_map = []
        for n in self.node_list:
            for adj in self.node_list:
                if adj == n:
                    continue
                res = self.ping_neighbor(n, adj)
                result_map.append((n,adj,res))

        ##report
        if self.verbose:
            for node, neighbor, res in result_map:
                print('Ping from node %s to neighbor %s returned %s\n' %(node, neighbor, res))

        failed_nodes = filter(lambda f: f[2] == False, result_map)
        return failed_nodes

if __name__ == '__main__':
    if len(sys.argv) > 1:
        nodes_file = sys.argv[1]
        with open(nodes_file, 'r') as fd:
            nodes = json.load(fd)
        node_list = nodes['node_list']
    else:
        m = FabricMAAS()
        node_list = m.get_node_list()
        print('Node list: %s' %node_list)
    key_file = os.getenv('SSH_KEY_FILE', None)
    Fabric.simulation = True if key_file is None else False
    fab = Fabric(node_list, verbose = True, key_file = key_file)
    failed_nodes = fab.ping_neighbors()
    if failed_nodes:
        print('Failed nodes: %s' %failed_nodes)
        for node, neighbor, _ in failed_nodes:
            print('Ping from node %s to neighbor %s Failed' %(node, neighbor))
    else:
        print('Fabric test between nodes %s is successful' %node_list)
