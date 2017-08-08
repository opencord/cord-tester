
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


import os
import shutil
import re
from novaclient import client as nova_client
import novaclient.v1_1.client as novaclient
from SSHTestAgent import SSHTestAgent
from CordTestUtils import *
from CordTestUtils import log_test as log

log.setLevel('INFO')

class OnboardingServiceUtils(object):

    @classmethod
    def setUp(cls):
        pass

    @classmethod
    def tearDown(cls):
        pass

    '''
    @method: get_nova_credentials_v2
    @Description: Get nova credentials
    @params:
    returns credential from env
    '''
    @classmethod
    def get_nova_credentials_v2(cls):
        credential = {}
        credential['username'] = os.environ['OS_USERNAME']
        credential['api_key'] = os.environ['OS_PASSWORD']
        credential['auth_url'] = os.environ['OS_AUTH_URL']
        credential['project_id'] = os.environ['OS_TENANT_NAME']
        return credential

    '''
    @method: get_compute_nodes
    @Description: Get the list of compute nodes
    @params:
    returns  node list
    '''
    @classmethod
    def get_compute_nodes(cls):
        credentials = cls.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        return nvclient.hypervisors.list()

    '''
    @method: get_exampleservices
    @Description: Get list of exampleservice's running in compute node
    @params: status of exampleservice
    returns exampleservice wrappers
    '''
    @classmethod
    def get_exampleservices(cls, active = True):
        credentials = cls.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        exampleservices = nvclient.servers.list(search_opts = {'all_tenants': 1})
        if active is True:
            exampleservices = filter(lambda exampleservice: exampleservice.status == 'ACTIVE', exampleservices)
        exampleservice_wrappers = []
        for exampleservice in exampleservices:
            exampleservice_wrappers.append(ExampleSeviceWrapper(exampleservice))
        return exampleservice_wrappers

    '''
    @method: health_check
    @Description: Check if exampleservices are reachable
    @params:
    returns True
    '''
    @classmethod
    def health_check(cls):
        '''Returns 0 if all active exampleservices are reachable through the compute node'''
        exampleservices = cls.get_exampleservices()
        exampleservice_status = []
        for exampleservice in exampleservices:
            exampleservice_status.append(exampleservice.get_health())
        unreachable = filter(lambda st: st == False, exampleservice_status)
        return len(unreachable) == 0

    def make_veth_pairs(self):

        def check_iface(iface):
            return os.system('ip link show {}'.format(iface)) == 0

        def make_veth(iface):
            os.system('ip link add type veth')
            os.system('ip link set {} up'.format(iface))
            peer = iface[:len('veth')] + str(int(iface[len('veth'):]) + 1)
            os.system('ip link set {} up'.format(peer))
            assert has_iface(iface)

        for iface_number in (0, 2):
            iface = 'veth{}'.format(iface_number)
            if not check_iface(iface):
                make_veth(iface)
                yield asleep(2)

    def source_env(self):
        a_dir = os.path.abspath(os.path.dirname(__file__))
        res = os.system('cd {}'.format(a_dir))
        assert res == 0

        # set the env
        command = ['bash', '-c', '. env.sh']
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        if proc.wait() != 0:
            err_msg = "Failed to source the environment'"
            raise RuntimeError(err_msg)

        env = os.environ.copy()
        return env

    @classmethod
    def discover_exampleservice_vm_instance_on_cord(cls, tenant_name):
        name=None
        status=None
        try:
            credentials = cls.get_nova_credentials_v2()
            nvclient = nova_client.Client('2', **credentials)
            instance_list=nvclient.servers.list()
            if instance_list > 0:

               for inst in instance_list:

                   instance_id = inst.id
                   name=inst.name
                   inst_find=nvclient.servers.find(id=instance_id)
                   print('   - Instance %s Discovered' % inst.name)
                   print('   - Instance ID %s Discovered' % instance_id)
                   print('   - Instance %s Status' % inst.status)
                   status=inst.status
        except Exception:
            print('   - Instance Not Found')
            status = False

        instance_data = {'instance_name': name,
                                'status': status }
        return instance_data


    @classmethod
    def terminate_exampleservice_instance_vm_on_cord(cls, tenant_name, vm_name, network_id):
        credentials = cls.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        nvclient.quotas.delete(tenant_name)
        try:
            instance = nvclient.servers.find(name=vm_name)
            nvclient.servers.delete(instance.id)
            print "  * Instance terminated on cord: " + str(network_id)
        except Exception:
            print "  * Instance Not Found on cord: " + str(network_id)
            pass
        return True

class ExampleSeviceWrapper(object):

    def __init__(self, exampleservice):
        self.exampleservice = exampleservice
        self.name = self.exampleservice.name
        self.compute_node = self.get_compute_node()
        self.ip = self.get_ip()

    '''
    @method: get_compute_node
    @Description:
    @params:
    returns compute node name
    '''
    def get_compute_node(self):
        return self.exampleservice._info['OS-EXT-SRV-ATTR:hypervisor_hostname']

    '''
    @method: get_ip
    @Description:
    @params:
    returns ip of network
    '''
    def get_ip(self):
        if 'management' in self.exampleservice.networks:
            ips = self.exampleservice.networks['management']
            if len(ips) > 0:
                return ips[0]
        return None

    def get_public_ip(self):
        if 'public' in self.exampleservice.networks:
            ips = self.exampleservice.networks['public']
            if len(ips) > 0:
                return ips[0]
        return None

    def get_name(self):
        return  self.exampleservice.name

    '''
    @method: run_cmd_compute
    @Description:
    @params:
    returns Status & output
    '''
    def run_cmd_compute(self, cmd, timeout = 5):
        ssh_agent = SSHTestAgent(self.compute_node)
        st, output = ssh_agent.run_cmd(cmd, timeout = timeout)
        if st == True and output:
            output = output.strip()
        else:
            output = None

        return st, output

    '''
    @method: get_health
    @Description:
    @params:
    returns Status
    '''
    def get_health(self):
        if self.ip is None:
            return True
        cmd = 'ping -c 1 {}'.format(self.ip)
        log.info('Pinging ONBOARDED SERVICE %s at IP %s' %(self.name, self.ip))
        st, _ = self.run_cmd_compute(cmd)
        log.info('ONBOARDED SERVICE %s at IP %s is %s' %(self.name, self.ip, 'reachable' if st == True else 'unreachable'))
        return st

    '''
    @method: check_access
    @Description: validates access
    @params:
    returns Status
    '''
    def check_access(self):
        if self.ip is None:
           return True
        ssh_agent = SSHTestAgent(self.compute_node)
        st, _ = ssh_agent.run_cmd('ls', timeout=10)
        if st == False:
            log.error('Compute node at %s is not accessible' %(self.compute_node))
            return st
        log.info('Checking if ONBOARDING SERVICE at %s is accessible from compute node %s' %(self.ip, self.compute_node))
        st, _ = ssh_agent.run_cmd('ssh {} ls'.format(self.ip), timeout=30)
        if st == True:
            log.info('OK')
        return st

    '''
    @method: Validate services
    @Description: This validates if expected service is running in example service VM
    @params:
    returns Status
    '''
    def validate_service_in_vm(self):
        if self.ip is None:
           return True
        ssh_agent = SSHTestAgent(self.compute_node)
        st, _ = ssh_agent.run_cmd('ls', timeout=10)
        if st == False:
            log.error('Compute node at %s is not accessible' %(self.compute_node))
            return st
        log.info('Checking if APACHE SERVICE at %s is running %s' %(self.ip, self.compute_node))
        st, _ = ssh_agent.run_cmd('ssh {} ls /var/run/apache2/apache2.pid'.format(self.ip), timeout=30)
        if st == True:
            log.info('OK')
        return st

    def pause(self):
	return self.exampleservice.pause()

    def unpause(self):
        return self.exampleservice.unpause()

    def stop(self):
        return self.exampleservice.stop()

    def start(self):
        return self.exampleservice.start()

    def suspend(self):
        return self.exampleservice.suspend()

    def resume(self):
        return self.exampleservice.resume()

    def reboot(self):
        return self.exampleservice.reboot()


