import os
import shutil
import re
from novaclient import client as nova_client
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

class ExampleSevicesWrapper(object):

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


