
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
from SSHTestAgent import SSHTestAgent
from CordTestUtils import *
from CordTestUtils import log_test as log

log.setLevel('INFO')

class VSGAccess(object):

    vcpe_map = {}
    interface_map = {}
    ip_addr_pattern = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$')

    @classmethod
    def setUp(cls):
        try:
            shutil.copy('/etc/resolv.conf', '/etc/resolv.conf.orig')
        except:
            pass

    @classmethod
    def tearDown(cls):
        try:
            shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
        except:
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
    @method: get_vsgs
    @Description: Get list of vsg's running in compute node
    @params: status of vsg
    returns vsg wrappers
    '''
    @classmethod
    def get_vsgs(cls, active = True):
        credentials = cls.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        vsgs = nvclient.servers.list(search_opts = {'all_tenants': 1})
        if active is True:
            vsgs = filter(lambda vsg: vsg.status == 'ACTIVE', vsgs)
        vsg_wrappers = []
        for vsg in vsgs:
            vsg_wrappers.append(VSGWrapper(vsg))
        return vsg_wrappers

    '''
    @method: open_mgmt
    @Description: Bringing up Interface for access to management
    @params: intf = "Interface to open"
    returns Gateway
    '''
    @classmethod
    def open_mgmt(cls, intf = 'eth0'):
        if intf in cls.interface_map:
            gw = cls.interface_map[intf]['gw']
            ip = cls.interface_map[intf]['ip']
            if gw != '0.0.0.0':
                current_gw, _ = get_default_gw()
                cmds = [ 'route del default gw {}'.format(current_gw),
                         'ifconfig {} {} up'.format(intf, ip),
                         'route add default gw {}'.format(gw) ]
                for cmd in cmds:
                    os.system(cmd)
                shutil.copy('/etc/resolv.conf', '/etc/resolv.conf.lastdhcp')
                shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
                return current_gw
        return None

    '''
    @method: close_mgmt
    @Description: Bringing up gateway deleting default
    @params: intf = "Interface to open"
             dict2 = retrieved data from GET method
    returns: NA
    '''
    @classmethod
    def close_mgmt(cls, restore_gw, intf = 'eth0'):
        if restore_gw:
            cmds = [ 'route del default gw 0.0.0.0',
                     'route add default gw {}'.format(restore_gw),
                     'cp /etc/resolv.conf.lastdhcp /etc/resolv.conf',
                     'rm -f /etc/resolv.conf.lastdhcp'
                     ]
            for cmd in cmds:
                os.system(cmd)

    '''
    @method: health_check
    @Description: Check if vsgs are reachable
    @params:
    returns True
    '''
    @classmethod
    def health_check(cls):
        '''Returns 0 if all active vsgs are reachable through the compute node'''
        vsgs = cls.get_vsgs()
        vsg_status = []
        for vsg in vsgs:
            vsg_status.append(vsg.get_health())
        unreachable = filter(lambda st: st == False, vsg_status)
        return len(unreachable) == 0

    '''
    @method: get_vcpe_vsg
    @Description: Getting vsg vm instance info from given vcpe
    @params: vcpe = "vcpe name"
    returns vsg
    '''
    @classmethod
    def get_vcpe_vsg(cls, vcpe):
        '''Find the vsg hosting the vcpe service'''
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['vsg']
        vsgs = cls.get_vsgs()
        for vsg in vsgs:
            cmd = 'sudo docker exec {} ls 2>/dev/null'.format(vcpe)
            st, _ = vsg.run_cmd(cmd, timeout = 30)
            if st == True:
                return vsg
        return None

    '''
    @method: save_vcpe_config
    @Description: Saving vcpe config with lan & wan side info
    @params: vsg
             vcpe
    returns True
    '''
    @classmethod
    def save_vcpe_config(cls, vsg, vcpe):
        if vcpe not in cls.vcpe_map:
            cmd_gw = "sudo docker exec %s ip route show | grep default | head -1 | awk '{print $3}'" %(vcpe)
            vsg_ip = vsg.ip
            if vsg_ip is None:
                return False
            st, output = vsg.run_cmd(cmd_gw, timeout = 30)
            if st == False or not output:
                return False
            gw = output
            cmd_wan = "sudo docker exec %s ip addr show eth0 |grep inet |head -1 | tr -s ' ' | awk '{print $2}' | awk '{print $1}'" %(vcpe)
            cmd_lan = "sudo docker exec %s ip addr show eth1 |grep inet |head -1 | tr -s ' ' | awk '{print $2}' | awk '{print $1}'" %(vcpe)
            st, output = vsg.run_cmd(cmd_wan, timeout = 30)
            ip_wan = '0.0.0.0/24'
            ip_lan = '0.0.0.0/24'
            if st and output:
                if cls.ip_addr_pattern.match(output):
                    ip_wan = output

            st, output = vsg.run_cmd(cmd_lan, timeout = 30)
            if st and output:
                if cls.ip_addr_pattern.match(output):
                    ip_lan = output

            cls.vcpe_map[vcpe] = { 'vsg': vsg, 'gw': gw, 'wan': ip_wan, 'lan': ip_lan }

        return True

    '''
    @method: restore_vcpe_config
    @Description: Restoring saved config for lan & wan
    @params: vcpe
             gw
             wan
             lan
    returns True/False
    '''
    @classmethod
    def restore_vcpe_config(cls, vcpe, gw = True, wan = False, lan = False):
        if vcpe in cls.vcpe_map:
            vsg = cls.vcpe_map[vcpe]['vsg']
            cmds = []
            if gw is True:
                #restore default gw
                gw = cls.vcpe_map[vcpe]['gw']
                cmds.append('sudo docker exec {} ip link set eth0 up'.format(vcpe))
                cmds.append('sudo docker exec {} route add default gw {} dev eth0'.format(vcpe, gw))
            if wan is True:
                ip_wan = cls.vcpe_map[vcpe]['wan']
                cmds.append('sudo docker exec {} ip addr set {} dev eth0'.format(vcpe, ip_wan))
            if lan is True:
                ip_lan = cls.vcpe_map[vcpe]['lan']
                cmds.append('sudo docker exec {} ip addr set {} dev eth1'.format(vcpe, ip_lan))
            ret_status = True
            for cmd in cmds:
                st, _ = vsg.run_cmd(cmd, timeout = 30)
                if st == False:
                    ret_status = False
            return ret_status
        return False

    '''
    @method: get_vcpe_gw
    @Description: Get gw of vcpe from created map
    @params: vcpe
    returns gw
    '''
    @classmethod
    def get_vcpe_gw(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['gw']
        return None

    '''
    @method: get_vcpe_wan
    @Description:
    @params:
    return wan side of vcpe
    '''
    @classmethod
    def get_vcpe_wan(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['wan']
        return None

    '''
    @method: get_vcpe_lan
    @Description:
    @params:
    returns True if contents of dict1 exists in dict2
    '''
    @classmethod
    def get_vcpe_lan(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['lan']
        return None

    '''
    @method: vcpe_wan_up
    @Description:
    @params:
    returns status
    '''
    @classmethod
    def vcpe_wan_up(cls, vcpe):
        return cls.restore_vcpe_config(vcpe)

    '''
    @method: vcpe_lan_up
    @Description:
    @params:
    returns status
    '''
    @classmethod
    def vcpe_lan_up(cls, vcpe, vsg = None):
        if vsg is None:
            vsg = cls.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        cmd = 'sudo docker exec {} ip link set eth1 up'.format(vcpe)
        st, _ = vsg.run_cmd(cmd, timeout = 30)
        return st

    '''
    @method: vcpe_port_down
    @Description:
    @params:
    returns status
    '''
    #we cannot access compute node if the vcpe port gets dhcp as default would be through fabric
    @classmethod
    def vcpe_port_down(cls, vcpe, port, vsg = None):
        if vsg is None:
            vsg = cls.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        if not cls.save_vcpe_config(vsg, vcpe):
            return False
        cmd = 'sudo docker exec {} ip link set {} down'.format(vcpe, port)
        st, _ = vsg.run_cmd(cmd, timeout = 30)
        if st is False:
            cls.restore_vcpe_config(vcpe)
            return False
        return st

    '''
    @method: vcpe_wan_down
    @Description:
    @params:
    returns status
    '''
    @classmethod
    def vcpe_wan_down(cls, vcpe, vsg = None):
        return cls.vcpe_port_down(vcpe, 'eth0', vsg = vsg)

    '''
    @method: vcpe_lan_down
    @Description:
    @params:
    returns status
    '''
    @classmethod
    def vcpe_lan_down(cls, vcpe, vsg = None):
        return cls.vcpe_port_down(vcpe, 'eth1', vsg = vsg)

    '''
    @method: save_interface_config
    @Description:
    @params:
    returns NA
    '''
    @classmethod
    def save_interface_config(cls, intf):
        if intf not in cls.interface_map:
            ip = get_ip(intf)
            if ip is None:
                ip = '0.0.0.0'
            default_gw, default_gw_device = get_default_gw()
            if default_gw_device != intf:
                default_gw = '0.0.0.0'
            cls.interface_map[intf] = { 'ip' : ip, 'gw': default_gw }
            #bounce the interface to remove default gw
            cmds = ['ifconfig {} 0 down'.format(intf),
                    'ifconfig {} 0 up'.format(intf)
                    ]
            for cmd in cmds:
                os.system(cmd)

    '''
    @method: restore_interface_config
    @Description:
    @params:
    returns NA
    '''
    #open up access to compute node
    @classmethod
    def restore_interface_config(cls, intf, vcpe = None):
        if intf in cls.interface_map:
            ip = cls.interface_map[intf]['ip']
            gw = cls.interface_map[intf]['gw']
            del cls.interface_map[intf]
            cmds = []
            if vcpe is not None:
                shutil.copy('/etc/resolv.conf.orig', '/etc/resolv.conf')
                #bounce the vcpes to clear default gw
                cmds.append('ifconfig {} 0 down'.format(vcpe))
                cmds.append('ifconfig {} 0 up'.format(vcpe))
            cmds.append('ifconfig {} {} up'.format(intf, ip))
            if gw and gw != '0.0.0.0':
                cmds.append('route add default gw {} dev {}'.format(gw, intf))
            for cmd in cmds:
                os.system(cmd)

    '''
    @method: vcpe_get_dhcp
    @Description: Get DHCP from vcpe dhcp interface.
    @params:
    returns vcpe ip
    '''
    @classmethod
    def vcpe_get_dhcp(cls, vcpe, mgmt = 'eth0'):
        '''Get DHCP from vcpe dhcp interface.'''
        '''We have to also save the management interface config for restoration'''
        cls.save_interface_config(mgmt)
        getstatusoutput('pkill -9 dhclient')
        st, output = getstatusoutput('dhclient -q {}'.format(vcpe))
        getstatusoutput('pkill -9 dhclient')
        vcpe_ip = get_ip(vcpe)
        if vcpe_ip is None:
            cls.restore_interface_config(mgmt)
            return None
        if output:
            #workaround for docker container apparmor that prevents moving dhclient resolv.conf
            start = output.find('/etc/resolv.conf')
            if start >= 0:
                end = output.find("'", start)
                dns_file = output[start:end]
                if os.access(dns_file, os.F_OK):
                    shutil.copy(dns_file, '/etc/resolv.conf')

        default_gw, default_gw_device = get_default_gw()
        if default_gw and default_gw_device == vcpe:
            return vcpe_ip
        cls.restore_interface_config(mgmt, vcpe = vcpe)
        return None

class VSGWrapper(object):

    def __init__(self, vsg):
        self.vsg = vsg
        self.name = self.vsg.name
        self.compute_node = self.get_compute_node()
        self.ip = self.get_ip()

    '''
    @method: get_compute_node
    @Description:
    @params:
    returns compute node name
    '''
    def get_compute_node(self):
        return self.vsg._info['OS-EXT-SRV-ATTR:hypervisor_hostname']

    '''
    @method: get_ip
    @Description:
    @params:
    returns ip of network
    '''
    def get_ip(self):
        if 'management' in self.vsg.networks:
            ips = self.vsg.networks['management']
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
    @method: run_cmd
    @Description:
    @params:
    returns status & output
    '''
    def run_cmd(self, cmd, timeout = 5, mgmt = 'eth0'):
        last_gw = VSGAccess.open_mgmt(mgmt)
        ssh_agent = SSHTestAgent(self.compute_node)
        ssh_cmd = 'ssh {} {}'.format(self.ip, cmd)
        st, output = ssh_agent.run_cmd(ssh_cmd, timeout = timeout)
        if st == True and output:
            output = output.strip()
        else:
            output = None
        VSGAccess.close_mgmt(last_gw, mgmt)
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
        log.info('Pinging VSG %s at IP %s' %(self.name, self.ip))
        st, _ = self.run_cmd_compute(cmd)
        log.info('VSG %s at IP %s is %s through compute node %s' %(self.name, self.ip, 'reachable' if st == True else 'unreachable', self.compute_node))
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
        log.info('Checking if VSG at %s is accessible from compute node %s' %(self.ip, self.compute_node))
        st, _ = ssh_agent.run_cmd('ssh {} ls'.format(self.ip), timeout=30)
        if st == True:
            log.info('OK')
        return st
