import os
import shutil
import re
from novaclient import client as nova_client
from SSHTestAgent import SSHTestAgent
from CordTestUtils import *

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

    @classmethod
    def get_nova_credentials_v2(cls):
        credential = {}
        credential['username'] = os.environ['OS_USERNAME']
        credential['api_key'] = os.environ['OS_PASSWORD']
        credential['auth_url'] = os.environ['OS_AUTH_URL']
        credential['project_id'] = os.environ['OS_TENANT_NAME']
        return credential

    @classmethod
    def get_compute_nodes(cls):
        credentials = cls.get_nova_credentials_v2()
        nvclient = nova_client.Client('2', **credentials)
        return nvclient.hypervisors.list()

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

    @classmethod
    def health_check(cls):
        '''Returns 0 if all active vsgs are reachable through the compute node'''
        vsgs = cls.get_vsgs()
        vsg_status = []
        for vsg in vsgs:
            vsg_status.append(vsg.get_health())
        unreachable = filter(lambda st: st == False, vsg_status)
        return len(unreachable) == 0

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

    @classmethod
    def get_vcpe_gw(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['gw']
        return None

    @classmethod
    def get_vcpe_wan(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['wan']
        return None

    @classmethod
    def get_vcpe_lan(cls, vcpe):
        if vcpe in cls.vcpe_map:
            return cls.vcpe_map[vcpe]['lan']
        return None

    @classmethod
    def vcpe_wan_up(cls, vcpe):
        return cls.restore_vcpe_config(vcpe)

    @classmethod
    def vcpe_lan_up(cls, vcpe, vsg = None):
        if vsg is None:
            vsg = cls.get_vcpe_vsg(vcpe)
            if vsg is None:
                return False
        cmd = 'sudo docker exec {} ip link set eth1 up'.format(vcpe)
        st, _ = vsg.run_cmd(cmd, timeout = 30)
        return st

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

    @classmethod
    def vcpe_wan_down(cls, vcpe, vsg = None):
        return cls.vcpe_port_down(vcpe, 'eth0', vsg = vsg)

    @classmethod
    def vcpe_lan_down(cls, vcpe, vsg = None):
        return cls.vcpe_port_down(vcpe, 'eth1', vsg = vsg)

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

    def get_compute_node(self):
        return self.vsg._info['OS-EXT-SRV-ATTR:hypervisor_hostname']

    def get_ip(self):
        if 'management' in self.vsg.networks:
            ips = self.vsg.networks['management']
            if len(ips) > 0:
                return ips[0]
        return None

    def run_cmd_compute(self, cmd, timeout = 5):
        ssh_agent = SSHTestAgent(self.compute_node)
        st, output = ssh_agent.run_cmd(cmd, timeout = timeout)
        if st == True and output:
            output = output.strip()
        else:
            output = None

        return st, output

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

    def get_health(self):
        if self.ip is None:
            return False
        cmd = 'ping -c 1 {}'.format(self.ip)
        st, _ = self.run_cmd_compute(cmd)
        return st

    def check_access(self):
        if self.ip is None:
            return False
        ssh_agent = SSHTestAgent(self.compute_node)
        st, _ = ssh_agent.run_cmd('ls', timeout=10)
        if st == False:
            return st
        st, _ = ssh_agent.run_cmd('ssh {} ls'.format(self.ip), timeout=30)
        return st
