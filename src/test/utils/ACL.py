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
import json
import requests
import os,sys,time
from scapy.all import *
from OnosCtrl import OnosCtrl, get_mac
from OnosFlowCtrl import OnosFlowCtrl

conf.verb = 0 # Disable Scapy verbosity
conf.checkIPaddr = 0 # Don't check response packets for matching destination IPs

class ACLTest:

    auth = ('karaf', 'karaf')
    controller = OnosCtrl.get_controller()
    add_acl_rule_url = 'http://%s:8181/onos/v1/acl/rules' %(controller)
    remove_acl_rule_url = 'http://%s:8181/onos/v1/acl/rules/%s' %(controller, id)
    clear_all_acl_rule_url = 'http://%s:8181/onos/v1/acl/rules' %(controller)
    iface_create_onos_url = 'http://%s:8181/onos/v1/network/configuration' %(controller)
    device_id = 'of:' + get_mac('ovsbr0')
    MAX_PORTS = 100

    def __init__(self, ipv4Prefix ='v4', srcIp ='null', dstIp ='null', ipProto = 'null', dstTpPort = 0, action = 'null', ingress_iface = 1, egress_iface = 2,iface_num = 0, iface_name = 'null', iface_count = 0, iface_ip = 'null'):
        self.ipv4Prefix = ipv4Prefix
        self.srcIp = srcIp
        self.ingress_iface = ingress_iface
        self.egress_iface = egress_iface
        self.dstIp = dstIp
        self.ipProto = ipProto
        self.dstTpPort = dstTpPort
        self.action = action
        self.iface_count = iface_count
        self.iface_num = iface_num
        self.iface_name = iface_name
        self.iface_ip = iface_ip

    def adding_acl_rule(self, ipv4Prefix, srcIp, dstIp, ipProto ='null', dstTpPort='null', action= 'include'):
        '''This function is generating ACL json file and post to ONOS for creating a ACL rule'''
        if ipv4Prefix is 'v4':
           acl_dict = {}
           if srcIp and dstIp and action:
              acl_dict['srcIp'] = '{}'.format(srcIp)
              acl_dict['dstIp'] = '{}'.format(dstIp)
              acl_dict['action'] = '{}'.format(action)
           if ipProto is not 'null':
              acl_dict['ipProto'] = '{}'.format(ipProto)
           if dstTpPort is not 'null':
              acl_dict['dstTpPort'] = '{}'.format(dstTpPort)
        json_data = json.dumps(acl_dict)
        resp = requests.post(self.add_acl_rule_url, auth = self.auth, data = json_data)
        return resp.ok, resp.status_code

    def get_acl_rules(self):
        '''This function is getting a ACL rules from ONOS with json formate'''
        resp = requests.get(self.add_acl_rule_url, auth = self.auth)
        return resp

    @classmethod
    def remove_acl_rule(cls,id = None):
        '''This function is delete one or all  ACL rules in ONOS'''
        if id is None:
           remove_acl_rule_url = 'http://%s:8181/onos/v1/acl/rules' %(cls.controller)
        else:
           remove_acl_rule_url = 'http://%s:8181/onos/v1/acl/rules/%s' %(cls.controller, id)
        resp = requests.delete(remove_acl_rule_url, auth = cls.auth)
        return resp.ok, resp.status_code

    def generate_onos_interface_config(self,iface_num = 4, iface_name = 'null',iface_count = 1,iface_ip = '198.162.10.1'):
        '''This function is generate interface config data in json format and post to ONOS for creating it '''
        ''' To add interfaces on ONOS to test acl with trffic'''
        num = 0
        egress_host_list = []
        interface_list = []
        ip = iface_ip.split('/')[0]
        start_iface_ip = ip.split('.')
        start_ip = ( int(start_iface_ip[0]) << 24) | ( int(start_iface_ip[1]) << 16)  |  ( int(start_iface_ip[2]) << 8) | 0
        end_ip =  ( 200 << 24 ) | (168 << 16)  |  (10 << 8) | 0
        ports_dict = { 'ports' : {} }
        for n in xrange(start_ip, end_ip, 256):
            port_map = ports_dict['ports']
            port = iface_num if num < self.MAX_PORTS - 1 else self.MAX_PORTS - 1
            device_port_key = '{0}/{1}'.format(self.device_id, port)
            try:
                interfaces = port_map[device_port_key]['interfaces']
            except:
                port_map[device_port_key] = { 'interfaces' : [] }
                interfaces = port_map[device_port_key]['interfaces']
            ip = n + 2
            peer_ip = n + 1
            ips = '%d.%d.%d.%d/%d'%( (ip >> 24) & 0xff, ( (ip >> 16) & 0xff ), ( (ip >> 8 ) & 0xff ), ip & 0xff, int(iface_ip.split('/')[1]))
            peer = '%d.%d.%d.%d' % ( (peer_ip >> 24) & 0xff, ( ( peer_ip >> 16) & 0xff ), ( (peer_ip >> 8 ) & 0xff ), peer_ip & 0xff )
            mac = RandMAC()._fix()
            egress_host_list.append((peer, mac))
            if num < self.MAX_PORTS - 1:
               interface_dict = { 'name' : '{0}-{1}'.format(iface_name,port), 'ips': [ips], 'mac' : mac }
               interfaces.append(interface_dict)
               interface_list.append(interface_dict['name'])
            else:
               interfaces[0]['ips'].append(ips)
            num += 1
            if num == iface_count:
               break
        json_data = json.dumps(ports_dict)
        resp = requests.post(self.iface_create_onos_url, auth = self.auth, data = json_data)
        return resp.ok, resp.status_code, egress_host_list

