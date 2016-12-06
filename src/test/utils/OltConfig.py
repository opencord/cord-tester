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
import os
import json
##load the olt config

class OltConfig:
    def __init__(self, olt_conf_file = ''):
        if not olt_conf_file:
            self.olt_conf_file = os.getenv('OLT_CONFIG')
        else:
            self.olt_conf_file = olt_conf_file
        try:
            self.olt_handle = open(self.olt_conf_file, 'r')
            self.olt_conf = json.load(self.olt_handle)
            self.olt_conf['olt'] = True
        except:
            self.olt_handle = None
            self.olt_conf = {}
            self.olt_conf['olt'] = False

    def on_olt(self):
        return self.olt_conf['olt'] is True

    def olt_port_map(self):
        if self.on_olt() and self.olt_conf.has_key('port_map'):
            port_map = {}
            if self.olt_conf['port_map'].has_key('switches'):
                port_map['switches'] = self.olt_conf['port_map']['switches']
            else:
                port_map['switches'] = []
                nr_switches = 1
                if self.olt_conf['port_map'].has_key('nr_switches'):
                    nr_switches = int(self.olt_conf['port_map']['nr_switches'])
                for sw in xrange(nr_switches):
                    switch = 'br-int{}'.format(sw+1) if sw > 0 else 'br-int'
                    port_map['switches'].append(switch)
            #if we have a host interface enabled, invalidate the switches config
            if self.olt_conf['port_map'].has_key('host'):
                #if host interface is specified, then use the host instead of ovs switch
                port_map['host'] = self.olt_conf['port_map']['host']
                port_map['switches'] = [ port_map['host'] ]
            else:
                port_map['host'] = port_map['switches'][0]
            nr_switches = len(port_map['switches'])
            port_map['switch_port_list'] = []
            if self.olt_conf['port_map'].has_key('ports'):
                port_map['ports'] = self.olt_conf['port_map']['ports']
                num_ports = len(port_map['ports'])
                port_map['switch_port_list'].append( (port_map['switches'][0], port_map['ports']) )
            else:
                port_map['ports'] = []
                num_ports = int(self.olt_conf['port_map']['num_ports'])
                for sw in xrange(nr_switches):
                    port_list = []
                    switch = port_map['switches'][sw]
                    port_start = sw * num_ports * 2
                    port_end = port_start + num_ports * 2
                    for port in xrange(port_start, port_end, 2):
                        port_name = 'veth{}'.format(port)
                        port_map['ports'].append(port_name)
                        port_list.append(port_name)
                    port_map['switch_port_list'].append( (switch, port_list) )
            ##also add dhcprelay ports. We add as many relay ports as subscriber ports
            port_map['num_ports'] = num_ports
            relay_ports = num_ports
            port_map['relay_ports'] = []
            port_map['switch_relay_port_list'] = []
            for sw in xrange(nr_switches):
                port_list = []
                switch = port_map['switches'][sw]
                port_start = (nr_switches + sw) * relay_ports * 2
                port_end = port_start + relay_ports * 2
                for port in xrange(port_start, port_end, 2):
                    port_name = 'veth{}'.format(port)
                    port_map['relay_ports'].append(port_name)
                    port_list.append(port_name)
                port_map['switch_relay_port_list'].append( (switch, port_list) )
            port_num = 1
            port_map['uplink'] = int(self.olt_conf['uplink'])
            port_map['wan'] = None
            if self.olt_conf.has_key('wan'):
                port_map['wan'] = self.olt_conf['wan']
            port_list = []
            ##build the port map and inverse port map
            for sw in xrange(nr_switches):
                sw_portnum = 1
                switch, ports = port_map['switch_port_list'][sw]
                uplink = sw * num_ports + port_map['uplink']
                port_map[switch] = {}
                port_map[switch]['uplink'] = uplink
                for p in ports:
                    port_map[port_num] = p
                    port_map[p] = port_num
                    if sw_portnum != port_map['uplink']:
                        #create tx, rx map
                        port_list.append( (uplink, port_num) )
                    port_num += 1
                    sw_portnum += 1
            ##build the port and inverse map for relay ports
            for port in port_map['relay_ports']:
                port_map[port_num] = port
                port_map[port] = port_num
                port_num += 1
            port_map['start_vlan'] = 0
            if self.olt_conf['port_map'].has_key('start_vlan'):
                port_map['start_vlan'] = int(self.olt_conf['port_map']['start_vlan'])

            return port_map, port_list
        else:
            return None, None

    def olt_device_data(self):
        if self.on_olt():
            accessDeviceDict = {}
            accessDeviceDict['uplink'] = str(self.olt_conf['uplink'])
            accessDeviceDict['vlan'] = str(self.olt_conf['vlan'])
            return accessDeviceDict
        return None
