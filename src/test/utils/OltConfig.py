#!/usr/bin/env python
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
            port_map['ports'] = self.olt_conf['port_map']['ports']
            port_map['start_vlan'] = 0
            if self.olt_conf['port_map'].has_key('host'):
                port_map['host'] = self.olt_conf['port_map']['host']
            else:
                port_map['host'] = 'ovsbr0'
            if self.olt_conf['port_map'].has_key('start_vlan'):
                port_map['start_vlan'] = int(self.olt_conf['port_map']['start_vlan'])
                
            ##Build a rx/tx port number to interface map
            port_map[1] = self.olt_conf['port_map']['rx']
            port_map[2] = self.olt_conf['port_map']['tx']
            port_map[port_map[1]] = 1
            port_map[port_map[2]] = 2
            return port_map
        else:
            return None

    def olt_device_data(self):
        if self.on_olt():
            accessDeviceDict = {}
            accessDeviceDict['uplink'] = str(self.olt_conf['uplink'])
            accessDeviceDict['vlan'] = str(self.olt_conf['vlan'])
            return accessDeviceDict
        return None
