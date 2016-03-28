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
        except:
            self.olt_handle = None
            self.olt_conf = {}
            self.olt_conf['olt'] = False
            
    def on_olt(self):
        return self.olt_conf['olt'] is True

    def olt_port_map(self):
        if self.on_olt() and self.olt_conf.has_key('ports'):
            port_map = {}
            ##Build a rx/tx port number to interface map
            port_map[1] = self.olt_conf['ports']['rx']
            port_map[2] = self.olt_conf['ports']['tx']
            port_map[port_map[1]] = 1
            port_map[port_map[2]] = 2
            return port_map
        else:
            return None
