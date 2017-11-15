
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
from OltConfig import OltConfig
from CordTestUtils import get_mac, get_controller, log_test
from EapolAAA import get_radius_macs, get_radius_networks

class OnosCtrl:

    auth = ('karaf', 'karaf')
    controller = get_controller()
    cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
    maven_repo = 'http://central.maven.org/maven2/org/onosproject'
    applications_url = 'http://%s:8181/onos/v1/applications' %(controller)
    host_cfg_url = 'http://%s:8181/onos/v1/network/configuration/hosts/' %(controller)

    def __init__(self, app, controller = None):
        self.app = app
        if controller is not None:
            self.controller = controller
        self.app_url = 'http://%s:8181/onos/v1/applications/%s' %(self.controller, self.app)
        self.cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(self.controller)
        self.auth = ('karaf', 'karaf')

    @classmethod
    def config(cls, config, controller=None):
        if config is not None:
            json_data = json.dumps(config)
	    if controller is None:
                resp = requests.post(cls.cfg_url, auth = cls.auth, data = json_data)
	    else:
		cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	        resp = requests.post(cfg_url, auth = cls.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    @classmethod
    def get_config(cls, controller=None):
	if controller is None:
            controller = cls.controller
	cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	resp = requests.get(cfg_url, auth = cls.auth)
        if resp.ok:
            return resp.json()
        return None

    @classmethod
    def delete(cls, config, controller=None):
        if config:
            json_data = json.dumps(config)
	    if controller is None:
	        print('default Onos config url is %s'%cls.cfg_url)
                resp = requests.delete(cls.cfg_url, auth = cls.auth, data = json_data)
	    else:
		cfg_url = 'http://%s:8181/onos/v1/network/configuration/' %(controller)
	        resp = requests.delete(cfg_url, auth = cls.auth, data = json_data)
            return resp.ok, resp.status_code
        return False, 400

    def activate(self):
        resp = requests.post(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    def deactivate(self):
        resp = requests.delete(self.app_url + '/active', auth = self.auth)
        return resp.ok, resp.status_code

    @classmethod
    def get_devices(cls, controller = None, mfr = None):
        if controller is None:
            controller = cls.controller
        url = 'http://%s:8181/onos/v1/devices' %(controller)
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            devices = result.json()['devices']
            devices = filter(lambda d: d['available'], devices)
            if mfr:
                devices = filter(lambda d: d['mfr'].startswith(mfr), devices)
            return devices
        return None

    @classmethod
    def get_links(cls, controller = None):
        if controller is None:
            controller = cls.controller
        url = 'http://%s:8181/onos/v1/links' %(controller)
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            links = result.json()['links']
            return links
        return None

    @classmethod
    def get_device_id(cls, controller = None, mfr = None, olt_conf_file = ''):
        '''If running under olt, we get the first switch connected to onos'''
        olt = OltConfig(olt_conf_file = olt_conf_file)
        did = 'of:' + get_mac()
        if olt.on_olt():
            devices = cls.get_devices(controller = controller, mfr = mfr)
            if devices:
                dids = map(lambda d: d['id'], devices)
                if len(dids) == 1:
                    did = dids[0]
                else:
                    ###If we have more than 1, then check for env before using first one
                    did = os.getenv('OLT_DEVICE_ID', dids[0])

        return did

    @classmethod
    def get_device_ids(cls, controller = None, olt_conf_file = ''):
        '''If running under olt, we get the first switch connected to onos'''
        olt = OltConfig(olt_conf_file = olt_conf_file)
        did = 'of:' + get_mac()
        device_ids = []
        if olt.on_olt():
            devices = cls.get_devices(controller = controller)
            if devices:
                device_ids = map(lambda d: d['id'], devices)
        else:
            device_ids.append(did)

        return device_ids

    @classmethod
    def get_flows(cls, device_id,controller=None):
        if controller is None:
	    url = 'http://%s:8181/onos/v1/flows/' %(cls.controller) + device_id
	else:
	    url = 'http://%s:8181/onos/v1/flows/' %(controller) + device_id
        result = requests.get(url, auth = cls.auth)
        if result.ok:
            return result.json()['flows']
        return None

    @classmethod
    def get_ports_device(cls, device_id, controller = None):
        if controller is None:
            url = 'http://{}:8181/onos/v1/devices/{}/ports'.format(cls.controller, device_id)
        else:
            url = 'http://{}:8181/onos/v1/devices/{}/ports'.format(controller, device_id)

        result = requests.get(url, auth = cls.auth)
        if result.ok:
            return result.json()['ports']
        return None

    @classmethod
    def cord_olt_device_map(cls, olt_config, controller = None):
        olt_device_list = []
        olt_port_map, _ = olt_config.olt_port_map()
        switches = olt_port_map['switches']
        if len(switches) > 1:
            device_ids = cls.get_device_ids(controller = controller)
        else:
            did = cls.get_device_id(controller = controller)
            if did is None:
                return olt_device_list
            uplink_dict = {}
            uplink_dict['did'] = did
            uplink_dict['switch'] = switches[0]
            uplink_dict['uplink'] = str(olt_config.olt_conf['uplink'])
            uplink_dict['vlan'] = str(olt_config.olt_conf['vlan'])
            olt_device_list.append(uplink_dict)
            return olt_device_list

        for did in device_ids:
            ports = cls.get_ports_device(did, controller = controller)
            if ports:
                matched = False
                for port in ports:
                    for switch in switches:
                        if port['annotations']['portName'] == switch:
                            uplink_dict = {}
                            uplink = olt_port_map[switch]['uplink']
                            uplink_dict['did'] = did
                            uplink_dict['switch'] = switch
                            uplink_dict['uplink'] = str(uplink)
                            uplink_dict['vlan'] = str(olt_config.olt_conf['vlan'])
                            olt_device_list.append(uplink_dict)
                            matched = True
                            break
                    if matched == True:
                        break

        return olt_device_list

    @classmethod
    def cord_olt_config(cls, olt_config, controller=None):
        '''Configures OLT data for existing devices/switches'''
        did_dict = {}
        config = { 'devices' : did_dict }
        olt_device_list = cls.cord_olt_device_map(olt_config, controller = controller)
        if not olt_device_list:
            return
        for olt_map in olt_device_list:
            access_device_dict = {}
            device_data = {'uplink': olt_map['uplink'], 'vlan': olt_map['vlan']}
            access_device_dict['accessDevice'] = device_data
            did_dict[olt_map['did']] = access_device_dict

        ##configure the device list with access information
        return cls.config(config, controller=controller)

    @classmethod
    def install_app(cls, app_file, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/octet-stream'}
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        with open(app_file, 'rb') as payload:
            result = requests.post(url, auth = cls.auth,
                                   params = params, headers = headers,
                                   data = payload)
	print('result.ok, result.status_code are %s and %s'%(result.ok, result.status_code))
        return result.ok, result.status_code

    @classmethod
    def install_app_from_url(cls, app_name, app_version, app_url = None, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/json'}
        if app_url is None:
            app_oar_file = '{}-{}.oar'.format(app_name, app_version)
            app_url = '{0}/{1}/{2}/{3}'.format(cls.maven_repo, app_name, app_version, app_oar_file)
        params['url'] = app_url
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        result = requests.post(url, auth = cls.auth,
                               json = params, headers = headers)
        return result.ok, result.status_code

    @classmethod
    def uninstall_app(cls, app_name, onos_ip = None):
        params = {'activate':'true'}
        headers = {'content-type':'application/octet-stream'}
        url = cls.applications_url if onos_ip is None else 'http://{0}:8181/onos/v1/applications'.format(onos_ip)
        app_url = '{}/{}'.format(url, app_name)
        resp = requests.delete(app_url, auth = cls.auth)
        return resp.ok, resp.status_code

    @classmethod
    def host_config(cls, config, onos_ip=None):
        if config:
           json_data = json.dumps(config)
           url = cls.host_cfg_url if onos_ip is None else 'http://{}:8181/onos/v1/network/configuration/hosts/'.format(onos_ip)
           resp = requests.post(url, auth = cls.auth, data = json_data)
           return resp.ok, resp.status_code
        return False, 400

    @classmethod
    def config_device_driver(cls, controller = None, dids = None, driver = 'pmc-olt'):
        driver_apps = ('org.onosproject.drivers', 'org.onosproject.openflow-base',)
        if dids is None:
            dids = cls.get_device_ids(controller = controller)
        device_map = {}
        for did in dids:
            device_map[did] = { 'basic' : { 'driver' : driver } }
        network_cfg = { 'devices' : device_map }
        cls.config(network_cfg)
        for driver in driver_apps:
            cls(driver).deactivate()
        time.sleep(2)
        for driver in driver_apps:
            cls(driver).activate()
        time.sleep(5)

    @classmethod
    def device_id_to_mac(cls, device_id):
        device_mac_raw = device_id[-12:]
        hwaddrs = []
        for i in xrange(0, 12, 2):
            hwaddrs.append(device_mac_raw[i:i+2])

        device_mac = ':'.join(hwaddrs)
        return device_mac

    @classmethod
    def aaa_load_config(cls, controller = None, olt_conf_file = '', conn_type = 'socket'):
        ovs_devices = cls.get_devices(controller = controller, mfr = 'Nicira')
        if not ovs_devices and conn_type != 'socket':
            log_test.info('No OVS devices found to configure AAA connect points')
            return
        olt = OltConfig(olt_conf_file = olt_conf_file)
        port_map, _ = olt.olt_port_map()
        app = 'org.opencord.aaa'
        cfg = { 'apps' : { app : { 'AAA' : {} } } }
        if conn_type == 'socket':
            customizer = 'default'
        else:
            customizer = 'sample'
        aaa_cfg = dict(radiusConnectionType = conn_type,
                       radiusSecret = 'radius_password',
                       radiusServerPort = '1812',
                       packetCustomizer = customizer,
                       vlanId = -1)
        radius_networks = get_radius_networks(len(port_map['switch_radius_port_list']))
        index = 0
        for switch, ports in port_map['switch_radius_port_list']:
            radius_macs = get_radius_macs(len(ports))
            prefix, _, _ = radius_networks[index]
            index += 1
            aaa_cfg['nasIp'] = controller or cls.controller
            aaa_cfg['nasMac'] = radius_macs[0]
            aaa_cfg['radiusMac'] = radius_macs[0]
            connect_points = []
            radius_port = port_map[ ports[0] ]
            radius_ip = '{}.{}'.format(prefix, radius_port)
            if conn_type == 'socket':
                radius_ip = os.getenv('ONOS_AAA_IP')
            aaa_cfg['radiusIp'] = radius_ip
            for dev in ovs_devices:
                device_id = dev['id']
                ports = OnosCtrl.get_ports_device(device_id, controller = controller)
                radius_ports = filter(lambda p: p['isEnabled'] and 'annotations' in p and \
                                      p['annotations']['portName'].startswith('r'),
                                      ports)
                if not radius_ports:
                    continue
                radius_port = radius_ports[0]['port']
                connect_point = '{}/{}'.format(device_id, radius_port)
                connect_points.append(connect_point)
            aaa_cfg['radiusServerConnectPoints'] = connect_points
            break

        cfg['apps'][app]['AAA'] = aaa_cfg
        cls.config(cfg, controller = controller)

    @classmethod
    def get_ovs_switch_map(cls, controller = None, olt_conf_file = ''):
        port_map = None
        #build ovs switch map
        if olt_conf_file:
            olt = OltConfig(olt_conf_file = olt_conf_file)
            port_map, _ = olt.olt_port_map()

        devices = cls.get_devices(controller = controller, mfr = 'Nicira')
        switch_map = {}
        for dev in devices:
            device_id = dev['id']
            serial = dev['serial']
            ports = cls.get_ports_device(dev['id'], controller = controller)
            ports = filter(lambda p: p['isEnabled'] and 'annotations' in p, ports)
            #just create dummy ctag/uni port numbers
            onu_ports = [1] * len(ports)
            onu_names = map(lambda p: p['annotations']['portName'], ports)
            onu_macs = map(lambda p: p['annotations']['portMac'], ports)
            switch_map[device_id] = dict(uplink_vlan = 1,
                                         serial = serial,
                                         ports = onu_ports,
                                         names = onu_names,
                                         macs = onu_macs)
        return switch_map

    @classmethod
    def sadis_load_config(cls, controller = None, olt_switch_map = {}, olt_conf_file = '', tagged_traffic = False):
        sadis_app = 'org.opencord.sadis'
        aaa_app = 'org.opencord.aaa'
        sadis_cfg = {
            'apps' : {
                sadis_app : {
                    'sadis' : {
                        'integration' : {
                            'cache' : {
                                'enabled' : False,
                                'maxsize' : 50,
                                'ttl' : 'PT0m',
                            },
                        },
                        'entries' : [],
                    },
                },
            }
        }
        sadis_entries = sadis_cfg['apps'][sadis_app]['sadis']['entries']
        nasId = '1/1/2'
        nasPortId = '1/1/2'
        switch_map = olt_switch_map.copy()
        ovs_switch_map = cls.get_ovs_switch_map(controller = controller,
                                                olt_conf_file = olt_conf_file)
        #log_test.info('OVS switch map: %s' %ovs_switch_map)
        switch_map.update(ovs_switch_map)
        for device, entries in switch_map.iteritems():
            uni_ports = entries['ports']
            uni_port_names = entries['names']
            uni_port_macs = entries['macs']
            s_tag = entries['uplink_vlan']
            serial = entries['serial']
            #add entries for uni ports and device
            for p in xrange(len(uni_ports)):
                sadis_entry = dict(nasId = nasId, nasPortId = nasPortId, slot = 1)
                sadis_entry['id'] = uni_port_names[p]
                sadis_entry['hardwareIdentifier'] = uni_port_macs[p]
                sadis_entry['cTag'] = uni_ports[p] if tagged_traffic else -1
                sadis_entry['sTag'] = s_tag if tagged_traffic else -1
                sadis_entry['port'] = uni_ports[p]
                sadis_entry['ipAddress'] = controller or cls.controller
                sadis_entries.append(sadis_entry)
                #add entry for the device itself
                sadis_entry = dict(nasId = nasId, nasPortId = nasPortId, slot = 1)
                sadis_entry['id']  = serial
                sadis_entry['hardwareIdentifier'] = cls.device_id_to_mac(device)
                sadis_entry['cTag'] = uni_ports[p] if tagged_traffic else -1
                sadis_entry['sTag'] = s_tag if tagged_traffic else -1
                sadis_entry['port'] = uni_ports[p]
                sadis_entry['ipAddress'] = controller or cls.controller
                sadis_entries.append(sadis_entry)

        #log_test.info('Sadis cfg: %s' %json.dumps(sadis_cfg, indent=4))
        cls.config(sadis_cfg, controller = controller)

    @classmethod
    def config_olt_access(cls, uplink_vlan, controller = None, defaultVlan = '0', olt_conf_file = ''):
        olt = OltConfig(olt_conf_file = olt_conf_file)
        port_map, _ = olt.olt_port_map()
        uplink = str(port_map['uplink'])
        device_config = { 'devices' : {} }
        ovs_devices = cls.get_devices(controller = controller, mfr = 'Nicira')
        for dev in ovs_devices:
            device_id = dev['id']
            device_config['devices'][device_id] = {}
            device_config['devices'][device_id]['basic'] = dict(driver = 'default')
            device_config['devices'][device_id]['accessDevice'] = dict(uplink = uplink,
                                                                       vlan = uplink_vlan,
                                                                       defaultVlan = defaultVlan)

        cls.config(device_config, controller = controller)

    @classmethod
    def config_olt_component(cls, controller = None, enableDhcpIgmpOnProvisioning = True, defaultVlan = 0):
        if controller is None:
            controller = cls.controller
        olt_property_url = 'configuration/org.opencord.olt.impl.Olt'
        property_url = 'http://{}:8181/onos/v1/{}'.format(controller, olt_property_url)
        cfg = dict(enableDhcpIgmpOnProvisioning = enableDhcpIgmpOnProvisioning, defaultVlan = defaultVlan)
        resp = requests.post(property_url, auth = cls.auth, data = json.dumps(cfg))
        return resp.ok, resp.status_code

    @classmethod
    def config_extraneous_flows(cls, controller = None, enable = True):
        if controller is None:
            controller = cls.controller
        flow_property_url = 'configuration/org.onosproject.net.flow.impl.FlowRuleManager'
        property_url = 'http://{}:8181/onos/v1/{}'.format(controller, flow_property_url)
        cfg = dict(allowExtraneousRules = enable)
        resp = requests.post(property_url, auth = cls.auth, data = json.dumps(cfg))
        return resp.ok, resp.status_code
