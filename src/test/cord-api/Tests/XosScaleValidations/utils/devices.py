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

from tinydb import TinyDB, Query
from robot.api import logger

class devices(object):

    def __init__(self):
        self.olts = TinyDB('olts.json')
        self.pon_ports = TinyDB('pon_ports.json')
        self.onus = TinyDB('onus.json')
        self.uni_ports = TinyDB('uni_ports.json')

    def get_mock_data(self):
        """
        Get all the mock data,
        this method is mostly intended for debugging
        :return: a dictionary containing all the mocked data
        """
        olts = self.olts.all()
        pon_ports = self.pon_ports.all()
        onus = self.onus.all()
        uni_ports = self.uni_ports.all()
        return {
            'olts': olts,
            'pon_ports': pon_ports,
            'onus': onus,
            'uni_ports': uni_ports,
        }

    def clean_storage(self):
        self.olts.purge()
        self.pon_ports.purge()
        self.onus.purge()
        self.uni_ports.purge()

###############################################################
#                             OLT                             #
###############################################################

    def create_mock_olts(self, num_olts, voltservice_id):
        """
        :param num_olts: Number of OLTs to be created
        :param voltservice_id: ID if the vOLT service
        :return:
        """
        olts = []
        for index in range(1, int(num_olts) + 1):
            olt = {
                'name': 'Test OLT%s' % index,
                'volt_service_id': voltservice_id,
                'device_type':  'fake_olt',
                'host': '127.0.0.1',
                'port': index,
                'uplink': '65536',
                'switch_datapath_id': 'of:0000000000000001',
                'switch_port': str(index),
                'of_id': 'of:000000%s' % index,
                'dp_id': 'of:000000%s' % index,
            }
            # logger.info('Created OLT %s' % olt, also_console=True)
            olts.append(olt)
            self.olts.insert(olt)

        return olts

    def get_rest_olts(self):
        """
        Get all the OLTs that have been created for the test
        formatted for the XOS Rest API
        :return: a list of OLTs
        """
        return self.olts.all()

    def update_olt_id(self, olt, id):
        """
        Update in the memory storage the XOS ID
        of a particular OLT as it's needed to create PON Ports
        :param olt: The OLT object to update
        :param id:  The ID returned from XOS
        :return: None
        """
        Olt = Query()
        self.olts.update({'id': id}, Olt.name == olt['name'])

###############################################################
#                        PON PORT                             #
###############################################################

    def create_mock_pon_ports(self, num_pon):

        ports = []
        for olt in self.olts.all():
            for index in range(1, int(num_pon) + 1):
                port = {
                    'name': 'Test PonPort %s Olt %s' % (index, olt['id']),
                    'port_no': index,
                    'olt_device_id': olt['id']
                }
                ports.append(port)
                self.pon_ports.insert(port)
        return ports

    def get_rest_pon_ports(self):
        """
        Get all the PON Ports that have been created for the test
        formatted for the XOS Rest API
        :return: a list of PON Ports
        """
        return self.pon_ports.all();

    def update_pon_port_id(self, pon_port, id):
        """
        Update in the memory storage the XOS ID
        of a particular PON Port as it's needed to create ONUs
        :param pon_port: The PON Port object to update
        :param id:  The ID returned from XOS
        :return: None
        """
        PonPort = Query()
        self.pon_ports.update({'id': id}, PonPort.name == pon_port['name'])

###############################################################
#                             ONU                             #
###############################################################

    def create_mock_onus(self, num_onus):
        onus = []
        j = 0
        for port in self.pon_ports.all():
            j = j + 1
            for index in range(1, int(num_onus) + 1):
                onu = {
                    'serial_number': "ROBOT%s%s" % (j, index),
                    'vendor': 'Robot',
                    'pon_port_id': port['id']
                }
                onus.append(onu)
                self.onus.insert(onu)
        return onus

    def get_rest_onus(self):
        return self.onus.all();

    def update_onu_id(self, onu, id):
        Onu = Query()
        self.onus.update({'id': id}, Onu.serial_number == onu['serial_number'])

###############################################################
#                             UNI                             #
###############################################################

    def create_mock_unis(self):
        # NOTE I believe UNI port number must be unique across OLT
        unis = []
        i = 0
        for onu in self.onus.all():
            uni = {
                'name': 'Test UniPort %s' % i,
                'port_no': i,
                'onu_device_id': onu['id']
            }
            unis.append(uni)
            self.uni_ports.insert(uni)
            i = i+1
        return unis

    def get_rest_unis(self):
        return self.uni_ports.all();

    def update_uni_id(self, uni, id):
        UniPort = Query()
        self.uni_ports.update({'id': id}, UniPort.name == uni['name'])

###############################################################
#                             WHITELIST                       #
###############################################################

    def create_mock_whitelist(self, attworkflowservice_id):
        entries = []
        for onu in self.onus.all():
            e = {
                'owner_id': attworkflowservice_id,
                'serial_number': onu['serial_number'],
                'pon_port_id': self._find_pon_port_by_onu(onu)['port_no'],
                'device_id': self._find_olt_by_onu(onu)['of_id']
            }
            entries.append(e)

        return entries

###############################################################
#                             EVENTS                          #
###############################################################

    def generate_onu_events(self):
        events = []
        for onu in self.onus.all():
            ev = {
                'status': 'activated',
                'serial_number': onu['serial_number'],
                'uni_port_id': self._find_uni_by_onu(onu)['port_no'],
                'of_dpid': self._find_olt_by_onu(onu)['of_id'],
            }
            events.append(ev)
        return events

    def generate_auth_events(self):
        events = []
        for onu in self.onus.all():
            ev = {
                'authenticationState': "APPROVED",
                'deviceId': self._find_olt_by_onu(onu)['dp_id'],
                'portNumber': self._find_uni_by_onu(onu)['port_no'],
            }
            events.append(ev)
        return events

    def generate_dhcp_events(self):
        events = []
        for onu in self.onus.all():
            ev = {
                'deviceId': self._find_olt_by_onu(onu)['dp_id'],
                'portNumber': self._find_uni_by_onu(onu)['port_no'],
                "macAddress": "aa:bb:cc:ee:ff",
                "ipAddress": "10.10.10.10",
                "messageType": "DHCPACK"
            }
            events.append(ev)
        return events

###############################################################
#                             HELPERS                         #
###############################################################

    def _find_uni_by_onu(self, onu):
        Uni = Query()
        # NOTE there's an assumption that 1 ONU has 1 UNI Port
        return self.uni_ports.search(Uni.onu_device_id == onu['id'])[0]

    def _find_pon_port_by_onu(self, onu):
        # this does not care about the olt id...
        PonPort = Query()
        return self.pon_ports.search(PonPort.id == onu['pon_port_id'])[0]

    def _find_olt_by_onu(self, onu):
        pon_port = self._find_pon_port_by_onu(onu)
        Olt = Query()
        return self.olts.search(Olt.id == pon_port['olt_device_id'])[0]