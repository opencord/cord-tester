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

from robot.api.deco import keyword

# def create_olts():
#     print('*WARN* Warning from a library. OUT')

class devices(object):

    def create_olts_data(self, num_olts, voltservice_id):
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
                'of_id': 'of:000000%s' % index
            }
            olts.append(olt)
        return olts

    def create_pon_ports_data(self, num_pon, olt_id):
        ports = []
        for index in range(1, int(num_pon) +1):
            port = {
                'name': 'Test PonPort %s' % index,
                'port_no': index,
                'olt_device_id': olt_id
            }
            ports.append(port)

        return ports
