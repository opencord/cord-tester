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

class bbsim_utils(object):

    def generate_subscribers(self, num_subs, rcord_service_id, stag=999, ctag_start=900, pon_id=0):
        """
        :param num_subs: Number of subscribers to create
        :param rcord_service_id: ID of the rcord service
        :param stag: S_tag of subscriber
        :param ctag: C_tag of first subscriber (to be incremented by num_subs)
        :return: List of subscribers to POST
        """
        subscribers = []
        for index in xrange(1, int(num_subs) + 1):
            sub = {
                "name" : "Sub_BBSM" + str("00000") + str(pon_id) + '{0:02x}'.format(int(index)),
                "status" : "pre-provisioned",
                "c_tag" : ctag_start + int(index),
                "s_tag" : stag,
                "onu_device" : "BBSM" + str("00000") + str(pon_id) + '{0:02x}'.format(int(index)),
                "circuit_id" : "circuit" + '{0:02x}'.format(int(index)),
                "remote_id" : "remote" + '{0:02x}'.format(int(index)),
                "nas_port_id" : "PON 2/1/01/1:1.1." + '{0:0x}'.format(int(index)),
	            "upstream_bps_id" : 1,
                "downstream_bps_id" : 1,
                "tech_profile_id" : 64
            }
            subscribers.append(sub)
            if index == 10:
                break
        for index in range(11, int(num_subs) + 1):
            sub = {
                "name" : "Sub_BBSM" + str("00000") + str(pon_id) + '{0:02x}'.format(int(index)),
                "status" : "pre-provisioned",
                "c_tag" : ctag_start + int(index),
                "s_tag" : stag,
                "onu_device" : "BBSM" + str("00000") + str(pon_id) + '{0:02x}'.format(int(index)),
                "circuit_id" : "circuit" + '{0:02x}'.format(int(index)),
                "remote_id" : "remote" + '{0:02x}'.format(int(index)),
                "nas_port_id" : "PON 2/1/01/1:1.1." + str(pon_id) + '{0:02x}'.format(int(index)),
                "upstream_bps_id" : 1,
                "downstream_bps_id" : 1,
                "tech_profile_id" : 64
            }
            subscribers.append(sub)
        return subscribers

    def generate_whitelists(self, num_onus, att_service_id, pon_id=0):
        """
        :param num_onus: Number of ONUs to be added to the whitelist
        :param att_service_id: ID of the att workflow service
        :param olt_id: ID of the pon_port
        :return: List of whitelists to POST
        """
        whitelists = []
        for index in range(1, int(num_onus) + 1):
            onu = {
                "serial_number": "BBSM" + str("00000") + str(pon_id) + '{0:02x}'.format(int(index)),
                "device_id" : "of:0000626273696d76",
                "pon_port_id" : 536870912,
                "owner_id" : att_service_id
            }
            whitelists.append(onu)
        return whitelists
