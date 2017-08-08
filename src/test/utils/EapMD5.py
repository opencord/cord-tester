
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
import sys, os
from EapolAAA import *
from Enum import *
import noseMd5AuthHolder as md5AuthHolder
from socket import *
from struct import *
from md5 import md5
from scapy.all import *
from nose.tools import *
from CordTestBase import CordTester

class MD5AuthTest(EapolPacket, CordTester):

    md5StateTable = Enumeration("MD5StateTable", ("ST_EAP_SETUP",
                                                  "ST_EAP_START",
                                                  "ST_EAP_ID_REQ",
                                                  "ST_EAP_MD5_CHALLENGE",
                                                  "ST_EAP_STATUS",
                                                  "ST_EAP_MD5_DONE"
                                                  )
                                )
    md5EventTable = Enumeration("MD5EventTable", ("EVT_EAP_SETUP",
                                                  "EVT_EAP_START",
                                                  "EVT_EAP_ID_REQ",
                                                  "EVT_EAP_MD5_CHALLENGE",
                                                  "EVT_EAP_STATUS",
                                                  "EVT_EAP_MD5_DONE"
                                                  )
                                )
    def __init__(self, intf = 'veth0', password = "password", required_status = "EAP_SUCCESS"):
        self.passwd = password
        self.req_status = required_status
        self.fsmTable = md5AuthHolder.initMd5AuthHolderFsmTable(self, self.md5StateTable, self.md5EventTable)
        EapolPacket.__init__(self, intf)
        CordTester.__init__(self, self.fsmTable, self.md5StateTable.ST_EAP_MD5_DONE)
        self.currentState = self.md5StateTable.ST_EAP_SETUP
        self.currentEvent = self.md5EventTable.EVT_EAP_SETUP
        self.nextState = None
        self.nextEvent = None

    def _eapSetup(self):
        print('Inside EAP Setup')
        self.setup()
        self.nextEvent = self.md5EventTable.EVT_EAP_START

    def _eapStart(self):
        print('Inside EAP Start')
        self.eapol_start()
        self.nextEvent = self.md5EventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        print('Inside EAP ID Req')
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print("Code %d, id %d, len %d" %(code, pkt_id, eaplen))
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        reqdata = p[5:4+eaplen]
        assert_equal(reqtype, EAP_TYPE_ID)
        print("<====== Send EAP Response with identity = %s ================>" % USER)
        self.eapol_id_req(pkt_id, USER)
        self.nextEvent = self.md5EventTable.EVT_EAP_MD5_CHALLENGE

    def _eapMd5Challenge(self):
        print('Inside EAP MD5 Challenge Exchange')
        challenge,pkt_id =self.eap_md5_challenge_recv(self.passwd)
        resp=md5(challenge).digest()
        resp=chr(len(resp))+resp
        length= 5+len(resp)
        print("Generated MD5 challenge is %s Length : %d" % (resp,length))
        print("--> Send EAP response with MD5 challenge")
        eap_payload = self.eap(EAP_RESPONSE, pkt_id, EAP_TYPE_MD5, str(resp))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = self.md5EventTable.EVT_EAP_STATUS

    def _eapStatus(self):
       print('Inside EAP Status -- Sucess/Failure')
       if self.req_status == "EAP_SUCCESS":
         status=self.eap_Status()
         print("<============EAP code received is = %d ====================>" % status)
         assert_equal(status, EAP_SUCCESS)
         print("Received EAP SUCCESS")
       else:
         print('Inside EAP Status -- Sucess/Failure ===> SUCCESS should not be received , Since Negative Testcase')
         self.s.settimeout(10)
         assert_equal(self.s.gettimeout(), 10)
         print("Check if the socket timed out ====> Since negative testcase socket should timeout because ONOS is not sending the EAP FAILURE Message")
         assert_raises(socket.error, self.s.recv, 1024)
       self.nextEvent = self.md5EventTable.EVT_EAP_MD5_DONE

    def _wrong_password(self):
       print('Start Testcase for EAP-MD5 Wrong Password')
       #self._eap_md5_states()
       self.__init__(intf = 'veth0', password = "wrong_password", required_status = "EAP_FAILURE")
