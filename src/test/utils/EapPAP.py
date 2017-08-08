
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
import nosePAPAuthHolder as PAPAuthHolder
from socket import *
from struct import *
from scapy.all import *
from nose.tools import *
from CordTestBase import CordTester
from CordTestUtils import log_test
PAP_USER = "raduser"
PAP_PASSWD = "radpass"
log_test.setLevel('INFO')

class PAPAuthTest(EapolPacket, CordTester):

    PAPStateTable = Enumeration("PAPStateTable", ("ST_EAP_SETUP",
                                                  "ST_EAP_START",
                                                  "ST_EAP_ID_REQ",
                                                  "ST_EAP_PAP_USER_REQ",
                                                  "ST_EAP_PAP_PASSWD_REQ",
                                                  "ST_EAP_PAP_DONE"
                                                  )
                                )
    PAPEventTable = Enumeration("PAPEventTable", ("EVT_EAP_SETUP",
                                                  "EVT_EAP_START",
                                                  "EVT_EAP_ID_REQ",
                                                  "EVT_EAP_PAP_USER_REQ",
                                                  "EVT_EAP_PAP_PASSWD_REQ",
                                                  "EVT_EAP_PAP_DONE"
                                                  )
                                )
    def __init__(self, intf = 'veth0'):
        self.fsmTable = PAPAuthHolder.initPAPAuthHolderFsmTable(self, self.PAPStateTable, self.PAPEventTable)
        EapolPacket.__init__(self, intf)
        CordTester.__init__(self, self.fsmTable, self.PAPStateTable.ST_EAP_PAP_DONE)
                            #self.PAPStateTable, self.PAPEventTable)
        self.currentState = self.PAPStateTable.ST_EAP_SETUP
        self.currentEvent = self.PAPEventTable.EVT_EAP_SETUP
        self.nextState = None
        self.nextEvent = None

    def _eapSetup(self):
        print 'Inside EAP PAP Setup'
        self.setup()
        self.nextEvent = self.PAPEventTable.EVT_EAP_START

    def _eapStart(self):
        print 'Inside EAP PAP Start'
        self.eapol_start()
        self.nextEvent = self.PAPEventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        log_test.info( 'Inside EAP ID Req' )
        def eapol_cb(pkt):
                log_test.info('Got EAPOL packet with type id and code request')
                log_test.info('Packet code: %d, type: %d, id: %s', pkt[EAP].code, pkt[EAP].type, pkt[EAP].id)
                log_test.info("<====== Send EAP Response with identity = %s ================>" % PAP_USER)
                self.eapol_id_req(pkt[EAP].id, PAP_USER)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter = lambda pkt: pkt[EAP].type == EAP.TYPE_ID and pkt[EAP].code == EAP.REQUEST)
        self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_USER_REQ

    def _eapPAPUserReq(self):
        log_test.info('UserReq Inside Challenge')
        def eapol_cb(pkt):
                log_test.info('Got EAPOL packet with type id and code request')
                log_test.info('Packet code: %d, id: %s', pkt[EAP].code, pkt[EAP].id)
                log_test.info('Send EAP Response for id %s with Password = %s' %(pkt[EAP].id, PAP_PASSWD) )
                self.eapol_id_req(pkt[EAP].id, PAP_PASSWD)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter = lambda pkt: pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        #self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_PASSWD_REQ
        self.nextEvent = None

    def _eapPAPPassReq(self):
        log_test.info('PassReq Inside Challenge')
        def eapol_cb(pkt):
                log_test.info('Got EAPOL packet with type id and code request')
                log_test.info('Packet code: %d, type: %d', pkt[EAP].code, pkt[EAP].type)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter = lambda pkt: pkt[EAP].code == EAP.SUCCESS)
        self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_DONE
