import sys, os
cord_root = os.getenv('CORD_TEST_ROOT') or './'
CORD_TEST_FSM = 'fsm'
sys.path.append(cord_root + CORD_TEST_FSM)
from EapolAAA import *
from enum import *
import nosePAPAuthHolder as PAPAuthHolder
from socket import *
from struct import *
import scapy
from nose.tools import *
from CordTestBase import CordTester
PAP_USER = "raduser"
PAP_PASSWD = "radpass"

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
        print 'Inside EAP ID Req'
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        reqdata = p[5:4+eaplen]
        assert_equal(reqtype, EAP_TYPE_ID)
        print "<====== Send EAP Response with identity = %s ================>" % PAP_USER
        self.eapol_id_req(pkt_id, PAP_USER)
        self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_USER_REQ

    def _eapPAPUserReq(self):
        print 'Inside Challenge'
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        reqdata = p[5:4+eaplen]
        assert_equal(reqtype, EAP_TYPE_MD5)
        print "<====== Send EAP Response with Password = %s ================>" % PAP_PASSWD 
        self.eapol_id_req(pkt_id, PAP_PASSWD)
        self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_PASSWD_REQ
 
    def _eapPAPPassReq(self):
        print 'Inside Challenge'
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_SUCCESS)
        self.nextEvent = self.PAPEventTable.EVT_EAP_PAP_DONE
 
