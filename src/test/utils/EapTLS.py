import sys, os
cord_root = os.getenv('CORD_TEST_ROOT') or './'
CORD_TEST_FSM = 'fsm'
sys.path.append(cord_root + CORD_TEST_FSM)
from EapolAAA import *
from enum import *
import noseTlsAuthHolder as tlsAuthHolder
from scapy_ssl_tls.ssl_tls import *
from socket import *
from struct import *
import scapy
from nose.tools import *
from CordTestBase import CordTester

class TLSAuthTest(EapolPacket, CordTester):

    tlsStateTable = Enumeration("TLSStateTable", ("ST_EAP_SETUP",
                                                  "ST_EAP_START",
                                                  "ST_EAP_ID_REQ",
                                                  "ST_EAP_TLS_HELLO_REQ",
                                                  "ST_EAP_TLS_CERT_REQ",
                                                  "ST_EAP_TLS_DONE"
                                                  )
                                )
    tlsEventTable = Enumeration("TLSEventTable", ("EVT_EAP_SETUP",
                                                  "EVT_EAP_START",
                                                  "EVT_EAP_ID_REQ",
                                                  "EVT_EAP_TLS_HELLO_REQ",
                                                  "EVT_EAP_TLS_CERT_REQ",
                                                  "EVT_EAP_TLS_DONE"
                                                  )
                                )
    def __init__(self, intf = 'veth0'):
        self.fsmTable = tlsAuthHolder.initTlsAuthHolderFsmTable(self, self.tlsStateTable, self.tlsEventTable)
        EapolPacket.__init__(self, intf)
        CordTester.__init__(self, self.fsmTable, self.tlsStateTable.ST_EAP_TLS_DONE)
                            #self.tlsStateTable, self.tlsEventTable)
        self.currentState = self.tlsStateTable.ST_EAP_SETUP
        self.currentEvent = self.tlsEventTable.EVT_EAP_SETUP
        self.nextState = None
        self.nextEvent = None

    def _eapSetup(self):
        print 'Inside EAP Setup'
        self.setup()
        self.nextEvent = self.tlsEventTable.EVT_EAP_START
        
    def _eapStart(self):
        print 'Inside EAP Start'
        self.eapol_start()
        self.nextEvent = self.tlsEventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        print 'Inside EAP ID Req'
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        reqdata = p[5:4+eaplen]
        assert_equal(reqtype, EAP_TYPE_ID)
        print "<====== Send EAP Response with identity = %s ================>" % USER
        self.eapol_id_req(pkt_id, USER)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_HELLO_REQ

    def _eapTlsHelloReq(self):
        print 'Inside EAP TLS Hello Req'
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        assert_equal(reqtype, EAP_TYPE_TLS)
        reqdata = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSClientHello(version="TLS_1_0",
                                                                             gmt_unix_time=1234,
                                                                             random_bytes="A" * 28,
                                                                             session_id='',
                                                                             compression_methods=(TLSCompressionMethod.NULL), 
                                                                             cipher_suites=[TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA]
                                                                             )

        #reqdata.show()
        print "------> Sending Client Hello TLS payload of len %d ----------->" %len(reqdata)
        eap_payload = self.eapTLS(EAP_RESPONSE, pkt_id, TLS_LENGTH_INCLUDED, str(reqdata))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CERT_REQ

    def _eapTlsCertReq(self):
        print 'Inside EAP TLS Cert Req'
        p = self.eapol_recv()
        print 'Got TLS Cert Req with payload len: %d' %len(p)
        self.nextEvent = None
