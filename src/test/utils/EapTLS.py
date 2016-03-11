import sys, os
from EapolAAA import *
from enum import *
import noseTlsAuthHolder as tlsAuthHolder
from scapy_ssl_tls.ssl_tls import *
from socket import *
from struct import *
import scapy
from nose.tools import *
from CordTestBase import CordTester
import re
log.setLevel('DEBUG')
class TLSAuthTest(EapolPacket, CordTester):

    tlsStateTable = Enumeration("TLSStateTable", ("ST_EAP_SETUP",
                                                  "ST_EAP_START",
                                                  "ST_EAP_ID_REQ",
                                                  "ST_EAP_TLS_HELLO_REQ",
                                                  "ST_EAP_TLS_CERT_REQ",
                                                  "ST_EAP_TLS_CHANGE_CIPHER_SPEC",
                                                  "ST_EAP_TLS_FINISHED",
                                                  "ST_EAP_TLS_DONE"
                                                  )
                                )
    tlsEventTable = Enumeration("TLSEventTable", ("EVT_EAP_SETUP",
                                                  "EVT_EAP_START",
                                                  "EVT_EAP_ID_REQ",
                                                  "EVT_EAP_TLS_HELLO_REQ",
                                                  "EVT_EAP_TLS_CERT_REQ",
                                                  "EVT_EAP_TLS_CHANGE_CIPHER_SPEC",
                                                  "EVT_EAP_TLS_FINISHED",
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
        self.setup()
        self.nextEvent = self.tlsEventTable.EVT_EAP_START
        
    def _eapStart(self):
        self.eapol_start()
        self.nextEvent = self.tlsEventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        reqdata = p[5:4+eaplen]
        assert_equal(reqtype, EAP_TYPE_ID)
        log.debug("<====== Send EAP Response with identity = %s ================>" % USER)
        self.eapol_id_req(pkt_id, USER)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_HELLO_REQ

    def _eapTlsHelloReq(self):
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
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
        log.debug("------> Sending Client Hello TLS payload of len %d ----------->" %len(reqdata))
        eap_payload = self.eapTLS(EAP_RESPONSE, pkt_id, TLS_LENGTH_INCLUDED, str(reqdata))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CERT_REQ

    def _eapTlsCertReq(self):
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        assert_equal(reqtype, EAP_TYPE_TLS)
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)
        self.pem_cert = """-----BEGIN CERTIFICATE-----
MIIDvTCCAqWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBizELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAkNBMRIwEAYDVQQHEwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5h
IEluYy4xHjAcBgkqhkiG9w0BCQEWD2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMd
RXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMTYwMzExMTg1MzM2WhcN
MTcwMzA2MTg1MzM2WjBnMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNV
BAoTCkNpZW5hIEluYy4xFzAVBgNVBAMUDnVzZXJAY2llbmEuY29tMR0wGwYJKoZI
hvcNAQkBFg51c2VyQGNpZW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAOxemcBsPn9tZsCa5o2JA6sQDC7A6JgCNXXl2VFzKLNNvB9PS6D7ZBsQ
5An0zEDMNzi51q7lnrYg1XyiE4S8FzMGAFr94RlGMQJUbRD9V/oqszMX4k++iAOK
tIA1gr3x7Zi+0tkjVSVzXTmgNnhChAamdMsjYUG5+CY9WAicXyy+VEV3zTphZZDR
OjcjEp4m/TSXVPYPgYDXI40YZKX5BdvqykWtT/tIgZb48RS1NPyN/XkCYzl3bv21
qx7Mc0fcEbsJBIIRYTUkfxnsilcnmLxSYO+p+DZ9uBLBzcQt+4Rd5pLSfi21WM39
2Z2oOi3vs/OYAPAqgmi2JWOv3mePa/8CAwEAAaNPME0wEwYDVR0lBAwwCgYIKwYB
BQUHAwIwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL3d3dy5leGFtcGxlLmNvbS9l
eGFtcGxlX2NhLmNybDANBgkqhkiG9w0BAQUFAAOCAQEALBzMPDTIB6sLyPl0T6JV
MjOkyldAVhXWiQsTjaGQGJUUe1cmUJyZbUZEc13MygXMPOM4x7z6VpXGuq1c/Vxn
VzQ2fNnbJcIAHi/7G8W5/SQfPesIVDsHTEc4ZspPi5jlS/MVX3HOC+BDbOjdbwqP
RX0JEr+uOyhjO+lRxG8ilMRACoBUbw1eDuVDoEBgErSUC44pq5ioDw2xelc+Y6hQ
dmtYwfY0DbvwxHtA495frLyPcastDiT/zre7NL51MyUDPjjYjghNQEwvu66IKbQ3
T1tJBrgI7/WI+dqhKBFolKGKTDWIHsZXQvZ1snGu/FRYzg1l+R/jT8cRB9BDwhUt
yg==
-----END CERTIFICATE-----"""
        self.der_cert = rex_pem.findall(self.pem_cert)[0].decode("base64")
        reqdata = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSCertificateList(
            certificates=[TLSCertificate(data=x509.X509Cert(self.der_cert))])
        #reqdata.show()
        log.info("------> Sending Client Hello TLS Certificate payload of len %d ----------->" %len(reqdata))
        eap_payload = self.eapTLS(EAP_RESPONSE, pkt_id, TLS_LENGTH_INCLUDED, str(reqdata))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CHANGE_CIPHER_SPEC

    def _eapTlsChangeCipherSpec(self):
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        assert_equal(reqtype, EAP_TYPE_TLS)
        reqdata = TLSFinished(data="")
        eap_payload = self.eapTLS(EAP_RESPONSE, pkt_id, TLS_LENGTH_INCLUDED, str(reqdata))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_FINISHED

    def _eapTlsFinished(self):
        p = self.eapol_recv()
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        log.debug("Code %d, id %d, len %d" %(code, pkt_id, eaplen))
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        assert_equal(reqtype, EAP_TYPE_TLS)
        #We stop here as certification validation success implies auth success
        self.nextEvent = None
