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
from enum import *
import noseTlsAuthHolder as tlsAuthHolder
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *
from socket import *
from struct import *
import scapy
from nose.tools import *
from CordTestBase import CordTester
import re

log.setLevel('INFO')

def bytes_to_num(data):
    return int(data.encode('hex'), 16)

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
    server_hello_done_signature = '\x0e\x00\x00\x00'
    SERVER_HELLO = '\x02'
    SERVER_CERTIFICATE = '\x0b'
    SERVER_HELLO_DONE = '\x0d'
    SERVER_UNKNOWN = '\xff'
    HANDSHAKE = '\x16'
    CHANGE_CIPHER = '\x14'
    TLS_OFFSET = 28
    HDR_IDX = 0
    DATA_IDX = 1
    CB_IDX = 2
    CLIENT_CERT = """-----BEGIN CERTIFICATE-----
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

    def handle_server_hello_done(self, server_hello_done):
        if server_hello_done[-4:] == self.server_hello_done_signature:
            self.server_hello_done_received = True

    def __init__(self, intf = 'veth0'):
        self.fsmTable = tlsAuthHolder.initTlsAuthHolderFsmTable(self, self.tlsStateTable, self.tlsEventTable)
        EapolPacket.__init__(self, intf)
        CordTester.__init__(self, self.fsmTable, self.tlsStateTable.ST_EAP_TLS_DONE)
                            #self.tlsStateTable, self.tlsEventTable)
        self.currentState = self.tlsStateTable.ST_EAP_SETUP
        self.currentEvent = self.tlsEventTable.EVT_EAP_SETUP
        self.nextState = None
        self.nextEvent = None
        self.pending_bytes = 0 #for TLS fragment reassembly
        self.server_hello_done_received = False
        self.send_tls_response = True
        self.server_certs = []
        self.pkt_last = ''
        self.pkt_history = []
        self.pkt_map = { self.SERVER_HELLO: ['', '', lambda pkt: pkt ],
                         self.SERVER_CERTIFICATE: ['', '', lambda pkt: pkt ],
                         self.SERVER_HELLO_DONE: ['', '', self.handle_server_hello_done ],
                         self.SERVER_UNKNOWN: ['', '', lambda pkt: pkt ]
                       }
        self.tls_ctx = TLSSessionCtx(client = True)

    def load_tls_record(self, data, pkt_type = ''):
        if pkt_type not in [ self.SERVER_HELLO_DONE, self.SERVER_UNKNOWN ]:
            TLS(data, ctx = self.tls_ctx)

    def pkt_update(self, pkt_type, data, hdr=None, reassembled = False):
        if not self.pkt_map.has_key(pkt_type):
            return
        if hdr is not None:
            self.pkt_map[pkt_type][self.HDR_IDX] += hdr
        self.pkt_map[pkt_type][self.DATA_IDX] += data
        if reassembled is True:
            self.pkt_map[pkt_type][self.CB_IDX](self.pkt_map[pkt_type][self.DATA_IDX])
            log.info('Appending packet type %02x to packet history of len %d'
                     %(ord(pkt_type), len(self.pkt_map[pkt_type][self.DATA_IDX])))
            self.pkt_history.append(self.pkt_map[pkt_type][self.DATA_IDX])
            data = ''.join(self.pkt_map[pkt_type][:self.DATA_IDX+1])
            self.load_tls_record(data, pkt_type = pkt_type)
            self.pkt_map[pkt_type][self.HDR_IDX] = ''
            self.pkt_map[pkt_type][self.DATA_IDX] = ''

    def eapol_server_hello_cb(self, pkt):
        '''Reassemble and send response for server hello/certificate fragments'''
        r = str(pkt)
        offset = self.TLS_OFFSET
        tls_data = r[offset:]
        if self.pending_bytes > 0:
            if len(tls_data) >= self.pending_bytes:
                self.pkt_update(self.pkt_last, tls_data[:self.pending_bytes], reassembled = True)
                offset += self.pending_bytes
                self.pkt_last = ''
                self.pending_bytes = 0
            else:
                self.pkt_update(self.pkt_last, tls_data)
                self.pending_bytes -= len(tls_data)

        while self.pending_bytes == 0 and offset < len(pkt):
            tls_data = r[offset:]
            self.pending_bytes = bytes_to_num(tls_data[3:5])
            if tls_data[0] == self.HANDSHAKE:
                pkt_type = tls_data[5]
                if len(tls_data) - 5 >= self.pending_bytes:
                    data_received = tls_data[5: 5 + self.pending_bytes]
                    offset += 5 + self.pending_bytes
                    self.pending_bytes = 0
                    self.pkt_update(pkt_type, data_received,
                                    hdr = tls_data[:5],
                                    reassembled = True)
                else:
                    self.pkt_update(pkt_type, tls_data[5:],
                                    hdr = tls_data[:5],
                                    reassembled = False)
                    self.pending_bytes -= len(tls_data) - 5
                    self.pkt_last = pkt_type
                    log.info('Pending bytes left %d' %(self.pending_bytes))
                    assert self.pending_bytes > 0
            else:
                self.pkt_last = self.SERVER_UNKNOWN
                if len(tls_data) - 5 >= self.pending_bytes:
                    offset += 5 + self.pending_bytes
                    self.pending_bytes = 0
                    self.pkt_last = ''

        #send TLS response
        if self.send_tls_response:
            eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, TLS_LENGTH_INCLUDED, '')
            self.eapol_send(EAPOL_EAPPACKET, eap_payload)

    def _eapSetup(self):
        self.setup()
        self.nextEvent = self.tlsEventTable.EVT_EAP_START
        
    def _eapStart(self):
        self.eapol_start()
        self.nextEvent = self.tlsEventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        log.info( 'Inside EAP ID Req' )
        def eapol_cb(pkt):
                log.info('Got EAPOL packet with type id and code request')
                log.info('Packet code: %d, type: %d, id: %d', pkt[EAP].code, pkt[EAP].type, pkt[EAP].id)
                log.info("<====== Send EAP Response with identity = %s ================>" % USER)
                self.eapol_id_req(pkt[EAP].id, USER)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].type == EAP.TYPE_ID and pkt[EAP].code == EAP.REQUEST)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_HELLO_REQ

    def _eapTlsHelloReq(self):

        def eapol_cb(pkt):
                log.info('Got hello request for id %d', pkt[EAP].id)
                self.client_hello = TLSClientHello(version="TLS_1_0",
                                                   gmt_unix_time=1234,
                                                   random_bytes= '\xAB' * 28,
                                                   session_id='',
                                                   compression_methods=(TLSCompressionMethod.NULL),
                                                   cipher_suites=[TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA]
                                                   )
                self.pkt_history.append( str(self.client_hello) )
                reqdata = TLSRecord()/TLSHandshake()/self.client_hello
                self.load_tls_record(str(reqdata))
                log.info("Sending Client Hello TLS payload of len %d, id %d" %(len(reqdata),pkt[EAP].id))
                eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, TLS_LENGTH_INCLUDED, str(reqdata))
                self.eapol_send(EAPOL_EAPPACKET, eap_payload)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)

        for i in range(2):
            self.eapol_scapy_recv(cb = self.eapol_server_hello_cb,
                                  lfilter =
                                  lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        ##send cert request when we receive the last server hello fragment
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CERT_REQ

    def get_encrypted_handshake_msg(self, finish_val=''):
        all_handshake_pkts = ''.join(self.pkt_history)
        if not finish_val:
            finish_val = self.tls_ctx.get_verify_data(data = all_handshake_pkts)
        msg = str(TLSHandshake(type=TLSHandshakeType.FINISHED)/finish_val)
        crypto_container = CryptoContainer(self.tls_ctx, data = msg,
                                           content_type = TLSContentType.HANDSHAKE)
        return crypto_container.encrypt()

    def _eapTlsCertReq(self):

        def eapol_cb(pkt):
                log.info('Got cert request')
                self.send_tls_response = False
                self.eapol_server_hello_cb(pkt)
                assert self.server_hello_done_received == True
                rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)
                der_cert = rex_pem.findall(self.CLIENT_CERT)[0].decode("base64")
                client_certificate = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSCertificateList(
                    certificates=[TLSCertificate(data=x509.X509Cert(der_cert))])
                kex_data = self.tls_ctx.get_client_kex_data()
                client_key_ex = TLSRecord()/TLSHandshake()/kex_data
                client_key_ex_data = str(TLSHandshake()/kex_data)
                self.pkt_history.append(client_key_ex_data)
                self.load_tls_record(str(client_key_ex))
                #log.info('TLS ctxt: %s' %self.tls_ctx)
                client_ccs = TLSRecord(version="TLS_1_0")/TLSChangeCipherSpec()
                enc_handshake_msg = self.get_encrypted_handshake_msg()
                handshake_msg = str(TLSRecord(content_type=TLSContentType.HANDSHAKE)/enc_handshake_msg)
                reqdata = str(TLS.from_records( [client_certificate, client_key_ex, client_ccs] ))
                reqdata += handshake_msg
                log.info("------> Sending Client Hello TLS Certificate payload of len %d ----------->" %len(reqdata))
                eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, TLS_LENGTH_INCLUDED, str(reqdata))
                self.eapol_send(EAPOL_EAPPACKET, eap_payload)

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CHANGE_CIPHER_SPEC

    def _eapTlsChangeCipherSpec(self):
        def eapol_cb(pkt):
            r = str(pkt)
            tls_data = r[TLS_OFFSET:]
            log.info('Verifying TLS Change Cipher spec record type %x' %ord(tls_data[0]))
            assert tls_data[0] == self.CHANGE_CIPHER

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_FINISHED

    def _eapTlsFinished(self):

        def eapol_cb(pkt):
                log.info('Got Server finished')

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        #We stop here as certification validation success implies auth success
        self.nextEvent = None
