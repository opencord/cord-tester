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
from tls_cert import Key
from socket import *
from CordTestServer import cord_test_radius_restart
import struct
import scapy
from nose.tools import *
from CordTestBase import CordTester
from CordContainer import *
import re
import time

log.setLevel('INFO')

def bytes_to_num(data):
    try:
        return int(data.encode('hex'), 16)
    except:
        print('Exception')
        return -1

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
    CERTIFICATE_REQUEST = '\x0d'
    SERVER_HELLO_DONE = '\x0e'
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

    CLIENT_PRIV_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7F6ZwGw+f21mwJrmjYkDqxAMLsDomAI1deXZUXMos028H09L
oPtkGxDkCfTMQMw3OLnWruWetiDVfKIThLwXMwYAWv3hGUYxAlRtEP1X+iqzMxfi
T76IA4q0gDWCvfHtmL7S2SNVJXNdOaA2eEKEBqZ0yyNhQbn4Jj1YCJxfLL5URXfN
OmFlkNE6NyMSnib9NJdU9g+BgNcjjRhkpfkF2+rKRa1P+0iBlvjxFLU0/I39eQJj
OXdu/bWrHsxzR9wRuwkEghFhNSR/GeyKVyeYvFJg76n4Nn24EsHNxC37hF3mktJ+
LbVYzf3Znag6Le+z85gA8CqCaLYlY6/eZ49r/wIDAQABAoIBAQC9Oha4l2+JMBoc
g2WjVVcccWJvY3xRhSMrWXEa5ahlswuxvRd8rwS7LlCBL/r8vQBQZ2ZY6fafM7X1
awNZNgMUk+9g6PJ1+11s0g3mlgsCeYCwnKRO1ueofjh2k2AxlCZ0LAA8WS7nJm4x
nfM9X3K2qDfEEHTh23Gvm1iIvDbtZ3+kXnjsdAuYduiaDDPNSyNOSCe2eCt2d9vt
twV5pEf0PXcuLJ29i2LkRKdPwz/1J/AAE0dTJS9lrlLKE9qWXO2my4eUQI2FXVzW
RpxhjGoFNXa59okobZ555rRrp4LHe8HPx5aowLSS5HGGrXHpiyYpFR9uciQxMD6q
BQgmim5RAoGBAP09mWJS2gyiB9xqNY8MYyTrldXUIfujJ5OZch088rmbdS2p3TvG
Oy6K0rOufBMCl95Ncv6YQ7cjQKpq8Q7fTfPkRI3/994DZu5D+vwyqIZpBnHDAnTi
R9kf1Ep1QHmJPPE1GcijTnksaXP5g9+me2fTi4cCcl+An8GPv06z/KKjAoGBAO7x
8MH1Dy2zAJhvlPbXdQLa/6b5aQeEVqObnJUvEaEy4M3c0QakULTDVQjsu/+ONNNV
0Z5ZsBIWe/LaXxenub9lRJpD4KZOdz5bYIIq+Oa8L4bqTvyB/pVcZOE5a4ANvGiC
4rVdAenPu734skgDFQPNZWKi/T6OZyJYgNzHG4L1AoGAEugvdHzVFM5gId+4Ifb9
y/re0/kjlGMJCGcTcwVi5eKqa/9bqiPRtVbeBlZHoy+1YP6NUF7T5291W4PifYbE
jioDyEpNGkFMxQtESOILXQWoWoQBwfJHBPnwYqLAbpKFf0jEpQs0R62+Lc96Pg9y
9TyBFVJkcabrxorR8LFVclsCgYB8+eJ5MBneRy/aixIZAZxb//uTdAQxQFCohi2i
Adpwu9HFGufhV3Q296u0XU3/XnvWxZ47+qES9Nujq//suXd32hnFrhcEJSpNXTHf
I2bIGEmrgUYK4Fst+ANzobrOYWDYMQ0u2xSzHEoQFNH6xFHriTSsIJ/gZk8fMbdE
wodrOQKBgQCOsFLo97vhlv6abA4v0T6bXuq4pzedIEh3bkqC/8rpLxqG98VoymHM
bZIYf0U0KK3aNVfyXkIjGBaqA9/A0ttx/guOacf8M3yXbl3uEqlKevJTjhWlbUjp
fM2med+fZ0+bh4DZ3O8BUJ1+6dxHngF/86GlwxTK4iSRkLIv6n3YSA==
-----END RSA PRIVATE KEY-----"""

    def handle_server_hello_done(self, server_hello_done):
        if server_hello_done[-4:] == self.server_hello_done_signature:
	    log.info('server hello received')
            self.server_hello_done_received = True

    def __init__(self, intf = 'veth0', client_cert = None, client_priv_key = None,
                 fail_cb = None, src_mac='default', version = "TLS_1_0", session_id = '',
                 session_id_length = None, gmt_unix_time=1234, invalid_content_type = 22,
                 record_fragment_length = None, cipher_suites_length = None,
                 compression_methods_length = None, compression_methods = TLSCompressionMethod.NULL,
                 CipherSuite = True, cipher_suite = 'RSA_WITH_AES_256_CBC_SHA', id_mismatch_in_identifier_response_packet = False,
                 id_mismatch_in_client_hello_packet = False , dont_send_client_certificate = False,
                 dont_send_client_hello = False, restart_radius = False, invalid_client_hello_handshake_type = False,
                 invalid_cert_req_handshake = False, incorrect_tlsrecord_type_cert_req = False,
                 invalid_client_hello_handshake_length = False, clientkeyex_replace_with_serverkeyex = False):

        self.fsmTable = tlsAuthHolder.initTlsAuthHolderFsmTable(self, self.tlsStateTable, self.tlsEventTable)
        EapolPacket.__init__(self, intf)
        CordTester.__init__(self, self.fsmTable, self.tlsStateTable.ST_EAP_TLS_DONE)
                            #self.tlsStateTable, self.tlsEventTable)
        self.currentState = self.tlsStateTable.ST_EAP_SETUP
        self.currentEvent = self.tlsEventTable.EVT_EAP_SETUP
	self.src_mac = src_mac
	self.version = version
        self.session_id_length = session_id_length
        self.session_id = session_id
        self.gmt_unix_time = gmt_unix_time
        self.invalid_content_type = invalid_content_type
        self.CipherSuite = CipherSuite
        self.cipher_suites_length = cipher_suites_length
        self.compression_methods_length = compression_methods_length
        self.cipher_suite = cipher_suite
        self.compression_methods_length = compression_methods_length
        self.compression_methods = compression_methods
        self.record_fragment_length = record_fragment_length
	self.invalid_client_hello_handshake_type = invalid_client_hello_handshake_type
	self.invalid_client_hello_handshake_length = invalid_client_hello_handshake_length
	self.invalid_cert_req_handshake = invalid_cert_req_handshake
        self.id_mismatch_in_identifier_response_packet = id_mismatch_in_identifier_response_packet
        self.id_mismatch_in_client_hello_packet = id_mismatch_in_client_hello_packet
        self.dont_send_client_certificate = dont_send_client_certificate
        self.dont_send_client_hello = dont_send_client_hello
	self.incorrect_tlsrecord_type_cert_req = incorrect_tlsrecord_type_cert_req
	self.restart_radius = restart_radius
	self.clientkeyex_replace_with_serverkeyex = clientkeyex_replace_with_serverkeyex
        self.nextState = None
        self.nextEvent = None
        self.pending_bytes = 0 #for TLS fragment reassembly
        self.server_hello_done_received = False
        self.server_hello_done_eap_id = 0
        self.send_tls_response = True
        self.server_certs = []
        self.pkt_last = ''
        self.pkt_history = []
        self.pkt_map = { self.SERVER_HELLO: ['', '', lambda pkt: pkt ],
                         self.SERVER_CERTIFICATE: ['', '', lambda pkt: pkt ],
                         self.CERTIFICATE_REQUEST: ['', '', lambda pkt: pkt ],
                         self.SERVER_HELLO_DONE: ['', '', self.handle_server_hello_done ],
                         self.SERVER_UNKNOWN: ['', '', lambda pkt: pkt ]
                       }
	if self.clientkeyex_replace_with_serverkeyex:
            self.tls_ctx = TLSSessionCtx(client = False)
	else:
	    self.tls_ctx = TLSSessionCtx(client = True)
        self.client_cert = self.CLIENT_CERT if client_cert is None else client_cert
        self.client_priv_key = self.CLIENT_PRIV_KEY if client_priv_key is None else client_priv_key
        self.failTest = False
        self.fail_cb = fail_cb

    def load_tls_record(self, data, pkt_type = ''):
        #if pkt_type not in [ self.SERVER_HELLO_DONE, self.SERVER_UNKNOWN ]:
        if pkt_type == self.SERVER_HELLO_DONE:
            data = str(TLSRecord(content_type=TLSContentType.HANDSHAKE)/data)
        elif pkt_type == self.CERTIFICATE_REQUEST:
            data = str(TLSRecord()/TLSHandshake(type=TLSHandshakeType.CERTIFICATE_REQUEST)/data[9:])
            data = None #For now ignore this record
        if data:
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

    def tlsFail(self):
        ##Force a failure
	log.info('entering into testFail function')
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_FINISHED
        self.nextState = self.tlsStateTable.ST_EAP_TLS_FINISHED
        self.failTest = True

    def eapol_server_hello_cb(self, pkt):
        '''Reassemble and send response for server hello/certificate fragments'''
        r = str(pkt)
        offset = self.TLS_OFFSET
        tls_data = r[offset:]
        type_hdrlen = 0
        if self.pending_bytes > 0:
            if len(tls_data) >= self.pending_bytes:
                self.pkt_update(self.pkt_last, tls_data[:self.pending_bytes], reassembled = True)
                offset += self.pending_bytes
                self.pkt_last = ''
                self.pending_bytes = 0
            else:
                self.pkt_update(self.pkt_last, tls_data)
                self.pending_bytes -= len(tls_data)
        print('Offset: %d, pkt : %d, pending %d\n' %(offset, len(pkt), self.pending_bytes))
        while self.pending_bytes == 0 and offset < len(pkt):
            tls_data = r[offset:]
            hexdump(tls_data)
            self.pending_bytes = bytes_to_num(tls_data[3:5])
            if self.pending_bytes < 0:
                self.pending_bytes = 0
                return
            if tls_data[0] == self.HANDSHAKE:
                pkt_type = tls_data[5]
                if pkt_type in [ self.CERTIFICATE_REQUEST ]:
                    self.pending_bytes = bytes_to_num(tls_data[6:9])
                    type_hdrlen = 4
                if len(tls_data) - 5 - type_hdrlen >= self.pending_bytes:
                    data_received = tls_data[5: 5 + type_hdrlen + self.pending_bytes ]
                    offset += 5 + type_hdrlen + self.pending_bytes
                    type_hdrlen = 0
                    self.pending_bytes = 0
                    self.pkt_update(pkt_type, data_received,
                                    hdr = tls_data[:5],
                                    reassembled = True)
                else:
                    self.pkt_update(pkt_type, tls_data[5:],
                                    hdr = tls_data[:5],
                                    reassembled = False)
                    self.pending_bytes -= len(tls_data) - 5 - type_hdrlen
                    self.pkt_last = pkt_type
                    log.info('Pending bytes left %d' %(self.pending_bytes))
                    assert self.pending_bytes > 0
            elif tls_data[0] == self.SERVER_HELLO_DONE:
                self.server_hello_done_eap_id = pkt[EAP].id
                self.pkt_update(tls_data[0], tls_data, reassembled = True)
                break
            else:
                self.pkt_last = self.SERVER_UNKNOWN
                if len(tls_data) - 5 >= self.pending_bytes:
                    offset += 5 + self.pending_bytes
                    self.pending_bytes = 0
                    self.pkt_last = ''

        #send TLS response ack till we receive server hello done
        if self.server_hello_done_received == False:
            eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, TLS_LENGTH_INCLUDED, '')
            self.eapol_send(EAPOL_EAPPACKET, eap_payload)

    def _eapSetup(self):
	#if self.src_mac == 'bcast':self.setup(src_mac='bcast')
	#if self.src_mac == 'mcast': self.setup(src_mac='mcast')
	#if self.src_mac == 'zeros': self.setup(src_mac='zeros')
	#if self.src_mac == 'default': self.setup(src_mac='default')
	log.info('source mac is %s'%self.src_mac)
	self.setup(src_mac=self.src_mac)
        self.nextEvent = self.tlsEventTable.EVT_EAP_START

    def _eapStart(self):
	log.info('_eapStart method started')
        self.eapol_start()
        self.nextEvent = self.tlsEventTable.EVT_EAP_ID_REQ

    def _eapIdReq(self):
        log.info( 'Inside EAP ID Req' )
        def eapol_cb(pkt):
                log.info('Got EAPOL packet with type id and code request')
                log.info('Packet code: %d, type: %d, id: %d', pkt[EAP].code, pkt[EAP].type, pkt[EAP].id)
                log.info("<====== Send EAP Response with identity = %s ================>" % USER)
		if self.id_mismatch_in_identifier_response_packet:
		    log.info('\nSending invalid id field in EAP Identity Response packet')
                    self.eapol_id_req(pkt[EAP].id+10, USER)
		else:
		    self.eapol_id_req(pkt[EAP].id, USER)

        r = self.eapol_scapy_recv(cb = eapol_cb,
                                  lfilter =
                                  lambda pkt: EAP in pkt and pkt[EAP].type == EAP.TYPE_ID and pkt[EAP].code == EAP.REQUEST)
        if len(r) > 0:
            self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_HELLO_REQ
        else:
            self.tlsFail()
            return r

    def _eapTlsHelloReq(self):

        def eapol_cb(pkt):
                log.info('Got hello request for id %d', pkt[EAP].id)
                self.client_hello = TLSClientHello(version= self.version,
                                                   gmt_unix_time=self.gmt_unix_time,
                                                   random_bytes= '\xAB' * 28,
                                                   session_id_length = self.session_id_length,
                                                   session_id= self.session_id,
                                                   compression_methods_length = self.compression_methods_length,
                                                   compression_methods= self.compression_methods,
                                                   cipher_suites_length = self.cipher_suites_length,
                                                   cipher_suites=[self.cipher_suite]
                                                   )
		if self.invalid_client_hello_handshake_type:
		    log.info('sending server_hello instead of client_hello handshape type in client hello packet')
		    client_hello_data = TLSHandshake(type='server_hello')/self.client_hello
		elif self.invalid_client_hello_handshake_length:
		    log.info('sending TLS Handshake message with zero length field in client hello packet')
		    client_hello_data = TLSHandshake(length=0)/self.client_hello
		else:
		    client_hello_data = TLSHandshake()/self.client_hello
                #client_hello_data = TLSHandshake()/self.client_hello
                self.pkt_history.append( str(client_hello_data) )
		if self.record_fragment_length:
                    reqdata = TLSRecord(length=self.record_fragment_length)/client_hello_data
		else:
		    reqdata = TLSRecord()/client_hello_data
                self.load_tls_record(str(reqdata))
                log.info("Sending Client Hello TLS payload of len %d, id %d" %(len(reqdata),pkt[EAP].id))
		if self.id_mismatch_in_client_hello_packet:
                    log.info('\nsending invalid id field in client hello packet')
                    eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id+10, TLS_LENGTH_INCLUDED, str(reqdata))
                else:
                    eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, TLS_LENGTH_INCLUDED, str(reqdata))
                if self.dont_send_client_hello:
                    log.info('\nskipping client hello packet sending part')
                    pass
                else:
                    self.eapol_send(EAPOL_EAPPACKET, eap_payload)
		if self.restart_radius:
                    cord_test_radius_restart()

        r = self.eapol_scapy_recv(cb = eapol_cb,
                                  lfilter =
                                  lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)

        if len(r) == 0:
            self.tlsFail()
            return r

        #move to client/server certificate request
        self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CERT_REQ

    def get_verify_data(self):
        all_handshake_pkts = ''.join(self.pkt_history)
        return self.tls_ctx.get_verify_data(data = all_handshake_pkts)

    def get_verify_signature(self, pem_data):
        all_handshake_pkts = ''.join(self.pkt_history)
        k = Key(pem_data)
        signature = k.sign(all_handshake_pkts, t = 'pkcs', h = 'tls')
        signature_data = '{}{}'.format(struct.pack('!H', len(signature)), signature)
        return signature_data

    def get_encrypted_handshake_msg(self, finish_val=''):
        if not finish_val:
            finish_val = self.get_verify_data()
        msg = str(TLSHandshake(type=TLSHandshakeType.FINISHED)/finish_val)
        crypto_container = CryptoContainer(self.tls_ctx, data = msg,
                                           content_type = TLSContentType.HANDSHAKE)
        return crypto_container.encrypt()

    def get_encrypted_application_msg(self, msg = ''):
        '''Needed with tunneled TLS'''
        if not msg:
            msg = 'test data'
        return to_raw(TLSPlaintext(data = 'GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n'), self.tls_ctx)

    def _eapTlsCertReq(self):
        log.info('Receiving server certificates')
        while self.server_hello_done_received == False:
            r = self.eapol_scapy_recv(cb = self.eapol_server_hello_cb,
                                      lfilter =
                                      lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and \
                                          pkt[EAP].code == EAP.REQUEST)
            if len(r) == 0:
                self.tlsFail()
                return r
        log.info('Sending client certificate request')
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)
        if self.client_cert:
            der_cert = rex_pem.findall(self.client_cert)[0].decode("base64")
            client_certificate_list = TLSHandshake()/TLSCertificateList(
                certificates=[TLSCertificate(data=x509.X509Cert(der_cert))])
        else:
            client_certificate_list = TLSHandshake()/TLSCertificateList(certificates=[])
        client_certificate = TLSRecord(version="TLS_1_0")/client_certificate_list
	kex_data = self.tls_ctx.get_client_kex_data()
        client_key_ex_data = TLSHandshake()/kex_data
        client_key_ex = TLSRecord()/client_key_ex_data
        if self.client_cert:
            self.load_tls_record(str(client_certificate))
            self.pkt_history.append(str(client_certificate_list))
        self.load_tls_record(str(client_key_ex))
        self.pkt_history.append(str(client_key_ex_data))
        verify_signature = self.get_verify_signature(self.client_priv_key)
	if self.invalid_cert_req_handshake:
	    log.info("sending 'certificate-request' type of handshake message instead of 'certificate-verify' type")
	    client_cert_verify = TLSHandshake(type=TLSHandshakeType.CERTIFICATE_REQUEST)/verify_signature
	else:
            client_cert_verify = TLSHandshake(type=TLSHandshakeType.CERTIFICATE_VERIFY)/verify_signature
	if self.incorrect_tlsrecord_type_cert_req:
	    log.info("sending TLS Record type as ALERT instead of HANDSHAKE in certificate request packet")
            client_cert_record = TLSRecord(content_type=TLSContentType.ALERT)/client_cert_verify
	else:
	    client_cert_record = TLSRecord(content_type=TLSContentType.HANDSHAKE)/client_cert_verify
        self.pkt_history.append(str(client_cert_verify))
        #log.info('TLS ctxt: %s' %self.tls_ctx)
        client_ccs = TLSRecord(version="TLS_1_0")/TLSChangeCipherSpec()
        enc_handshake_msg = self.get_encrypted_handshake_msg()
	if self.invalid_content_type:
            handshake_msg = str(TLSRecord(content_type=self.invalid_content_type)/enc_handshake_msg)
	else:
	    handshake_msg = str(TLSRecord(content_type=TLSContentType.HANDSHAKE)/enc_handshake_msg)
        reqdata = str(TLS.from_records([client_certificate, client_key_ex, client_cert_record, client_ccs]))
        reqdata += handshake_msg
        log.info("------> Sending Client Hello TLS Certificate payload of len %d ----------->" %len(reqdata))
	if self.dont_send_client_certificate:
	    log.info('\nskipping sending client certificate part')
	    pass
	else:
            status = self.eapFragmentSend(EAP_RESPONSE, self.server_hello_done_eap_id, TLS_LENGTH_INCLUDED,
                                      payload = reqdata, fragsize = 1024)
            assert_equal(status, True)
            self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CHANGE_CIPHER_SPEC

    def _eapTlsCertReq_delay(self):
        self.server_hello_done_received = True
        log.info('Sending client certificate request')
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)

        if self.client_cert:
           der_cert = rex_pem.findall(self.client_cert)[0].decode("base64")
           client_certificate_list = TLSHandshake()/TLSCertificateList(
                                                    certificates=[TLSCertificate(data=x509.X509Cert(der_cert))])
        else:
           client_certificate_list = TLSHandshake()/TLSCertificateList(certificates=[])

        client_certificate = TLSRecord(version="TLS_1_0")/client_certificate_list
	kex_data = self.tls_ctx.get_client_kex_data()
        client_key_ex_data = TLSHandshake()/kex_data
        client_key_ex = TLSRecord()/client_key_ex_data

        if self.client_cert:
           self.load_tls_record(str(client_certificate))
           self.pkt_history.append(str(client_certificate_list))

        self.load_tls_record(str(client_key_ex))
        self.pkt_history.append(str(client_key_ex_data))
        verify_signature = self.get_verify_signature(self.client_priv_key)

	if self.invalid_cert_req_handshake:
	   log.info("Sending 'certificate-request' type of handshake message instead of 'certificate-verify' type")
	   client_cert_verify = TLSHandshake(type=TLSHandshakeType.CERTIFICATE_REQUEST)/verify_signature
	else:
           client_cert_verify = TLSHandshake(type=TLSHandshakeType.CERTIFICATE_VERIFY)/verify_signature

	if self.incorrect_tlsrecord_type_cert_req:
	   log.info("Sending TLS Record type as ALERT instead of HANDSHAKE in certificate request packet")
           client_cert_record = TLSRecord(content_type=TLSContentType.ALERT)/client_cert_verify
	else:
	   client_cert_record = TLSRecord(content_type=TLSContentType.HANDSHAKE)/client_cert_verify

        self.pkt_history.append(str(client_cert_verify))
        #log.info('TLS ctxt: %s' %self.tls_ctx)
        client_ccs = TLSRecord(version="TLS_1_0")/TLSChangeCipherSpec()
        enc_handshake_msg = self.get_encrypted_handshake_msg()

	if self.invalid_content_type:
            handshake_msg = str(TLSRecord(content_type=self.invalid_content_type)/enc_handshake_msg)
	else:
	    handshake_msg = str(TLSRecord(content_type=TLSContentType.HANDSHAKE)/enc_handshake_msg)
        reqdata = str(TLS.from_records([client_certificate, client_key_ex, client_cert_record, client_ccs]))
        reqdata += handshake_msg
        log.info("------> Sending Client Hello TLS Certificate payload of len %d ----------->" %len(reqdata))

	if self.dont_send_client_certificate:
	   log.info('\nSkipping sending client certificate part')
	   pass
	else:
           status = self.eapFragmentSend(EAP_RESPONSE, self.server_hello_done_eap_id, TLS_LENGTH_INCLUDED,
                                      payload = reqdata, fragsize = 1024)
           assert_equal(status, True)
           self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_CHANGE_CIPHER_SPEC

    def _eapTlsChangeCipherSpec(self):
        def eapol_cb(pkt):
            r = str(pkt)
	    log.info('data received in change cipher spec function is %s'%pkt.show())
            tls_data = r[self.TLS_OFFSET:]
            log.info('Verifying TLS Change Cipher spec record type %x' %ord(tls_data[0]))
            assert tls_data[0] == self.CHANGE_CIPHER
            log.info('Handshake finished. Sending empty data')
            eap_payload = self.eapTLS(EAP_RESPONSE, pkt[EAP].id, 0, '')
            self.eapol_send(EAPOL_EAPPACKET, eap_payload)

        r = self.eapol_scapy_recv(cb = eapol_cb,
                                  lfilter =
                                  lambda pkt: EAP in pkt and pkt[EAP].type == EAP_TYPE_TLS and pkt[EAP].code == EAP.REQUEST)
        if len(r) > 0:
            self.nextEvent = self.tlsEventTable.EVT_EAP_TLS_FINISHED
        else:
            self.tlsFail()
            return r

    def _eapTlsFinished(self):
        self.nextEvent = None
        def eapol_cb(pkt):
            log.info('Server authentication successfull')

        timeout = 5
        if self.failTest is True:
            if self.fail_cb is not None:
                self.fail_cb()
                return
            timeout = None ##Wait forever on failure and force testcase timeouts

        self.eapol_scapy_recv(cb = eapol_cb,
                              lfilter =
                              lambda pkt: EAP in pkt and pkt[EAP].code == EAP.SUCCESS,
                              timeout = timeout)
        self.eapol_logoff()
