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
####  Authentication parameters
from scapy.all import *
from socket import *
from struct import *
import sys
from nose.tools import assert_equal, assert_not_equal, assert_raises, assert_true

USER = "raduser"
PASS = "radpass"
WRONG_USER = "XXXX"
WRONG_PASS = "XXXX"
NO_USER = ""
NO_PASS = ""
DEV = "tap0"
ETHERTYPE_PAE = 0x888e
PAE_GROUP_ADDR = "\xff\xff\xff\xff\xff\xff"
EAPOL_VERSION = 1
EAPOL_EAPPACKET = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_KEY = 3
EAPOL_ASF = 4
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4
EAP_TYPE_ID = 1
EAP_TYPE_MD5 = 4
EAP_TYPE_MSCHAP = 26
EAP_TYPE_TLS = 13
cCertMsg = '\x0b\x00\x00\x03\x00\x00\x00'
TLS_LENGTH_INCLUDED = 0x80

class EapolPacket(object):
    
    def __init__(self, intf = 'veth0'):
        self.intf = intf
        self.s = None
        self.max_payload_size = 1600

    def setup(self):
        self.s = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
        self.s.bind((self.intf, ETHERTYPE_PAE))
        self.mymac = self.s.getsockname()[4]
        self.llheader = Ether(dst = PAE_GROUP_ADDR, src = self.mymac, type = ETHERTYPE_PAE)
        self.recv_sock = L2Socket(iface = self.intf, type = ETHERTYPE_PAE)

    def cleanup(self):
        if self.s is not None:
            self.s.close()
            self.s = None
            
    def eapol(self, req_type, payload=""):
        return EAPOL(version = EAPOL_VERSION, type = req_type)/payload

    def eap(self, code, pkt_id, req_type=0, data=""):
        return EAP(code = code, id = pkt_id, type = req_type)/data

    def eapTLS(self, code, pkt_id, flags = TLS_LENGTH_INCLUDED, data=""):
        req_type = EAP_TYPE_TLS
        if code in [EAP_SUCCESS, EAP_FAILURE]:
            return pack("!BBH", code, pkt_id, 4)
        else:
            if flags & TLS_LENGTH_INCLUDED:
                flags_dlen = pack("!BL", flags, len(data))
                return pack("!BBHB", code, pkt_id, 5+len(flags_dlen)+len(data), req_type) + flags_dlen + data
            flags_str = pack("!B", flags)
            return pack("!BBHB", code, pkt_id, 5+len(flags_str)+len(data), req_type) + flags_str + data

    def eapol_send(self, eapol_type, eap_payload):
        return sendp(self.llheader/self.eapol(eapol_type, eap_payload), iface=self.intf)

    def eapol_recv(self):
        p = self.s.recv(self.max_payload_size)[14:]
        vers,pkt_type,eapollen  = unpack("!BBH",p[:4])
        print "Version %d, type %d, len %d" %(vers, pkt_type, eapollen)
        assert_equal(pkt_type, EAPOL_EAPPACKET)
        return p[4:]

    def eapol_scapy_recv(self, cb = None, lfilter = None, count = 1):
        def eapol_default_cb(pkt): pass
        if cb is None:
            cb = eapol_default_cb
        sniff(prn = cb, lfilter = lfilter, count = count, opened_socket = self.recv_sock)

    def eapol_start(self):
        eap_payload = self.eap(EAPOL_START, 2)
        return self.eapol_send(EAPOL_START, eap_payload)

    def eapol_id_req(self, pkt_id = 0, user = USER):
        eap_payload = self.eap(EAP_RESPONSE, pkt_id, EAP_TYPE_ID, user)
        return self.eapol_send(EAPOL_EAPPACKET, eap_payload)

    def eap_md5_challenge_recv(self,rad_pwd):
        PASS = rad_pwd
        print 'Inside EAP MD5 Challenge Exchange'
        p = self.s.recv(self.max_payload_size)[14:]
        vers,pkt_type,eapollen  = unpack("!BBH",p[:4])
        print "EAPOL Version %d, type %d, len %d" %(vers, pkt_type, eapollen)
        code, pkt_id, eaplen = unpack("!BBH", p[4:8])
        print "EAP Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[8:9])[0]
        reqdata = p[9:4+eaplen]
        print 'Request type is %d' %(reqtype)
        assert_equal(reqtype, EAP_TYPE_MD5)
        challenge=pack("!B",pkt_id)+PASS+reqdata[1:]
        print "Generating md5 challenge for %s" % challenge
        return (challenge,pkt_id)

    def eap_Status(self):
        print 'Inside EAP Status'
        p = self.s.recv(self.max_payload_size)[14:]
        code, id, eaplen = unpack("!BBH", p[4:8])
        return code

