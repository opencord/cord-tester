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
        code, pkt_id, eaplen = unpack("!BBH", p[0:4])
        print "Code %d, id %d, len %d" %(code, pkt_id, eaplen)
        assert_equal(code, EAP_REQUEST)
        reqtype = unpack("!B", p[4:5])[0]
        assert_equal(reqtype, EAP_TYPE_TLS)
        rex_pem = re.compile(r'\-+BEGIN[^\-]+\-+(.*?)\-+END[^\-]+\-+', re.DOTALL)
        self.pem_cert="""-----BEGIN CERTIFICATE-----
MIIE4TCCA8mgAwIBAgIJANhJTS6x4B0iMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD
VQQGEwJGUjEPMA0GA1UECBMGUmFkaXVzMRIwEAYDVQQHEwlTb21ld2hlcmUxFTAT
BgNVBAoTDEV4YW1wbGUgSW5jLjEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBs
ZS5jb20xJjAkBgNVBAMTHUV4YW1wbGUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4X
DTE0MDUyMDExNTkzNloXDTE0MDcxOTExNTkzNlowgZMxCzAJBgNVBAYTAkZSMQ8w
DQYDVQQIEwZSYWRpdXMxEjAQBgNVBAcTCVNvbWV3aGVyZTEVMBMGA1UEChMMRXhh
bXBsZSBJbmMuMSAwHgYJKoZIhvcNAQkBFhFhZG1pbkBleGFtcGxlLmNvbTEmMCQG
A1UEAxMdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC/KUyltP0BS5A/sYg/XJOZMSHDIUiW+D8s1JgJ
9Q/FIAnlMpevjPQtlmWi+hpgOUGgTryV+rTlzcUNw/gjmMs1Z4bAakFIc2vCPybw
5hgKMU2E9SMgLr1aMVzwN3BH/njt1eWQ5Q9ajyu3JzmXZwOg/tV03L7BYpjLajhT
iln4pvO/nq9YHVGurE5qCwyyrleYmtEXPi8MxrgudaKShrr7KgXbhlSwEaGGapSD
JFhKvyQ4UZ56qiDFXD/AIXE9o8Soouv+8ufsCOyf/xKp1QkUaZ17Fe6YHqvQYdNM
ovwnXnX+vRW0cZVui7ufxHncb9sJSAlovxzDy/GeL0SHtdH9AgMBAAGjggE0MIIB
MDAdBgNVHQ4EFgQUHjtJ/Mjl+dcwmT5UI37N74qh2YUwgcgGA1UdIwSBwDCBvYAU
HjtJ/Mjl+dcwmT5UI37N74qh2YWhgZmkgZYwgZMxCzAJBgNVBAYTAkZSMQ8wDQYD
VQQIEwZSYWRpdXMxEjAQBgNVBAcTCVNvbWV3aGVyZTEVMBMGA1UEChMMRXhhbXBs
ZSBJbmMuMSAwHgYJKoZIhvcNAQkBFhFhZG1pbkBleGFtcGxlLmNvbTEmMCQGA1UE
AxMdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBBdXRob3JpdHmCCQDYSU0useAdIjAMBgNV
HRMEBTADAQH/MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5j
b20vZXhhbXBsZV9jYS5jcmwwDQYJKoZIhvcNAQELBQADggEBAEbkq17kbT7X/oiy
E2DOV7g1W8Au+TQR0GKzjXPgmYVGixN8l/9dQZ9WVDmCetBy71UHgTxPp20My2zr
uA7hy9FYNGtZ2jmu0p019fH+CSCL7RHHgKsY63UsldT1qPYiWiyqbWy5GvJX778N
GxVo7oN33se1c4KEmMOLVqQqX5dDWjN2r27l0GFh1ssx4RHqOc57G5Txq861i6UT
KlrN0xpyu7LjcQGMwKbfzCXfwys5i4rrAVX1spILTIihUKpD6FYxp6oj+d4ELZOh
br3zfhKrkbvPCG0gEziBLnwd11ZJELQfm89IYBhmoOYkk5+ZOszDsXKGWzfV6XSW
ZRv+LU0=
-----END CERTIFICATE-----"""
        self.der_cert = rex_pem.findall(self.pem_cert)[0].decode("base64")
        self.pem_priv_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA84TzkjbcskbKZnrlKcXzSSgi07n+4N7kOM7uIhzpkTuU0HIv
h4VZS2axxfV6hV3CD9MuKVg2zEhroqK1Js5n4ke230nSP/qiELfCl0R+hzRtbfKL
tFUr1iHeU0uQ6v3q+Tg1K/Tmmg72uxKrhyHDL7z0BriPjhAHJ5XlQsvR1RCMkqzu
D9wjSInJxpMMIgLndOclAKv4D1wQtYU7ZpTw+01XBlUhIiXb86qpYL9NqnnRq5JI
uhmOEuxo2ca63+xaHNhD/udSyc8C0Md/yX6wlONTRFgLLv0pdLUGm1xEjfsydaQ6
qGd7hzIKUI3hohNKJa/mHLElv7SZolPTogK/EQIDAQABAoIBAADq9FwNtuE5IRQn
zGtO4q7Y5uCzZ8GDNYr9RKp+P2cbuWDbvVAecYq2NV9QoIiWJOAYZKklOvekIju3
r0UZLA0PRiIrTg6NrESx3JrjWDK8QNlUO7CPTZ39/K+FrmMkV9lem9yxjJjyC34D
AQB+YRTx+l14HppjdxNwHjAVQpIx/uO2F5xAMuk32+3K+pq9CZUtrofe1q4Agj9R
5s8mSy9pbRo9kW9wl5xdEotz1LivFOEiqPUJTUq5J5PeMKao3vdK726XI4Z455Nm
W2/MA0YV0ug2FYinHcZdvKM6dimH8GLfa3X8xKRfzjGjTiMSwsdjgMa4awY3tEHH
674jhAECgYEA/zqMrc0zsbNk83sjgaYIug5kzEpN4ic020rSZsmQxSCerJTgNhmg
utKSCt0Re09Jt3LqG48msahX8ycqDsHNvlEGPQSbMu9IYeO3Wr3fAm75GEtFWePY
BhM73I7gkRt4s8bUiUepMG/wY45c5tRF23xi8foReHFFe9MDzh8fJFECgYEA9EFX
4qAik1pOJGNei9BMwmx0I0gfVEIgu0tzeVqT45vcxbxr7RkTEaDoAG6PlbWP6D9a
WQNLp4gsgRM90ZXOJ4up5DsAWDluvaF4/omabMA+MJJ5kGZ0gCj5rbZbKqUws7x8
bp+6iBfUPJUbcqNqFmi/08Yt7vrDnMnyMw2A/sECgYEAiiuRMxnuzVm34hQcsbhH
6ymVqf7j0PW2qK0F4H1ocT9qhzWFd+RB3kHWrCjnqODQoI6GbGr/4JepHUpre1ex
4UEN5oSS3G0ru0rC3U4C59dZ5KwDHFm7ffZ1pr52ljfQDUsrjjIMRtuiwNK2OoRa
WSsqiaL+SDzSB+nBmpnAizECgYBdt/y6rerWUx4MhDwwtTnel7JwHyo2MDFS6/5g
n8qC2Lj6/fMDRE22w+CA2esp7EJNQJGv+b27iFpbJEDh+/Lf5YzIT4MwVskQ5bYB
JFcmRxUVmf4e09D7o705U/DjCgMH09iCsbLmqQ38ONIRSHZaJtMDtNTHD1yi+jF+
OT43gQKBgQC/2OHZoko6iRlNOAQ/tMVFNq7fL81GivoQ9F1U0Qr+DH3ZfaH8eIkX
xT0ToMPJUzWAn8pZv0snA0um6SIgvkCuxO84OkANCVbttzXImIsL7pFzfcwV/ERK
UM6j0ZuSMFOCr/lGPAoOQU0fskidGEHi1/kW+suSr28TqsyYZpwBDQ==
-----END RSA PRIVATE KEY-----
        """
        self.der_priv_key = rex_pem.findall(self.pem_priv_key)[0].decode("base64")
        reqdata = TLSRecord(version="TLS_1_0")/TLSHandshake()/TLSCertificateList(
            certificates=[TLSCertificate(data=x509.X509Cert(self.der_cert))])
        #reqdata.show()
        print "------> Sending Client Hello TLS Certificate payload of len %d ----------->" %len(reqdata)
        eap_payload = self.eapTLS(EAP_RESPONSE, pkt_id, TLS_LENGTH_INCLUDED, str(reqdata))
        self.eapol_send(EAPOL_EAPPACKET, eap_payload)
        self.nextEvent = None
