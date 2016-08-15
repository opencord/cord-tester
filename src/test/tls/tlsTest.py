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
import unittest
import time
import os
from nose.tools import *
from nose.twistedtools import reactor, deferred
from twisted.internet import defer
from EapTLS import TLSAuthTest
from OnosCtrl import OnosCtrl
from scapy.all import *
log.setLevel('INFO')

class eap_auth_exchange(unittest.TestCase):

    app = 'org.opencord.aaa'
    TLS_TIMEOUT = 20
    CLIENT_CERT_INVALID = '''-----BEGIN CERTIFICATE-----
MIIEyTCCA7GgAwIBAgIJAM6l2jUG56pLMA0GCSqGSIb3DQEBCwUAMIGLMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UE
ChMKQ2llbmEgSW5jLjEeMBwGCSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYw
JAYDVQQDEx1FeGFtcGxlIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xNjAzMTEx
ODUzMzVaFw0xNzAzMDYxODUzMzVaMIGLMQswCQYDVQQGEwJVUzELMAkGA1UECBMC
Q0ExEjAQBgNVBAcTCVNvbWV3aGVyZTETMBEGA1UEChMKQ2llbmEgSW5jLjEeMBwG
CSqGSIb3DQEJARYPYWRtaW5AY2llbmEuY29tMSYwJAYDVQQDEx1FeGFtcGxlIENl
cnRpZmljYXRlIEF1dGhvcml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAL9Jv54TkqycL3U2Fdd/y5NXdnPVXwAVV3m6I3eIffVCv8eS+mwlbl9dnbjo
qqlGEgA3sEg5HtnKoW81l3PSyV/YaqzUzbcpDlgWlbNkFQ3nVxh61gSU34Fc4h/W
plSvCkwGSbV5udLtEe6S9IflP2Fu/eXa9vmUtoPqDk66p9U/nWVf2H1GJy7XanWg
wke+HpQvbzoSfPJS0e5Rm9KErrzaIkJpqt7soW+OjVJitUax7h45RYY1HHHlbMQ0
ndWW8UDsCxFQO6d7nsijCzY69Y8HarH4mbVtqhg3KJevxD9UMRy6gdtPMDZLah1c
LHRu14ucOK4aF8oICOgtcD06auUCAwEAAaOCASwwggEoMB0GA1UdDgQWBBQwEs0m
c8HARTVp21wtiwgav5biqjCBwAYDVR0jBIG4MIG1gBQwEs0mc8HARTVp21wtiwga
v5biqqGBkaSBjjCBizELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRIwEAYDVQQH
EwlTb21ld2hlcmUxEzARBgNVBAoTCkNpZW5hIEluYy4xHjAcBgkqhkiG9w0BCQEW
D2FkbWluQGNpZW5hLmNvbTEmMCQGA1UEAxMdRXhhbXBsZSBDZXJ0aWZpY2F0ZSBB
dXRob3JpdHmCCQDOpdo1BueqSzAMBgNVHRMEBTADAQH/MDYGA1UdHwQvMC0wK6Ap
oCeGJWh0dHA6Ly93d3cuZXhhbXBsZS5jb20vZXhhbXBsZV9jYS5jcmwwDQYJKoZI
hvcNAQELBQADggEBAK+fyAFO8CbH35P5mOX+5wf7+AeC+5pwaFcoCV0zlfwniANp
jISgcIX9rcetLxeYRAO5com3+qLdd9dGVNL0kwufH4QhlSPErG7OLHHAs4JWVhUo
bH3lK9lgFVlnCDBtQhslzqScR64SCicWcQEjv3ZMZsJwYLvl8unSaKz4+LVPeJ2L
opCpmZw/V/S2NhBbe3QjTiRPmDev2gbaO4GCfi/6sCDU7UO3o8KryrkeeMIiFIej
gfwn9fovmpeqCEyupy2JNNUTJibEuFknwx7JAX+htPL27nEgwV1FYtwI3qLiZqkM
729wo9cFSslJNZBu+GsBP5LszQSuvNTDWytV+qY=
-----END CERTIFICATE-----'''

    def setUp(self):
        self.onos_ctrl = OnosCtrl(self.app)
        self.onos_aaa_config()

    def onos_aaa_config(self):
        aaa_dict = {'apps' : { 'org.onosproject.aaa' : { 'AAA' : { 'radiusSecret': 'radius_password',
                                                                   'radiusIp': '172.17.0.2' } } } }
        radius_ip = os.getenv('ONOS_AAA_IP') or '172.17.0.2'
        aaa_dict['apps']['org.onosproject.aaa']['AAA']['radiusIp'] = radius_ip
        self.onos_ctrl.activate()
        time.sleep(2)
        self.onos_load_config(aaa_dict)

    def onos_load_config(self, config):
        status, code = OnosCtrl.config(config)
        if status is False:
            log.info('Configure request for AAA returned status %d' %code)
            assert_equal(status, True)
            time.sleep(3)

    @deferred(TLS_TIMEOUT)
    def test_eap_tls(self):
        df = defer.Deferred()
        def eap_tls_verify(df):
            tls = TLSAuthTest()
            tls.runTest()
            df.callback(0)
        reactor.callLater(0, eap_tls_verify, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_no_cert(self):
        df = defer.Deferred()
        def eap_tls_no_cert(df):
            def tls_no_cert_cb():
                log.info('TLS authentication failed with no certificate')

            tls = TLSAuthTest(fail_cb = tls_no_cert_cb, client_cert = '')
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_no_cert, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_invalid_cert(self):
        df = defer.Deferred()
        def eap_tls_invalid_cert(df):
            def tls_invalid_cert_cb():
                log.info('TLS authentication failed with invalid certificate')

            tls = TLSAuthTest(fail_cb = tls_invalid_cert_cb,
                              client_cert = self.CLIENT_CERT_INVALID)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_cert, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_Nusers_with_same_valid_cert(self):
        df = defer.Deferred()
        def eap_tls_Nusers_with_same_valid_cert(df):
            num_users = 3
            for i in xrange(num_users):
                tls = TLSAuthTest(intf = 'veth{}'.format(i*2))
                tls.runTest()
            df.callback(0)
        reactor.callLater(0, eap_tls_Nusers_with_same_valid_cert, df)
        return df

if __name__ == '__main__':
    t = TLSAuthTest()
    t.runTest()
