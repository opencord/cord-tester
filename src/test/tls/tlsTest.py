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
