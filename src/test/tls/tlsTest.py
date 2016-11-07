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
from CordLogger import CordLogger
from scapy.all import *
from scapy_ssl_tls.ssl_tls import *
from scapy_ssl_tls.ssl_tls_crypto import *
log.setLevel('INFO')

class eap_auth_exchange(CordLogger):

    app = 'org.opencord.aaa'
    TLS_TIMEOUT = 20
    TEST_TIMEOUT = 3600
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

    invalid_cipher_suites = ['TLS_RSA_WITH_NULL_SHA256',
                             'TLS_RSA_WITH_AES_128_CBC_SHA',
                             'TLS_RSA_WITH_AES_128_CBC_SHA256',
                             'TLS_RSA_WITH_AES_256_CBC_SHA256',
                             'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
                             'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
                             'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
                             'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
                             'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
                             'TLS_DH_anon_WITH_AES_256_CBC_SHA256']

    def setUp(self):
        super(eap_auth_exchange, self).setUp()
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

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_session_id(self):
        df = defer.Deferred()
        def eap_tls_invalid_session_id(df):
            def tls_invalid_session_id_cb():
                log.info('TLS authentication failed with invalid session  id')
            tls = TLSAuthTest(fail_cb = tls_invalid_session_id_cb,session_id = 12345, session_id_length = 1)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_session_id, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_random_gmt_unix_time(self):
        df = defer.Deferred()
        def eap_tls_invalid_gmt_unix_time(df):
            def eap_tls_invalid_gmt_unix_time_cb():
                log.info('TLS authentication failed with invalid gmt_unix_time in Client Hello Packet')
            for i in [0,7265,98758,23627238]:
                log.info("\nExecuting test case with gmt_unix_time value is set to %d"%i)
                tls = TLSAuthTest(fail_cb = eap_tls_invalid_gmt_unix_time_cb, gmt_unix_time = i)
                tls.runTest()
                assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_gmt_unix_time, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_content_type(self,Positive_Test=True):
        df = defer.Deferred()
        def eap_tls_invalid_content_type(df):
            def tls_invalid_content_type_cb():
                log.info('TLS authentication failed with invalid content type in TLSContentType packet')
            tls = TLSAuthTest(fail_cb = tls_invalid_content_type_cb, invalid_content_type = 24)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_content_type, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_record_fragment_length(self):
        df = defer.Deferred()
        def eap_tls_invalid_record_fragment_length(df):
            def eap_tls_invalid_record_fragment_length_cb():
                log.info('TLS authentication failed with invalid fragment length field in TLSRecord packet')
            tls = TLSAuthTest(fail_cb = eap_tls_invalid_record_fragment_length_cb, record_fragment_length = 17384)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_record_fragment_length, df)
        return df

    #invalid id field in identifier response packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_invalid_id_in_identifier_response_packet(self):
        df = defer.Deferred()
        def eap_tls_with_invalid_id_in_identifier_response_packet(df):
            def tls_with_invalid_id_in_identifier_response_packet_cb():
                log.info('TLS authentication failed with invalid id in identifier packet')
            tls = TLSAuthTest(fail_cb = tls_with_invalid_id_in_identifier_response_packet_cb,
                              id_mismatch_in_identifier_response_packet = True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_with_invalid_id_in_identifier_response_packet, df)
        return df

    #invalid id field in client hello packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_invalid_id_in_client_hello_packet(self):
        df = defer.Deferred()
        def eap_tls_with_invalid_id_in_client_hello_packet(df):
            def tls_with_invalid_id_in_client_hello_packet_cb():
                log.info('TLS authentication failed with invalid id in client hello packet')
            tls = TLSAuthTest(fail_cb = tls_with_invalid_id_in_client_hello_packet_cb,
                              id_mismatch_in_client_hello_packet = True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_with_invalid_id_in_client_hello_packet, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_without_sending_client_hello(self):
        df = defer.Deferred()
        def eap_tls_without_sending_client_hello(df):
            def tls_without_sending_client_hello_cb():
                log.info('TLS authentication failed with not sending client hello')
            tls = TLSAuthTest(fail_cb = tls_without_sending_client_hello_cb,
                              dont_send_client_hello = True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_without_sending_client_hello, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_aaa_app_deactivate(self):
        df = defer.Deferred()
        def eap_tls_aaa_app_deactivate(df):
            def tls_aaa_app_deactivate_cb():
                log.info('TLS authentication failed with aaa app deactivated in ONOS')
            tls = TLSAuthTest(fail_cb = tls_aaa_app_deactivate_cb)
            self.onos_ctrl.deactivate()
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_aaa_app_deactivate, df)
        return df

    #keeping cipher suite length as zero but including cipher suite key which is more than zero length in client hello packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_incorrect_cipher_suite_length_field(self):
        df = defer.Deferred()
        def eap_tls_incorrect_cipher_suite_length_field(df):
            def tls_incorrect_cipher_suite_length_field_cb():
                log.info('TLS authentication failed with incorrect cipher suite length field in client hello packet')
            tls = TLSAuthTest(fail_cb = tls_incorrect_cipher_suite_length_field_cb, cipher_suites_length = 0)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_incorrect_cipher_suite_length_field, df)
        return df

    #keeping compression methods length to zero but sending compression method of more than 0 zero length in client hello packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_incorrect_compression_methods_length_field(self):
        df = defer.Deferred()
        def eap_tls_incorrect_compression_methods_length_field(df):
            def tls_incorrect_compression_methods_length_field_cb():
                log.info('TLS authentication failed with incorrect compression methods length field in client hello packet')
            tls = TLSAuthTest(fail_cb = tls_incorrect_compression_methods_length_field_cb, compression_methods_length=1,compression_methods=TLSCompressionMethod.LZS)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_incorrect_compression_methods_length_field, df)
        return df

    #checking with broadcast source mac of EAPOL packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_source_mac_broadcast(self):
        df = defer.Deferred()
        def eap_tls_invalid_source_mac_broadcast(df):
            def tls_invalid_source_mac_broadcast_cb():
                log.info('TLS authentication failed with invalid source mac as broadcast in EAPOL packet')
            tls = TLSAuthTest(fail_cb = tls_invalid_source_mac_broadcast_cb, src_mac='bcast')
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_source_mac_broadcast, df)
        return df

    #checking with multicast source mac of EAPOL packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_source_mac_multicast(self):
        df = defer.Deferred()
        def eap_tls_invalid_source_mac_multicast(df):
            def tls_invalid_source_mac_multicast_cb():
                log.info('TLS authentication failed with invalid source mac as multicast in EAPOL packet')
            tls = TLSAuthTest(fail_cb = tls_invalid_source_mac_multicast_cb, src_mac='mcast')
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_source_mac_multicast, df)
        return df

    #checking with zero source mac of EAPOL packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_source_mac_zero(self):
        df = defer.Deferred()
        def eap_tls_invalid_source_mac_zero(df):
            def tls_invalid_source_mac_zero_cb():
                log.info('TLS authentication failed with invalid source mac as zero in EAPOL packet')
            tls = TLSAuthTest(fail_cb = tls_invalid_source_mac_zero_cb, src_mac='zeros')
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_source_mac_zero, df)
        return df

    #Restarting Radius server after sending client hello
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_restart_radius_server(self):
        df = defer.Deferred()
        def eap_tls_restart_radius_server(df):
            def tls_restart_radius_server_cb():
                log.info('TLS authentication failed with  radius server down in middle of authentication process')
            tls = TLSAuthTest(fail_cb = tls_restart_radius_server_cb, restart_radius=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_restart_radius_server, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_incorrect_handshake_type_client_hello(self):
        df = defer.Deferred()
        def eap_tls_incorrect_handshake_type_client_hello(df):
            def tls_incorrect_handshake_type_client_hello_cb():
                log.info('TLS authentication failed with incorrect handshake type in client hello packet')
            tls = TLSAuthTest(fail_cb = tls_incorrect_handshake_type_client_hello_cb, invalid_client_hello_handshake_type=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_incorrect_handshake_type_client_hello, df)
        return df

    #Sending certificate request type of handhsake instead of  certificate verify in client certificate request message
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_incorrect_handshake_type_certificate_request(self):
        df = defer.Deferred()
        def eap_tls_incorrect_handshake_type_certificate_request(df):
            def tls_incorrect_handshake_type_certificate_request_cb():
                log.info('TLS authentication failed with incorrect handshake type in client certificate request packet')
            tls = TLSAuthTest(fail_cb = tls_incorrect_handshake_type_certificate_request_cb, invalid_cert_req_handshake=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_incorrect_handshake_type_certificate_request, df)
        return df

    #Sending tls record content type as 'ALERT' instead of 'HANDSHAKE' in certificate request packet
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_with_incorrect_tlsrecord_certificate_request(self):
        df = defer.Deferred()
        def eap_tls_incorrect_tlsrecord_certificate_request(df):
            def tls_incorrect_tlsrecord_certificate_request_cb():
                log.info('TLS authentication failed with incorrect tlsrecord type  in certificate request packet')
            tls = TLSAuthTest(fail_cb = tls_incorrect_tlsrecord_certificate_request_cb, incorrect_tlsrecord_type_cert_req=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_incorrect_tlsrecord_certificate_request, df)
        return df

    #Sending client hello with zero lenght field in Handshake protocol
    @deferred(TLS_TIMEOUT)
    def test_eap_tls_invalid_handshake_length_client_hello(self):
        df = defer.Deferred()
        def eap_tls_invalid_handshake_length_client_hello(df):
            def tls_invalid_handshake_length_client_hello_cb():
                log.info('TLS authentication failed with invalid handshake length in client hello packet')
            tls = TLSAuthTest(fail_cb = tls_invalid_handshake_length_client_hello_cb, invalid_client_hello_handshake_length=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_invalid_handshake_length_client_hello, df)
        return df

    @deferred(TLS_TIMEOUT)
    def test_eap_tls_clientkeyex_replace_with_serverkeyex(self):
        df = defer.Deferred()
        def eap_tls_clientkeyex_replace_with_serverkeyex(df):
            def tls_clientkeyex_replace_with_serverkeyex_cb():
                log.info('TLS authentication failed with client key exchange replaced with server key exchange')
            tls = TLSAuthTest(fail_cb = tls_clientkeyex_replace_with_serverkeyex_cb,clientkeyex_replace_with_serverkeyex=True)
            tls.runTest()
            assert_equal(tls.failTest, True)
            df.callback(0)
        reactor.callLater(0, eap_tls_clientkeyex_replace_with_serverkeyex, df)
        return df

    #simulating authentication for multiple users, 1K in this test case
    @deferred(TEST_TIMEOUT)
    def test_eap_tls_1k_with_diff_mac(self):
        df = defer.Deferred()
        def eap_tls_1k_with_diff_mac(df):
            for i in xrange(1000):
                tls = TLSAuthTest(src_mac = 'random')
                tls.runTest()
		log.info('Authentication successfull for user %d'%i)
            df.callback(0)
        reactor.callLater(0, eap_tls_1k_with_diff_mac, df)
        return df

    #simulating authentication for multiple users, 5K in this test case
    @deferred(TEST_TIMEOUT)
    def test_eap_tls_5k_with_diff_mac(self):
        df = defer.Deferred()
        def eap_tls_5k_with_diff_mac(df):
            for i in xrange(5000):
                tls = TLSAuthTest(src_mac = 'random')
                tls.runTest()
                log.info('Authentication successfull for user %d'%i)
            df.callback(0)
        reactor.callLater(0, eap_tls_5k_with_diff_mac, df)
        return df

if __name__ == '__main__':
    t = TLSAuthTest()
    t.runTest()
