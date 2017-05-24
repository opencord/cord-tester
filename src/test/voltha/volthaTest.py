import os
import sys
import unittest
from nose.tools import *
from CordTestConfig import setup_module
from CordTestUtils import log_test
from VolthaCtrl import VolthaCtrl

class voltha_exchange(unittest.TestCase):

    OLT_TYPE = 'tibit_olt'
    OLT_MAC = '00:0c:e2:31:12:00'
    VOLTHA_HOST = 'localhost'
    VOLTHA_REST_PORT = 8881
    voltha = None

    @classmethod
    def setUpClass(cls):
        cls.voltha = VolthaCtrl(cls.VOLTHA_HOST, rest_port = cls.VOLTHA_REST_PORT)

    def test_olt_enable(self):
        log_test.info('Enabling OLT type %s, MAC %s' %(self.OLT_TYPE, self.OLT_MAC))
        status = self.voltha.enable_device(self.OLT_TYPE, self.OLT_MAC)
        assert_equal(status, True)

    def test_subscriber_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  auth request packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber is authenticated successfully.
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_failure(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls without cert auth packet is being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_using_invalid_cert(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets and exchange invalid cert from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls with invalid cert auth packet is being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_with_aaa_app_deactivation(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls without sending client hello, it's not being exchanged between client, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_radius_server(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls with restart of radius server and packets are being exchanged between subscriber, onos and freeradius.
        5. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_with_disabled_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable olt which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_disabling_uni_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable uni port which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_olt(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart olt which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """

    def test_subscriber_with_voltha_for_eap_tls_authentication_restarting_onu(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Restart onu which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        """

    def test_two_subscribers_with_voltha_for_eap_tls_authentication(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between two subscriber, onos and freeradius.
        5. Verify that two subscribers are authenticated successfully.
        """

    def test_two_subscribers_with_voltha_for_eap_tls_authentication_using_same_certificates(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that two valid certificates are being exchanged between two subscriber, onos and freeradius.
        5. Verify that two subscribers are not authenticated.
        """

    def test_two_subscribers_with_voltha_for_eap_tls_authentication_initiating_invalid_tls_packets_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between valid subscriber, onos and freeradius.
        5. Validate that eap tls valid auth packets are being exchanged between invalid client, onos and freeradius.
        6. Verify that valid subscriber authenticated successfully.
        7. Verify that invalid subscriber are not authenticated successfully.
        """

    def test_two_subscribers_with_voltha_for_eap_tls_authentication_initiating_invalid_cert_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT is detected and ONU ports(nni and 2 uni's) are being seen.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        4. Validate that eap tls valid auth packets are being exchanged between valid subscriber, onos and freeradius.
        5. Validate that eap tls invalid cert auth packets are being exchanged between invalid subscriber, onos and freeradius.
        6. Verify that valid subscriber authenticated successfully.
        7. Verify that invalid subscriber are not authenticated successfully.
        """

    def test_two_subscribers_with_voltha_for_eap_tls_authentication_with_one_uni_port_disabled(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Bring up freeradius server container using CORD TESTER and make sure that ONOS have connectivity to freeradius server.
        3. Bring up two Residential subscribers from cord-tester and issue tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        5. Validate that eap tls packets are being exchanged between two subscriber, onos and freeradius.
        6. Verify that subscriber authenticated successfully.
        7. Disable one of the uni port which is seen in voltha and issue tls auth packets from subscriber.
        8. Validate that eap tls packets are not being exchanged between one subscriber, onos and freeradius.
        9. Verify that subscriber authentication is unsuccessful..
        10. Verify that other subscriber authenticated successfully.
        """

    def test_subscriber_with_voltha_for_dhcp_request(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        """

    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_broadcast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac broadcast from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_multicast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac multicast from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcp_request_with_invalid_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac zero from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcp_request_and_release(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp release from residential subscrber to dhcp server which is running as onos app.
        6  Verify that subscriber should not get ip from dhcp server, ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcp_starvation_positive_scenario(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times.
        6  Verify that subscriber should get ip from dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcp_starvation_negative_scenario(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber without of pool ip to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip from dhcp server.
        5. Repeat steps 3 and 4 for 10 times.
        6  Verify that subscriber should not get ip from dhcp server.
        """
    def test_subscriber_with_voltha_for_dhcp_sending_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Repeat step 3 for 50 times.
        6  Verify that subscriber should get same ip which was received from 1st discover from dhcp server.
        """
    def test_subscriber_with_voltha_for_dhcp_sending_multiple_request(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send DHCP request to dhcp server which is running as onos app.
        6. Repeat step 5 for 50 times.
        7. Verify that subscriber should get same ip which was received from 1st discover from dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcp_requesting_desired_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired ip address from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip which was requested in step 3 from dhcp server successfully.
        """

    def test_subscriber_with_voltha_for_dhcp_requesting_desired_out_pool_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired out of pool ip address from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber should not get ip which was requested in step 3 from dhcp server, and its offered only within dhcp pool of ip.
        """
    def test_subscriber_with_voltha_for_dhcp_deactivate_dhcp_app_in_onos(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Deactivate dhcp server app in onos.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
    def test_subscriber_with_voltha_for_dhcp_renew_time(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp renew packet to dhcp server which is running as onos app.
        6. Repeat step 4.
        """
    def test_subscriber_with_voltha_for_dhcp_rebind_time(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Send dhcp rebind packet to dhcp server which is running as onos app.
        6. Repeat step 4.
        """
    def test_subscriber_with_voltha_for_dhcp_disable_olt_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
    def test_subscriber_with_voltha_for_dhcp_disable_enable_olt_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable olt devices which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """
    def test_subscriber_with_voltha_for_dhcp_disable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        """
    def test_subscriber_with_voltha_for_dhcp_disable_enable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscriber get ip from dhcp server successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from dhcp server, and ping to gateway.
        8. Enable onu port which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

    def test_two_subscriber_with_voltha_for_dhcp_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips from dhcp server successfully.
        """

    def test_two_subscriber_with_voltha_for_dhcp_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times for both subscribers.
        6  Verify that subscribers should get same ips which are offered the first time from dhcp server.
        """
    def test_two_subscriber_with_voltha_for_dhcp_multiple_discover_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Repeat step 3 and 4 for 10 times for only one subscriber and ping to gateway from other subscriber.
        6  Verify that subscriber should get same ip which is offered the first time from dhcp server and other subscriber ping to gateway should not failed
        """
    def test_two_subscriber_with_voltha_for_dhcp_discover_desired_ip_address_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from one residential subscriber to dhcp server which is running as onos app.
        3. Send dhcp request with desired ip from other residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips (one subscriber desired ip and other subscriber random ip) from dhcp server successfully.
        """
    def test_two_subscriber_with_voltha_for_dhcp_discover_within_and_wothout_dhcp_pool_ip_addresses(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired wihtin dhcp pool ip from one residential subscriber to dhcp server which is running as onos app.
        3. Send dhcp request with desired without in dhcp pool ip from other residential subscriber to dhcp server which is running as onos app.
        4. Verify that subscribers had got different ips (both subscriber got random ips within dhcp pool) from dhcp server successfully.
        """
    def test_two_subscriber_with_voltha_for_dhcp_disable_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should not failed.
        """
    def test_two_subscriber_with_voltha_for_dhcp_disable_enable_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should not failed.
        8. Enable onu port on which was disable at step 5 and ping to gateway from other subscriber.
        9. Repeat step 3 and 4 for one subscriber where uni port is up now.
        10. Verify that subscriber should get ip from dhcp server and other subscriber ping to gateway should not failed.
        """
    def test_two_subscriber_with_voltha_for_dhcp_disable_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        """
    def test_two_subscriber_with_voltha_for_dhcp_disable_enable_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        8. Enable the olt device which is detected in voltha.
        9. Verify that subscriber should get ip from dhcp server and other subscriber ping to gateway should not failed.
        """
    def test_two_subscriber_with_voltha_for_dhcp_pause_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to dhcp server which is running as onos app.
        4. Verify that subscribers had got ip from dhcp server successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Pause the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from dhcp server and other subscriber ping to gateway should failed.
        """
    def test_subscriber_with_voltha_for_dhcpRelay_dhcp_request(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server successfully.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_dhcp_request_with_invalid_broadcast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac broadcast from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_dhcp_request_with_invalid_multicast_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are is up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac multicast from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_dhcp_request_with_invalid_source_mac(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with invalid source mac zero from residential subscrber to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_dhcp_request_and_release(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscrber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server successfully.
        5. Send dhcp release from residential subscrber to external dhcp server.
        6  Verify that subscriber should not get ip from external dhcp server, ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_starvation(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times.
        6  Verify that subscriber should get ip from external dhcp server..
        """

    def test_subscriber_with_voltha_for_dhcpRelay_starvation_negative_scenario(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber without of pool ip to external dhcp server.
        4. Verify that subscriber should not get ip from external dhcp server..
        5. Repeat steps 3 and 4 for 10 times.
        6  Verify that subscriber should not get ip from external dhcp server..
        """
    def test_subscriber_with_voltha_for_dhcpRelay_sending_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Repeat step 3 for 50 times.
        6  Verify that subscriber should get same ip which was received from 1st discover from external dhcp server..
        """
    def test_subscriber_with_voltha_for_dhcpRelay_sending_multiple_request(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send DHCP request to external dhcp server.
        6. Repeat step 5 for 50 times.
        7. Verify that subscriber should get same ip which was received from 1st discover from external dhcp server..
        """

    def test_subscriber_with_voltha_for_dhcpRelay_requesting_desired_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired ip address from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip which was requested in step 3 from external dhcp server. successfully.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_requesting_desired_out_of_pool_ip_address(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired out of pool ip address from residential subscriber to external dhcp server.
        4. Verify that subscriber should not get ip which was requested in step 3 from external dhcp server., and its offered only within dhcp pool of ip.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_deactivating_dhcpRelay_app_in_onos(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Deactivate dhcp server app in onos.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_renew_time(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send dhcp renew packet to external dhcp server.
        6. Repeat step 4.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_rebind_time(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Send dhcp rebind packet to external dhcp server.
        6. Repeat step 4.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_disable_olt_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_toggling_olt_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable olt devices which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        8. Enable olt devices which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_disable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        """

    def test_subscriber_with_voltha_for_dhcpRelay_disable_enable_onu_port_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from residential subscriber to external dhcp server.
        4. Verify that subscriber get ip from external dhcp server. successfully.
        5. Disable onu port which is being detected in voltha CLI.
        6. Repeat step 3.
        7. Verify that subscriber should not get ip from external dhcp server., and ping to gateway.
        8. Enable onu port which is being detected in voltha CLI.
        9. Repeat steps 3 and 4.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got different ips from external dhcp server. successfully.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_multiple_discover(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times for both subscribers.
        6  Verify that subscribers should get same ips which are offered the first time from external dhcp server..
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_multiple_discover_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Repeat step 3 and 4 for 10 times for only one subscriber and ping to gateway from other subscriber.
        6  Verify that subscriber should get same ip which is offered the first time from external dhcp server. and other subscriber ping to gateway should not failed
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_discover_desired_ip_address_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from one residential subscriber to external dhcp server.
        3. Send dhcp request with desired ip from other residential subscriber to external dhcp server.
        4. Verify that subscribers had got different ips (one subscriber desired ip and other subscriber random ip) from external dhcp server. successfully.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_discover_in_range_and_out_of_range_from_dhcp_pool_ip_addresses(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request with desired wihtin dhcp pool ip from one residential subscriber to external dhcp server.
        3. Send dhcp request with desired without in dhcp pool ip from other residential subscriber to external dhcp server.
        4. Verify that subscribers had got different ips (both subscriber got random ips within dhcp pool) from external dhcp server. successfully.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_disable_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_toggle_onu_port_for_one_subscriber(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Disable onu port on which access one subscriber and ping to gateway from other subscriber.
        6. Repeat step 3 and 4 for one subscriber where uni port is down.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        8. Enable onu port on which was disable at step 5 and ping to gateway from other subscriber.
        9. Repeat step 3 and 4 for one subscriber where uni port is up now.
        10. Verify that subscriber should get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_disable_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_toggle_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Disable the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        8. Enable the olt device which is detected in voltha.
        9. Verify that subscriber should get ip from external dhcp server. and other subscriber ping to gateway should not failed.
        """

    def test_two_subscriber_with_voltha_for_dhcpRelay_pause_olt_detected_in_voltha(self):
        """
        Test Method:
        0. Make sure that voltha and external dhcp server are up and running on CORD-POD setup.
        1. OLT and ONU is detected and validated.
        2. Issue  tls auth packets from CORD TESTER voltha test module acting as a subscriber..
        3. Send dhcp request from two residential subscribers to external dhcp server.
        4. Verify that subscribers had got ip from external dhcp server. successfully.
        5. Start pinging continuously from one subscriber and repeat steps 3 and 4 for other subscriber.
        6. Pause the olt device which is detected in voltha.
        7. Verify that subscriber should not get ip from external dhcp server. and other subscriber ping to gateway should failed.
        """
