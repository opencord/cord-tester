*** Settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***
Verify Onos DHCP Server Functionality
  [Documentation]  Make a DHCP request to ONOS to get an IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_1request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Server Functionality 1
  [Documentation]  Make a DHCP release to ONOS to release the dhcp IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_1release
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Server Functionality 2
  [Documentation]  Make a DHCP request to ONOS to get desired dhcp IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_desired_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 1
  [Documentation]  Send a Mac flow request to ONOS to verify flow traffic
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 2
  [Documentation]  Send a TCP flow request to ONOS to verify tcp flow traffic
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_tcp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 3
  [Documentation]  Send a Ipv6 flow request to ONOS to verify Icmpv6 Echo request flow traffic
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_EchoRequest
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Relay Functionality 1
  [Documentation]  Make a DHCP request to a relay server through ONOS to get an IP
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_1request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Relay Functionality 2
  [Documentation]  Make a DHCP request to a relay server through ONOS to get an IP
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_starvation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Relay Functionality 3
  [Documentation]  Make a DHCP request to a relay server through ONOS to get an IP with specifif lease time requested
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_specific_lease_packet_in_dhcp_discover
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Relay Functionality 4
  [Documentation]  Make a DHCP request to a relay server through ONOS to get an IP from out of pool
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_desired_address_out_of_pool
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Functionality 1
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Functionality 2
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application with invalid certificates
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_invalid_cert
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Functionality 3
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application without sending client hello packet
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_without_sending_client_hello
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Functionality 4
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application with disabling and re-enabling the app
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_with_aaa_app_deactivation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS AAA Functionality 5
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application with cleintkeyex replace with serverkeyex
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls_clientkeyex_replace_with_serverkeyex
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMP Functionality 1
  [Documentation]  Make a IGMP join leave request through ONOS IGMP snooping application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_verify_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMP Functionality 2
  [Documentation]  Test for igmp query packet from ONOS igmpsnooping application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMP Functionality 3
  [Documentation]  Test for igmp allow new source record type functionilty of ONOS igmpsnooping application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_allow_new_source_mode
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMP Functionality 4
  [Documentation]  Test for ONOS igmpsnooping functionality with app disable and re-enable
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_toggling_app_activation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMP Functionality 5
  [Documentation]  Test for ONOS igmpsnooping functionality by sending igmp data traffic without sending join
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_traffic_verification_for_registered_group_with_no_join_sent
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORDd SUBSCRIBER Functionality 1
  [Documentation]  Simulate Channel Surfing experience
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD SUBSCRIBER Functionality 2
  [Documentation]  Simulate Cord subscriber join channel change
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD SUBSCRIBER Functionality 3
  [Documentation]  Simulate Cord Subscriber Channel surfing for authentication with dhcp client rebind
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_client_rebind_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD SUBSCRIBER Functionality 4
  [Documentation]  Simulate Cord Subscriber Authentication with and without certificates and channel surfing
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_2_cord_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Functionality 1
  [Documentation]  Start Quagga container, connect it to ONOS before validating ONOS routing works
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_5_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Functionality 2
  [Documentation]  Start Quagga container, connect it to ONOS before validating ONOS routing works
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_6_routes_3_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Functionality 3
  [Documentation]  To verify vrouter functionality with dynamic addition or deletion of routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_deleting_and_adding_routes_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Functionality 4
  [Documentation]  To verify vrouter functionality for classB duplicate route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classB_duplicate_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS PROXY-ARP Functionality 1
  [Documentation]  Create a host in different subnet and arp to the host IP to test ONOS proxy-arp app
  ${rc}=  Run Cord Tester  proxyarp:proxyarp_exchange.test_proxyarp_with_1_host
  Should Be Equal As Integers  ${rc}  0

Verify ONOS PROXY-ARP Functionality 2
  [Documentation]  Test ONOS proxyarp app with disable and re-enable the app
  ${rc}=  Run Cord Tester  proxyarp:proxyarp_exchange.test_proxyarp_app_with_disabling_and_re_enabling
  Should Be Equal As Integers  ${rc}  0

Verify ONOS PROXY-ARP Functionality 3
  [Documentation]  Test ONOS proxyarp functionality with multiple hosts
  ${rc}=  Run Cord Tester  proxyarp:proxyarp_exchange.test_proxyarp_concurrent_requests_with_multiple_host_and_different_interfaces
  Should Be Equal As Integers  ${rc}  0

