***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS DHCPRelay Functionality 1
  [Documentation]  Test ONOS DHCPRelay Application for one client
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_1request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 2
  [Documentation]  Test ONOS DHCPRelay Application for multiple clients
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_Nrequest
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 3
  [Documentation]  Test ONOS DHCPRelay Application for dhcp release for one client
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_1release
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 4
  [Documentation]  Test ONOS DHCPRelay Application for dhcp release for multiple clients
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_Nrelease
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 5
  [Documentation]  Test ONOS DHCPRelay Application for dhcp starvation
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_starvation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 6
  [Documentation]  Test ONOS DHCPRelay Application same client sends multiple discovers
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_same_client_multiple_discover
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 7
  [Documentation]  Test ONOS DHCPRelay Application same client sends multiple dhcp requests
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_same_client_multiple_request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 8
  [Documentation]  Test ONOS DHCPRelay Application client requests for desired IP
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_desired_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 9
  [Documentation]  Test ONOS DHCPRelay Application client request for desired IP from out of pool
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_desired_address_out_of_pool
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 10
  [Documentation]  Test ONOS DHCPRelay Application for dhcp nak packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_nak_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 11
  [Documentation]  Test ONOS DHCPRelay Application client requests IP for specific lease time
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_specific_lease_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 12
  [Documentation]  Test ONOS DHCPRelay Application clients sends dhcp requests after reboot
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_request_after_reboot
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 13
  [Documentation]  Test ONOS DHCPRelay Application when dhcp server reboots
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_after_reboot
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 14
  [Documentation]  Test ONOS DHCPRelay Application for specific lease in client discover packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_specific_lease_packet_in_dhcp_discover
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 15
  [Documentation]  Test ONOS DHCPRelay Application for default lease time in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_default_lease_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 16
  [Documentation]  Test ONOS DHCPRelay Application for client renew time in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_renew_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 17
  [Documentation]  Test ONOS DHCPRelay Application for clients rebind time in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_rebind_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 18
  [Documentation]  Test ONOS DHCPRelay Application for subnet mask in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_expected_subnet_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 19
  [Documentation]  Test ONOS DHCPRelay Application clients sends requests with wrong subnet mask
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_sends_dhcp_request_with_wrong_subnet_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 20
  [Documentation]  Test ONOS DHCPRelay Application for router address in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_expected_router_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 21
  [Documentation]  Test ONOS DHCPRelay Application when  client sends dhcp requests with wrong router address
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_sends_dhcp_request_with_wrong_router_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 22
  [Documentation]  Test ONOS DHCPRelay Application for broadcast address in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_expected_broadcast_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 23
  [Documentation]  Test ONOS DHCPRelay Application when client sends requests to  wrong broadcast address
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_sends_dhcp_request_with_wrong_broadcast_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 22
  [Documentation]  Test ONOS DHCPRelay Application for DNS IP received in server offered packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_expected_dns_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 23
  [Documentation]  Test ONOS DHCPRelay Application when client sends dhcp requests with wrongs dns IP
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_sends_request_with_wrong_dns_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 24
  [Documentation]  Test ONOS DHCPRelay Application to calculate transactions per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_transactions_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 25
  [Documentation]  Test ONOS DHCPRelay Application to calculate consecutive successes per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_consecutive_successes_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 26
  [Documentation]  Test ONOS DHCPRelay Application for number of clients per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_clients_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 27
  [Documentation]  Test ONOS DHCPRelay Application to clculate number of consecutive successive clients per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_consecutive_successful_clients_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 28
  [Documentation]  Test ONOS DHCPRelay Application to calculate concurrent transactions per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_concurrent_transactions_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 29
  [Documentation]  Test ONOS DHCPRelay Application to calculate concurrent consecutive successes per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_concurrent_consecutive_successes_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 30
  [Documentation]  Test ONOS DHCPRelay Application to calculate clients per second
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_concurrent_clients_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 31
  [Documentation]  Test ONOS DHCPRelay Application for dhcp inform packet
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_inform_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCPRelay Functionality 32
  [Documentation]  Test ONOS DHCPRelay Application when clients conflict happens
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_client_conflict
  Should Be Equal As Integers  ${rc}  0

