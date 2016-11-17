***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS DHCP Functionality 1
  [Documentation]  Test ONOS DHCP Application for one client
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_1request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 2
  [Documentation]  Test ONOS DHCP Application for multiple clients
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_Nrequest
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 3
  [Documentation]  Test ONOS DHCP Application for dhcp release for one client
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_1release
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 4
  [Documentation]  Test ONOS DHCP Application for dhcp release for multiple clients
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_Nrelease
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 5
  [Documentation]  Test ONOS DHCP Application for dhcp starvation
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_starvation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 6
  [Documentation]  Test ONOS DHCP Application same client sends multiple discovers
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_same_client_multiple_discover
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 7
  [Documentation]  Test ONOS DHCP Application same client sends multiple dhcp requests
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_same_client_multiple_request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 8
  [Documentation]  Test ONOS DHCP Application client requests for desired IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_desired_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 9
  [Documentation]  Test ONOS DHCP Application client request for desired IP from out of pool
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_desired_address_out_of_pool
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 10
  [Documentation]  Test ONOS DHCP Application for dhcp nak packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_nak_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 11
  [Documentation]  Test ONOS DHCP Application client requests IP for specific lease time
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_lease_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 12
  [Documentation]  Test ONOS DHCP Application clients sends dhcp requests after reboot
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_request_after_reboot
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 13
  [Documentation]  Test ONOS DHCP Application when dhcp server reboots
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_after_reboot
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 14
  [Documentation]  Test ONOS DHCP Application for specific lease in client discover packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_specific_lease_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 15
  [Documentation]  Test ONOS DHCP Application for default lease time in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_lease_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 16
  [Documentation]  Test ONOS DHCP Application for client renew time in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_renew_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 17
  [Documentation]  Test ONOS DHCP Application for clients rebind time in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_rebind_time
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 18
  [Documentation]  Test ONOS DHCP Application for subnet mask in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_expected_subnet_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 19
  [Documentation]  Test ONOS DHCP Application clients sends requests with wrong subnet mask
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_sends_dhcp_request_with_wrong_subnet_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 20
  [Documentation]  Test ONOS DHCP Application for router address in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_expected_router_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 21
  [Documentation]  Test ONOS DHCP Application when  client sends dhcp requests with wrong router address
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_sends_dhcp_request_with_wrong_router_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 22
  [Documentation]  Test ONOS DHCP Application for broadcast address in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_expected_broadcast_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 23
  [Documentation]  Test ONOS DHCP Application when client sends requests to  wrong broadcast address
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_sends_dhcp_request_with_wrong_broadcast_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 24
  [Documentation]  Test ONOS DHCP Application for DNS IP received in server offered packet
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_expected_dns_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 25
  [Documentation]  Test ONOS DHCP Application when client sends dhcp requests with wrongs dns IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_client_sends_request_with_wrong_dns_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 26
  [Documentation]  Test ONOS DHCP Application to calculate transactions per second
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_transactions_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 27
  [Documentation]  Test ONOS DHCP Application to calculate consecutive successes per second
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_consecutive_successes_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 28
  [Documentation]  Test ONOS DHCP Application for number of clients per second
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_client_transactions_per_second
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Functionality 29
  [Documentation]  Test ONOS DHCP Application to clculate number of consecutive successive clients per second
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_server_consecutive_successful_clients_per_second
  Should Be Equal As Integers  ${rc}  0
