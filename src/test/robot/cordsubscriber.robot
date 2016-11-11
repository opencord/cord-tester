***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS CORD Subscriber Functionality 1
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 2
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 3
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 4
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for invalid certificate
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_invalid_certificate_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 5
  [Documentation]  Test ONOS CORD Subscriber authentication functionalitywith no cerfiticates
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_no_certificate_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 6
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for self signed certificates
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_self_signed_certificate_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 7
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and invalid certificates
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_2_cord_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 8
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and no certificates
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_2_cord_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 9
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and non ca authorized certificates
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_2_cord_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 10
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp discover
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_discover_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 11
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client reboots
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_client_reboot_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 12
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp server reboots
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_server_reboot_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 13
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client rebinds
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_client_rebind_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 14
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp starvation
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_starvation_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 15
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for multiple dhcp discovers from same subscriber
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_multiple_dhcp_discover_for_same_subscriber_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 16
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for multiple dhcp requests from same subscriber
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_multiple_dhcp_request_for_same_subscriber_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 17
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client requested specific IP
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_client_requested_ip_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 18
  [Documentation]  Test ONOS CORD Subscriber functionality for dhcp non offered IP
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_non_offered_ip_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 19
  [Documentation]  Test ONOS CORD Subscriber functionality for dhcp client requests out of pool IP
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 20
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client requests specific lease time
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_authentication_with_dhcp_specified_lease_time_functionality_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 21
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and invalid certificates for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 22
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and no certificates for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 23
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and non-ca authorized certificates for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 24
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and invalid certificates for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 25
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and no certificates for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 26
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and non-ca authorized certificates for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 27
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and invalid certificates for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 28
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and no certificates for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 29
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for valid and non-ca authorized certificates for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 30
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client discover  for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_discovers_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 31
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client reboot for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_client_reboot_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 32
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp server reboots for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_server_reboot_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 33
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client rebiind for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_client_rebind_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 34
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp starvation for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_starvation_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 35
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp client requests specific IP for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_client_requested_ip_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 36
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp non offered IP for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_non_offered_ip_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 37
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive for 4 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_4_cord_subscribers_join_recv_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 38
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump for 4 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_4_cord_subscribers_join_jump_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 39
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next for 4 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_4_cord_subscribers_join_next_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 40 
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive for 10 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10_cord_subscribers_join_recv_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 41
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump for 10 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10_cord_subscribers_join_jump_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 42
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next for 10 subscribers 5 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10_cord_subscribers_join_next_5channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 43
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 100 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv_100channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 44
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 400 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv_400channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 45
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 800 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv_800channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 46
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1200 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv_1200channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 47
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1500 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_recv_1500channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 48
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 100 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump_100channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 49
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 400 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump_400channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 50
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 800 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump_800channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 51
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1200 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 52
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1500 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump_1500channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 53
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 100 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next_100channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 54
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 400 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next_400channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 55
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 800 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next_800channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 56
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1200 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next_1200channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 57
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1500 channels
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_next_1500channels
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 58
  [Documentation]  Test ONOS CORD Subscriber authentication functionality for dhcp clients requests out of pool IP for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 59
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 100 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_recv_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 60
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 100 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_jump_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 61
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 100 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_next_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 62
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 400 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_recv_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 63
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 400 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_jump_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 64
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 400 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_next_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 65
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 800 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_recv_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 66
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 800 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_jump_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 67
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 800 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_next_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 68
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1200 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_recv_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 69
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1200 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_jump_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 70
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1200 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_next_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 71
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1500 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_recv_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 72
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1500 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_jump_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 73
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1500 channels for 1k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_1k_cord_subscribers_join_next_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 74
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 100 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_recv_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 75
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 100 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_jump_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 76
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 100 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_next_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 77
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 400 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_recv_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 78
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 400 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_jump_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 79
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 400 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_next_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 80
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 800 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_recv_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 81
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 800 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_jump_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 82
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 800 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_next_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 83
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1200 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_recv_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 84
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1200 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_jump_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 85
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1200 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_next_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 86
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1500 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_recv_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 87
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1500 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_jump_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 88
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1500 channels for 5k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_5k_cord_subscribers_join_next_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 89
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 100 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_recv_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 90
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 100 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_jump_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 91
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 100 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_next_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 92
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 100 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_recv_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 93
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 100 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_jump_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 94
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 100 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_next_100channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 95
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 400 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_recv_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 96
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 400 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_jump_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 97
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 400 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_next_400channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 98
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 800 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_recv_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 100
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 800 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_jump_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 101
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 800 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_next_800channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 102
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1200 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_recv_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 103
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1200 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_jump_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 104
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1200 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_next_1200channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 105
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1500 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_recv_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 106
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1500 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_jump_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 107
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1500 channels for 10k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_10k_cord_subscribers_join_next_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 108
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join receive 1500 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_recv_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 109
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join jump 1500 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_jump_1500channel
  Should Be Equal As Integers  ${rc}  0

Verify ONOS CORD Subscriber Functionality 110
  [Documentation]  Test ONOS CORD Subscriber functionality for igmp join next 1500 channels for 100k subscribers
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_100k_cord_subscribers_join_next_1500channel
  Should Be Equal As Integers  ${rc}  0

