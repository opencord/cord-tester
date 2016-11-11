***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS IGMPSNOOPING Functionality 1
  [Documentation]  Send IGMP join to ONOS and verify data traffic
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_verify_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 2
  [Documentation]  Verify igmp data traffic after sending leave packet
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_leave_verify_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 3
  [Documentation]  Send IGMP join and leave packets in a loop
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_leave_join_loop
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 4
  [Documentation]  Verify latency to send one igmp join packet to ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_1group_join_latency
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 5
  [Documentation]  Verify latency to send two igmp join packets to ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_2group_join_latency
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 6
  [Documentation]  Verify latency to send multiple igmp join packets to ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_Ngroup_join_latency
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 7
  [Documentation]  Send IGMP join to ONOS and verify data traffic
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_rover_all
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 8
  [Documentation]  Send IGMP join to ONOS and verify data traffic
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_rover
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 9
  [Documentation]  Verify igmp query packet from ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 10
  [Documentation]  Send 2 IGMP joins and 1 leave to ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_2joins_1leave
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 11
  [Documentation]  Send 2 IGMP joins 1 leave and again send 1 join after leave
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_2joins_1leave_and_join_again
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 12
  [Documentation]  Send IGMP join to ONOS and verify data traffic from source not in source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_not_in_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 13
  [Documentation]  Verify igmp change to exclude record type of ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_change_to_exclude_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 14
  [Documentation]  Verify igmp include to allow new sources record type of  ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_to_allow_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 15
  [Documentation]  Verify igmp include to block old sources record type of  ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_to_block_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 16
  [Documentation]  Verify igmp change to include  record type of ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_change_to_include_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 17
  [Documentation]  Verify igmp exclude to allow new sources record type of  ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_to_allow_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 18
  [Documentation]  Verify igmp exclude to block old sources record type of  ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_to_block_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 19
  [Documentation]  Send IGMP join and send data traffic with new source IPs
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_new_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 20
  [Documentation]  Verify igmp block old source list record type of ONOS IGMPSNOOPING Application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_block_old_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 21
  [Documentation]  Send IGMP join with empty source list and send data traffic
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_empty_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 22
  [Documentation]  Send IGMP join with exclude empty source list and send data traffic
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_empty_src_list
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 23
  [Documentation]  Send IGMP join to ONOS with 0.0.0.0 source IP
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_sourceip_0_0_0_0
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 24
  [Documentation]  Send IGMP join to ONOS with invalid fields in join
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_invalid_join_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 25
  [Documentation]  Send IGMP join to ONOS and verify data traffic while subscriber link toggles
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_data_received_during_subscriber_link_toggle
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 26
  [Documentation]  Send IGMP join to ONOS and verify data traffic while channel distributors link toggles
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_data_received_during_channel_distributors_link_toggle
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 27
  [Documentation]  Send IGMP join to ONOS with invalid class D ip for join
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_invalid_class_d_ip_for_join_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 28
  [Documentation]  Send IGMP join to ONOS with class D invalid IP in source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_invalid_class_d_ip_as_srclist_ip_for_join_packet
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 29
  [Documentation]  Verify igmp data traffic received on interface general query sent
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_general_query_received_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 30
  [Documentation]  Verify igmp query received on join packet sending interface
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_query_received_on_joining_interface
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 31
  [Documentation]  Verify periodic queries received on igmp join sending interface
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_for_periodic_query_received_on_joining_interface
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 32
  [Documentation]  Verify periodic queries received on join sent interface and the entry deleted in ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_for_periodic_query_received_and_checking_entry_deleted
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 33
  [Documentation]  Verify igmp query interval and  expiry for group in ONOS
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_member_query_interval_and_expiry_for_rejoining_interface
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 34
  [Documentation]  Verify for igmp group specific query received on leave packet sent interface
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_leave_received_group_and_source_specific_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING for Functionality 35
  [Documentation]  Verify igmp group sepcific query on change to exclude source list mode
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_change_to_exclude_src_list_and_check_for_group_source_specific_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 36
  [Documentation]  Verify for igmp general when record type change to chnage to include source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_change_to_include_src_list_and_check_for_general_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 37
  [Documentation]  Verify for igmp general query when record type changed to allow new sources
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_allow_new_src_list_and_check_for_general_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 38
  [Documentation]  Verify for igmp group specific query when record type changed to block old source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_block_old_src_list_and_check_for_group_source_specific_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 39
  [Documentation]  Verify for igmp general query when record type changed to include to allow new source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_to_allow_src_list_and_check_for_general_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 40
  [Documentation]  Verify for igmp group specific query when record type changed to include to block old source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_to_block_src_list_and_check_for_group_source_specific_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 41
  [Documentation]  Verify for igmp general query when record type changed to exclude to allow new source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_to_allow_src_list_and_check_for_general_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 42
  [Documentation]  Verify for igmp group specific query when record type changed to exclude to block old source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_to_block_src_list_and_check_for_group_source_specific_query
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 43
  [Documentation] Verify igmp include and exclude modes
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_exclude_modes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 44
  [Documentation]  Verify igmp allow new source list record type
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_allow_new_source_mode
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 45
  [Documentation]  Verify changing igmp include to exclude record type
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_include_to_exclude_mode_change
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 46
  [Documentation]  Verify changing igmp exclude to include record  type
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_exclude_to_include_mode_change
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 47
  [Documentation]  Verify igmp To_Include mode with null source list
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_to_include_mode_with_null_source
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 48
  [Documentation]  Verify igmp To_Include mode record type
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_to_include_mode
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 49
  [Documentation]  Verify igmp block old source list record type
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_blocking_old_source_mode
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 50
  [Documentation]  Verify igmp join and data for 100 groups
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_multiple_joins_and_data_verification_with_100_groups
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 51
  [Documentation]  Verify igmp join data followed by leave for 100 groups
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_multiple_joins_with_data_verification_and_leaving_100_groups
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 52
  [Documentation]  Load ONOS ssmTranslate table with 1000 igmp group-source pair
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_group_source_for_only_config_with_1000_entries
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 53
  [Documentation]  Verify igmp exclude to include mode change for 100 groups
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_from_exclude_to_include_mode_with_100_groups
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 54
  [Documentation]  Verify igmp join and data for 1000 groups
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_with_multiple_joins_and_data_verify_with_1000_groups
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 55
  [Documentation]  Verify igmp join and data for 5000  groups
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_with_multiple_joins_and_data_verify_with_5000_groups
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 56
  [Documentation]  Verify sending data traffic to non-registered igmp group
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_send_data_to_non_registered_group
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 57
  [Documentation]  Verify igmp data traffic  to a registed in ONOS group but join not sent to the group
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_traffic_verification_for_registered_group_with_no_join_sent
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 58
  [Documentation]  Send IGMP functionality with app deactivate and re-activate
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_toggling_app_activation
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 59
  [Documentation]  Verify igmp data traffic with dest MAC and dest IP mismatch
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_with_mismatch_for_dst_ip_and_mac_in_data_packets
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 60
  [Documentation]  Verify igmp join to ONOS with invalid group address
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_registering_invalid_group
  Should Be Equal As Integers  ${rc}  0

Verify ONOS IGMPSNOOPING Functionality 61
  [Documentation]  Verify igmp join to ONOS with invalis source address
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_registering_invalid_source
  Should Be Equal As Integers  ${rc}  0

