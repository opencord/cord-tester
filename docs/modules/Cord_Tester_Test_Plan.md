**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Test Cases (Implemented and Planned) : **

**Test Plan CORD TESTER Implemented Features**

** **

** **

** **

** **

**Table of Contents**

** **

** **

** ****IGMP**

 **AUTHENTICATION **

** DHCP **

** DHCPRelay**

** SUBSCRIBER**

** VROUTER**

** ACL **

** Proxy-Arp**

** Flows**

 **Cluster**

** XOS**

** Cbench**

** iPerf**

** Cord-Subscriber**

** netCondition**

** Mininet**

**IGMP**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>IGMP_1</td>
    <td>Verify the traffic flow after joining </td>
    <td>test_igmp_join_verify_traffic</td>
    <td>1. Send a IGMP join message to a particular group from an interface
2. Check for traffic flow </td>
    <td>Traffic should get received on that interface</td>
    <td>
Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_2</td>
    <td>Verify the traffic after leaving from the group</td>
    <td>test_igmp_leave_verify_traffic</td>
    <td>1. Leave a group from an interface.
2. Check for traffic flow</td>
    <td>Traffic should not get received on that interface</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_3</td>
    <td>Verify joining loop</td>
    <td>test_igmp_leave_join_loop</td>
    <td>Send a join message to the groups in the same subnet</td>
    <td>Joining interface should receive traffic</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_4</td>
    <td>Check for latency with 1  group</td>
    <td>test_igmp_1group_join_latency</td>
    <td>1. Send a join message to one group from intf1.
2. Send multicast data from intf2.
3. Check for the latency of the data which is sent from intf2 to intf1</td>
    <td>Latency should be checked when the data is being received on intf1</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_5</td>
    <td>Check for latency with 2 groups</td>
    <td>test_igmp_2group_join_latency</td>
    <td>1. Send a join message to 2 groups from 2  different interfaces
2. Send multicast data to 2 groups.
3. Check for the latency of the data</td>
    <td>Latency should be checked when the data is being received on 2 different interfaces</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_6</td>
    <td>Check for latency with N groups</td>
    <td>test_igmp_Ngroup_join_latency</td>
    <td>1. Send a join message to N groups from N different interfaces
2. Send multicast data to N groups.
3. Check for the latency of the data</td>
    <td>Latency should be checked when the data is being received on N different interfaces</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_7</td>
    <td>Verify IGMP query packet</td>
    <td>test_igmp_query</td>
    <td>1. Send a Leave message to the group 224.0.0.1.
2. Check for IGMP query message from the router.</td>
    <td>ONOS should send the IGMP Query message to 224.0.0.1</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_8</td>
    <td>Verify leaving group2 when group1 is still alive</td>
    <td>test_igmp_2joins_1leave_functionality</td>
    <td>1. Send a join message to  group1 and check  the traffic.
2. Send a leave message to group2  and check the traffic on the interface1</td>
    <td>1. Traffic should get received on an interface.
2. Traffic should  get received without any interruptions.</td>
    <td>Pass
 </td>
  </tr>
  <tr>
    <td>IGMP_9</td>
    <td>Verify rejoining to the same group</td>
    <td>test_igmp_2joins_1leave_again_joins_functionality</td>
    <td>1. Send a join message to 2 groups.
2. Send a leave message to group2 and join back again</td>
    <td>Traffic should get received on interface.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_10</td>
    <td>Verify joining a group with source ip as 0.0.0.0</td>
    <td>test_igmp_join_sourceip_0_0_0_0_functionality</td>
    <td>1. Send a join message to a group with source ip as 0.0.0.0
2. Check the traffic on the interface.</td>
    <td>Traffic should not get received.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_11</td>
    <td>Verify the traffic when invalid join message is being sent</td>
    <td> test_igmp_invalidClassD_IP_join_packet_functionality</td>
    <td>Send an invalid join message to a group. Eg class D IP</td>
    <td>Traffic should not get received.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_12</td>
    <td>Verify periodic general query messages</td>
    <td>test_igmp_periodic_query_packet_received_on_joining_interface</td>
    <td>Send a Join packet  to a particular group. </td>
    <td>Joining interface should receive multiple periodic general query packets from ONOS</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_13</td>
    <td>Verify general membership query packet</td>
    <td>test_igmp_query_packet_received_on_joining_interface</td>
    <td>Send a join message and wait for membership query packet</td>
    <td>General membership query packet should be received from querier router after 60sec</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_14</td>
    <td>Verify the traffic after 180sec</td>
    <td>test_igmp_general_query_recv_packet_traffic_functionality</td>
    <td>1. Let onos send query packets.
2. For 180 sec, hosts should not respond.
3. Check for multicast data.</td>
    <td>Multicast data should stop after 180 sec of time.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_15</td>
    <td>Verify the traffic after the interface is made down and then up.</td>
    <td>test_igmp_join_data_receiving_during_subscriber_link_up_down_functionality</td>
    <td>1. Send a join message to the group from the intf1
2. Bring down the intf1.
3. Make the intf1 up again.</td>
    <td>Traffic should get stopped and then resume once the interface is made up.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_16</td>
    <td>Check for "include" source list</td>
    <td>test_igmp_include_to_allow_src_list_functionality</td>
    <td>Send a join message with the include source list as A,B</td>
    <td>Traffic sent from any of the source address should not get filtered</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_17</td>
    <td>Check for “Exclude” source list</td>
    <td>test_igmp_exclude_to_allow_src_list_functionality</td>
    <td>Send a join message with the exclude source list as C</td>
    <td>Traffic sent from any of the source address should get filtered.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_18</td>
    <td>Changing filter to Include mode</td>
    <td>test_igmp_change_to_include_src_list_functionality</td>
    <td>1. Send a join message with Exclude mode.
2. Now change it to Include.</td>
    <td>Traffic sent from any of the source address should now not get filtered</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_19</td>
    <td>Changing filter to Exclude mode</td>
    <td>test_igmp_change_to_exclude_src_list_functionality</td>
    <td>1. Send join message with Include mode.
2. Now change it to Exclude. </td>
    <td>Traffic sent from any of the source address should now get filtered</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_20</td>
    <td>Verify Allowing new sources list</td>
    <td>test_igmp_new_src_list_functionality</td>
    <td>1. Send join message with include mode for A and B.
2. Add a new source list for C.
3. Check the traffic</td>
    <td>Traffic sent from the new source list should now not get filtered.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_21</td>
    <td>Verify Blocking Old sources list</td>
    <td>test_igmp_block_old_src_list_functionality</td>
    <td>1. Send join message with include mode for A and B.
2. Disallow A and B now.</td>
    <td>Traffic sent from the new source list should now be filtered.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_22</td>
    <td>Verify sending multicast data which is not in Join group</td>
    <td>test_igmp_not_in_src_list_functionality</td>
    <td>1. Let the join group has 2.2.2.2 and 3.3.3.3
2. Send a multicast data from 6.6.6.6</td>
    <td>The joining interfaces should not receive the multicast data.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_23</td>
    <td>Verify the traffic when invalid join message is being sent with source list</td>
    <td>test_igmp_invalid_join_packet_functionality</td>
    <td>1. Send a join message with the include source list as A,B
2. Specify the source ip be as 255.255.255.255</td>
    <td>Traffic should not get received.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_24</td>
    <td>Verify general query packet for Include(A) and Allow(B)</td>
    <td>test_igmp_include_to_allow_src_list_check_for_general_query</td>
    <td>1. Send a join message with include mode for A and Allow for B.
2. Check for membership query packet</td>
    <td>General membership query packet should get received from both A and B source list.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_25</td>
    <td>Verify specific query packet for Include(A) and Block(B)</td>
    <td>test_igmp_include_to_block_src_list_check_for_group_source_specific_query</td>
    <td>1. Send a join message with include mode with source list A for G1 and Allow with new source list B for G1.
2. Check for specific query packet</td>
    <td>Source  membership query packet should get received to A*B source list interface</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_26</td>
    <td>Verify general query packet for Exclude(A) and Allow(B)</td>
    <td>test_igmp_exclude_to_allow_src_list_check_for_general_query</td>
    <td>1. Send a join message Exclude mode with source list A for G1 and Allow with new source list B for G1.
2. Check for general membership query packet</td>
    <td>General membership query packet should get received on A*B source list interface</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_27</td>
    <td>Verify query packet for Exclude(A) and Block(B)</td>
    <td>test_igmp_exclude_to_block_src_list_check_for_group_source_specific_query(</td>
    <td>1. Send a join message with  Exclude mode with source list A for G1 and block with new source list B for G1.
2. Check for Specific query packet</td>
    <td>Specific query packet should not get received.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_28</td>
    <td>Verify traffic for INCLUDE (A) and Block(B)</td>
    <td>test_igmp_include_to_block_src_list_functionality</td>
    <td>1. Send a join message with Include mode for A and Block for B.
2. Check for multicast traffic</td>
    <td>Multicast traffic should get received from  A source list.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_29</td>
    <td>Verify joining across multicast range of address </td>
    <td>test_igmp_join_rover</td>
    <td>Keep sending joins across different multicast range of address. </td>
    <td>Joining interface should receive traffic for all the groups.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_30</td>
    <td>Verify empty source list include</td>
    <td>test_igmp_include_empty_src_list_functionality</td>
    <td>Send a join message with include mode with empty source list</td>
    <td>It should be unsuccessful</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_31</td>
    <td>Verify empty source list Exclude</td>
    <td>test_igmp_exclude_empty_src_list_functionality</td>
    <td>Send a join message with Exclude mode with empty source list</td>
    <td>It should be unsuccessful</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_32</td>
    <td>Verify invalid Class D ip join packet with source list</td>
    <td>test_igmp_invalidClassD_IP_as_srclistIP_join_packet_functionality</td>
    <td>1. Send a join message with the include source list as A,B
2. Specify the source ip be as 239.5.5.5</td>
    <td>Traffic shouldn't get received</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_33</td>
    <td>Verify the traffic after the channel is made down and then up.</td>
    <td> test_igmp_join_data_receiving_during_channel_distributor_link_down_up_functionality</td>
    <td>1. Send a join message to the group from the intf1
2. Bring down the channel
4. Make the channel up again.</td>
    <td>Traffic should get stopped and then resume.</td>
    <td>To Be implemented</td>
  </tr>
  <tr>
    <td>IGMP_34</td>
    <td>Verify entry deletion after membership query time expires</td>
    <td>test_igmp_periodic_query_packet_received_and_checking_entry_deleted</td>
    <td>Send IGMP join and wait till 3 membership query packets are received. Check for traffic</td>
    <td>Traffic shouldn't get received.
ONOS should not show the entry for MF table </td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_35</td>
    <td>Verify rejoining interface after membership query interval expires</td>
    <td>test_igmp_member_query_interval_expire_re_joining_interface</td>
    <td>1.Send IGMP join and wait till 3 membership query packets are received.
2. After the timer expires, again rejoin the interface</td>
    <td>Rejoining the interface should happen and traffic flow should be seen.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_36</td>
    <td>Verify source specific query for leave message</td>
    <td>test_igmp_leave_verify_received_group_source_specific_query</td>
    <td>1.Leave a group from an interface.
2.Check for source specific query</td>
    <td>Source specific query should not get received on that interface</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_37</td>
    <td>Verify group specific query packet after changing to exclude mode</td>
    <td>test_igmp_change_to_exclude_src_list_check_for_group_source_specific_query</td>
    <td>1. Send join message with Include mode.
2. Now change it to Exclude.
3. Check for specific query packet</td>
    <td>Specific query packet  sent from any of the source address should now get filtered</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_38</td>
    <td>Verify group specific query packet after changing to Include mode</td>
    <td>test_igmp_change_to_include_src_list_check_for_general_query</td>
    <td>1. Send a join message with Exclude mode.
2. Now change it to Include.
3. Check for General query packet</td>
    <td>General query packet  sent from any of the source address should not get filtered</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_39</td>
    <td>Verify igmp include and exclude modes </td>
    <td>test_igmp_include_exclude_modes</td>
    <td>send igmp join for include mode
Send igmp join for exclude mode
Send traffic to both the groups</td>
    <td>Traffic should receive for include mode group only</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_40</td>
    <td>Verify igmp allow new source mode </td>
    <td>test_igmp_allow_new_source_mode</td>
    <td>Send igmp include mode join
Send traffic
Send allow new source to the same group
Send traffic with newly allowed source </td>
    <td>Traffic should receive with newly allowed source </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_41</td>
    <td>Verify igmp include mode to exclude mode change</td>
    <td>test_igmp_include_to_exclude_mode_change</td>
    <td>send igmp include mode join
Send traffic to above group
Send exclude mode join to same group
Send traffic now</td>
    <td>Traffic should receive when join sent as include mode and traffic should not receive  when exclude mode sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_42</td>
    <td>Verify igmp exclude mode to include mode change</td>
    <td>test_igmp_exclude_to_include_mode_change</td>
    <td>1.send igmp exclude mode join
2.Send traffic to above group
3.Send include mode join to same group
4. Send traffic now</td>
    <td>Traffic should receive when join sent as include mode and traffic should not receive  when exclude mode sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_43</td>
    <td>Verify igmp to_include with null source list </td>
    <td>test_igmp_to_include_mode_with_null_source</td>
    <td>Send igmp include ode join
Send traffic
Send to_include mode with empty source join to same group</td>
    <td>After sending to_include with empty source list, traffic should not receive </td>
    <td>Need to test on multicast router connected setup</td>
  </tr>
  <tr>
    <td>IGMP_44</td>
    <td>Verify igmp to_include mode </td>
    <td>test_igmp_to_include_mode</td>
    <td>send igmp include mode join
Send traffic
Send igmp to_include to same group with other source
Send traffic </td>
    <td>Traffic should receive when traffic sent from other sources also</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>
IGMP_45</td>
    <td>Verify igmp block old source mode </td>
    <td>test_igmp_blocking_old_source_mode</td>
    <td>send igmp join with include mode
Send traffic
Send join with block old sources
Send traffic with source blocked </td>
    <td>Traffic should not receive once the source has blocked </td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_46</td>
    <td>Verify igmp traffic for 100 groups </td>
    <td>test_igmp_multiple_joins_and_data_verification_with_100_groups</td>
    <td>send 100 igmp joins
Send traffic to all 100 groups </td>
    <td>Traffic should receive for all 100 groups</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_47</td>
    <td>Verify igmp-leave</td>
    <td>test_igmp_multiple_joins_with_data_verification_and_leaving_100_groups</td>
    <td>send 100 igmp joins
Send traffic to each group
Send leave to each group</td>
    <td>Traffic should not received once the group receives leave </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_48</td>
    <td>
Verify onos stability when ssm table filled with 1000 entries </td>
    <td>test_igmp_group_source_for_only_config_with_1000_entries</td>
    <td>Push igmp ssm entries for 1000 groups into onos </td>
    <td>Verify if all groups lists  in ‘netcfg’ command in onos and onos should be stable </td>
    <td>Need to check for max entries support in ONOS ssm table </td>
  </tr>
  <tr>
    <td>IGMP_49</td>
    <td>Verify exclue to include mode for 100 groups</td>
    <td>test_igmp_from_exclude_to_include_mode_with_100_groups</td>
    <td>send igmp join exclude mode
Send traffic
Send igmp join to include mode
Send traffic
Repeat steps for 100 groups</td>
    <td>Traffic should receive in case of include sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_50</td>
    <td>Verify igmp include mode traffic for 1000 groups</td>
    <td>test_igmp_with_multiple_joins_and_data_verify_with_1000_groups</td>
    <td>send igmp join with include mode
Send traffic to above join
Repeat for 1000 groups</td>
    <td>Traffic should receive for all 1000 groups</td>
    <td>Pass
</td>
  </tr>
  <tr>
    <td>IGMP_51</td>
    <td>Verify igmp include mode traffic for 5000 groups</td>
    <td>test_igmp_with_multiple_joins_and_data_verify_with_5000_groups</td>
    <td>1.send igmp join with include mode
2.Send traffic to above join
3. Repeat for 5000 groups
</td>
    <td>Traffic should receive for all 5000 groups</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_52</td>
    <td>Verify sending traffic to not registered igmp group</td>
    <td>test_igmp_send_data_to_non_registered_group</td>
    <td>send igmp join include mode for group G1
Send data traffic to group G2</td>
    <td>Traffic to G2 should not received on client side</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_53</td>
    <td>Verify igmp data traffic without sending join </td>
    <td>test_igmp_traffic_verification_for_registered_group_with_no_join_sent</td>
    <td>Dont send igmp join for group G1
Send data traffic to group G1</td>
    <td>As the join not registered data traffic should not received on any interface </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_54</td>
    <td>Verify igmp functionality with app deactivation </td>
    <td>test_igmp_toggling_app_activation</td>
    <td>send igmp join include mode
Send data traffic to above group
Deactivate igmp app
Repeat step 2</td>
    <td>After app deactivate data traffic should not receive on any interface</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_55</td>
    <td>Verify igmp traffic sent to mismatching destination ip and mac</td>
    <td>test_igmp_with_mismatch_for_dst_ip_and_mac_in_data_packets</td>
    <td>send igmp include mode join
Send data traffic
Data traffic again with dest mac and IP addresses mismatch </td>
    <td>Incase of dest mac and IP mismatch, client should not receive traffic </td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>IGMP_56</td>
    <td>Verify ig igmp module registers invalid IP address</td>
    <td>test_igmp_registering_invalid_group</td>
    <td>send igmp join include mode for valid multicast ip
Repeat step for invalid IP </td>
    <td>Joins sent to invalid multicast IPs should not get registered</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>IGMP_57</td>
    <td>Verify igmp join sent with invalid source IP should not register </td>
    <td>test_igmp_registering_invalid_source</td>
    <td>1.send igmp include mode join with invalid source IP</td>
    <td>Join should not get registered </td>
    <td>Pass</td>
  </tr>
</table>


**Authentication**

** **

**Set up for EAP-TLS :**

**-------------------------**

**1. ****ea.conf file  (**

**          in eap section  default_eap_type = tls **

**          in gtc section comment the #auth_type = EAP }**

** **

**2. TLS Client Certification PEM file. (File name - inno-dev-ca-certificate..pem) .**

**3. Copy and past Client crt in server installed  CA.crt file. (File name -inno-dev-ca-certificate.crt)   **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Auth_1</td>
    <td>Verify EAP-MD5 authentication </td>
    <td> test_eap_md5</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response with identity.
3. Send EAP response with MD5 challenge</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP success message should be seen.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_2</td>
    <td>Verify EAP-MD5 authentication with wrong password</td>
    <td>test_eap_md5_wrg_password</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response.
3. Send EAP response with MD5 challenge with wrong password</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP failure message should be seen.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_3</td>
    <td>Verify EAP-MD5 authentication with wrong challenge</td>
    <td> </td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response.
3. Send EAP response with MD5 challenge with wrong challenge</td>
    <td>1. Got EAP Request for identity.
2. Got EAP request  for MD5 challenge.
3. EAP failure message should be seen.
 </td>
    <td>To Be implemented</td>
  </tr>
  <tr>
    <td>Auth_4</td>
    <td>Verify EAP-TLS authentication</td>
    <td>test_eap_tls</td>
    <td>1. Send EAPOL start message from the client.
2. Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send Client Hello TLS Certificate.
5. Send Client TLS Finished</td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Got change cipher request from server
5. EAP-TLS success message should be seen.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_5</td>
    <td>Verify EAP-TLS authentication with empty TLS client certification</td>
    <td>test_eap_tls_noCrt</td>
    <td>1. Send EAPOL start message from the client
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send an empty Client Hello TLS Certificate
 </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_6</td>
    <td>Verify EAP-TLS authentication with Invalid client certification</td>
    <td>test_eap_tls_InvalidCrt</td>
    <td>1. Send EAPOL start message from the client .
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send an invalid Client Hello TLS Certificate
 </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out. </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_7</td>
    <td>Verify EAP-TLS authentication with self signed client certification</td>
    <td>test_eap_tls_Self_Signed_Crt</td>
    <td>1. Send EAPOL start message from the client .
2.  Send EAP response with identity.
3. Send Client Hello TLS payload .
4. Send Self signed Client Hello TLS Certificate. </td>
    <td>1. Got EAP Request for identity.
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_8</td>
    <td>Verify EAP-TLS authentication with 2 RGs having the same valid TLS certificate </td>
    <td>test_eap_tls_2RGs_SameValid_Crt</td>
    <td>1.Let one RG start with EAPOL message using the valid TLS certificate.
2. Let 2nd RG start with EAPOL message using the same TLS certificate. </td>
    <td>Access reject message should be seen from ONOS or socket should get timed out.  </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_9</td>
    <td>Verify tls authentication fails with invalid session id </td>
    <td>test_eap_tls_invalid_session_id</td>
    <td>1. Initiate tls authentication process with invalid session id </td>
    <td>Authentication should get fail </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_10</td>
    <td>Verify random gmt_unit_time field in tls hello</td>
    <td>test_eap_tls_random_gmt_unix_time</td>
    <td>Initiate tla authentication process with gmt_unix_time value set to random value</td>
    <td>Authentication should get success if gmt_unix_time in within range </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_11</td>
    <td>Verify authentication with invalid content type in tls hello </td>
    <td>test_eap_tls_invalid_content_type</td>
    <td>Initiate tls authentication with invalid content type in tls hello</td>
    <td>Authentication should get failed </td>
    <td>Scapy tool filters invalid content type</td>
  </tr>
  <tr>
    <td>Auth_12</td>
    <td>Verify tls authentication with invalid fragment length field in tls record packet</td>
    <td>test_eap_tls_invalid_record_fragment_length</td>
    <td>Initiate tls authentication process with invalid fragment length in tls record </td>
    <td>Authentication should get failed </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_13</td>
    <td>Verify tls authentication with invalid id in identifier response packet </td>
    <td>test_eap_tls_with_invalid_id_in_identifier_response_packet</td>
    <td>Initiate tls authentication process with invalid id in identifier response packet </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_14</td>
    <td>Verify tls authentication with invalid id in client hello packet</td>
    <td>test_eap_tls_with_invalid_id_in_client_hello_packet</td>
    <td>Initiate tls authentication process with invalid id in client hello packet</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_15</td>
    <td>Verify tls authentication without sending client hello packet </td>
    <td>test_eap_tls_without_sending_client_hello</td>
    <td>Initiate tls authentication without sending client hello packet</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_16</td>
    <td>Verify tls authentication with app deactivated</td>
    <td>test_eap_tls_aaa_app_deactivate</td>
    <td>Initiate tls authentication with app deactivation </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_17</td>
    <td>Verify tls authentication with incorrect cipher suite length field</td>
    <td>test_eap_tls_incorrect_cipher_suite_length_field</td>
    <td>Initiate tls authentication with invalid cipher suite length field </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_18</td>
    <td>Verify tls authentication with incorrect compression method field length in  tls hello</td>
    <td>test_eap_tls_incorrect_compression_methods_length_field</td>
    <td>Initiate tls authentication with incorrect compression length field in tls hello </td>
    <td>Authentication should get failed </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_19</td>
    <td>Verify tls authentication with broadcast source mac</td>
    <td>test_eap_tls_invalid_source_mac_broadcast</td>
    <td>Initiate tls authentication process with client mac broadcast </td>
    <td>Authentication should get failed</td>
    <td>Fail
</td>
  </tr>
  <tr>
    <td>Auth_20</td>
    <td>Verify tls authentication with multicast source mac</td>
    <td>test_eap_tls_invalid_source_mac_multicast</td>
    <td>Initiate tls authentication process with client mac multicast </td>
    <td>Authentication should get failed</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>Auth_21</td>
    <td>Verify tls authentication with all 0’s source mac</td>
    <td>test_eap_tls_invalid_source_mac_zero</td>
    <td>Initiate tls authentication process with client mac all 0’s</td>
    <td>Authentication should get failed</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>Auth_22</td>
    <td>Verify tls authentication if radius server restarts in middle of auth process </td>
    <td>test_eap_tls_restart_radius_server</td>
    <td>Initiate tls authentication process and restart radius server in middle of  auth process </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_23</td>
    <td>Verify tls authentication with incorrect tls hello handshake type</td>
    <td>test_eap_tls_with_incorrect_handshake_type_client_hello</td>
    <td>Initiate tls authentication process with incorrect hello handshake type</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_24</td>
    <td>Verify tls authentication with incorrect tls hello handshake type certificate request </td>
    <td>test_eap_tls_with_incorrect_handshake_type_certificate_request</td>
    <td>Initiate tls authentication process with incorrect hello handshake type</td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_25</td>
    <td>Verify tls authentication with incorrect tls hello tls record certificate request</td>
    <td>test_eap_tls_with_incorrect_tlsrecord_certificate_request</td>
    <td>Initiate tls authentication process with incorrect tls record certificate  request </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_26</td>
    <td>Verify tls authentication with invalid handshake length in client hello </td>
    <td>test_eap_tls_invalid_handshake_length_client_hello</td>
    <td>Initiate tls authentication with invalid  handshake length in client hello </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_27</td>
    <td>Verify tls authentication with client key exchange with server key exchange </td>
    <td>test_eap_tls_clientkeyex_replace_with_serverkeyex</td>
    <td>Initiate tls authentication process with client key exchange replaced with server key exchange </td>
    <td>Authentication should get failed</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_28</td>
    <td>Verify tls authentication for 1000 users </td>
    <td>test_eap_tls_1k_with_diff_mac</td>
    <td>Initiate tls authentication for 1000  clients</td>
    <td>Authentication should get success for  all 1000 clients </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_29</td>
    <td>Verify tls authentication for 5000 clients </td>
    <td>test_eap_tls_5k_with_diff_mac</td>
    <td>Initiate tls authentication for 5000  clients</td>
    <td>Authentication should get success for  all 5000 clients</td>
    <td>Pass</td>
  </tr>
</table>


**DHCP**

** **

**Activate the DHPC app**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>DHCP_1</td>
    <td>Verify the dynamic ip address allocation of client</td>
    <td>test_dhcp_1request</td>
    <td>Send a DHCP discover message from client</td>
    <td>All DHCP messages like DHCP discover, DHCP offer, DHCP request and DHCP Ack should be checked.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_2</td>
    <td>Verify DHCP NAK message from the server</td>
    <td> </td>
    <td>1. Configure pool lets say 20.0.0.1-20.0.0.10 in DHCP server.
2. Let client get the ip address
1. Disconnect this server and Connect another server with IP pool as 80.0.0.1-80.0.0.10
2. Let client send DHCP request message.</td>
    <td>When the client sends DHCPREQUEST it will ask for the previous ip address which is not present in pool so the server will send NAK.</td>
    <td>Not yet implemented</td>
  </tr>
  <tr>
    <td>DHCP_3</td>
    <td>Verify releasing an IP from the client to the server to rediscover</td>
    <td>test_dhcp_1release</td>
    <td>Send DHCP release packet from the client to the server</td>
    <td>IP address should get released back to the server and should be able to rediscover</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_4</td>
    <td>Multiple dhcp servers</td>
    <td> </td>
    <td>Let there be multiple DHCP servers.
Start a dhcp client from one host.</td>
    <td>IP address should get allocated to the host from one of the DHCP servers.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>DHCP_5</td>
    <td>Verify DHCP decline message from the client</td>
    <td> </td>
    <td>1. You need two clients. One static and one through DHCP server.
2. Try to first assign ip address to dhcp client, reboot the client or just remove it from network.
3. Meanwhile give the same static ip to another client.
4. Now connect the dhcp client.</td>
    <td>When the server assigns the ip address the client will do gracious arp and as static ip is already present it will send DHCPDECLINE message to the Server.</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHCP_6</td>
    <td>Verify restarting the dhcp client</td>
    <td>test_dhcp_client_request_after_reboot</td>
    <td>1. Restart the client which has got previously leased IP address.
2. Check for DHCP Ack message </td>
    <td>If the requested IP address can be used by the client, the DHCP server responds with a DHCPAck message.
   </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_7</td>
    <td>Verify multiple client scenario</td>
    <td>test_dhcp_Nrequest</td>
    <td>Let there be multiple hosts and generate a multiple DHCP request messages</td>
    <td>Server should be able to give ip address to all the hosts.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_8</td>
    <td>check for Fail over mechanism in dhcp</td>
    <td> </td>
    <td>Let there be 2 dhcp servers in the same subnet or scope.
Make one dhcp server down</td>
    <td>If a DHCP server1 is no longer reachable, then client is able to extend the lease on its current IP address by contacting another DHCP server2.</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHCP_9</td>
    <td>Verify DHCP client renewing State</td>
    <td> </td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server</td>
    <td>Since the server is up and reachable , it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_10</td>
    <td>Verify the client behavior when DHCP server is rebooted.</td>
    <td>test_dhcp_server_after_reboot</td>
    <td>1. Send a DHCP discover packet .
2. Send a DHCP request packet from the client.
3. Make the DHCP server down.
4. Make the DHCP server up.</td>
    <td>1. DHCP offer packet generated.
2. DHCP Ack packet generated.
3. Client should have the same ip till the lease time expires.
4. DHCP Ack should be sent from the server. </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_11</td>
    <td>Verify generation of DHCP inform message</td>
    <td> </td>
    <td>1. Let client send a DHCP inform message with its own ip address in ciaddr field.
2. Check for DHCP ACk message</td>
    <td>DHCP Ack message should be sent from the server which includes the needed parameters in the appropriate DHCP option fields</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHCP_12</td>
    <td>DHCP starvation attack</td>
    <td>test_dhcp_starvation</td>
    <td>Send a lot of dummy DHCP requests, with random source Mac address (using Scapy)</td>
    <td>After few second, there is no more IP addresses available in the pool, thus successfully performing denial of service attack to other network client.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_13</td>
    <td>Verify DHCP Relay functionality</td>
    <td> </td>
    <td>Make ONOS as DHCP relay agent and Send a DHCP discover message from the client. This inserts the option 82.</td>
    <td>ONOS should forward the DHCP server reply to the client</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHVP_14</td>
    <td>Verify sending DHCP discover packet twice</td>
    <td>test_dhcp_same_client_multiple_discover</td>
    <td>Send DHCP discover packet twice from the client.</td>
    <td>DHCP server should give the same ip to the client.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_15</td>
    <td>Verify sending DHCP request packet twice</td>
    <td>test_dhcp_same_client_multiple_request</td>
    <td>Send the DHCP request packet twice form the client</td>
    <td>DHCP Ack should be sent.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_16</td>
    <td>Verify ip address assignment when dhcp request and offer ip are different </td>
    <td>test_dhcp_server_nak_packet</td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message with a different ip.
 </td>
    <td>1. DHCP offer should be sent from server.
2. DHCP NAK should be sent from the server.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_17</td>
    <td>Verify  ip address assignment is successful when desired ip is sent.</td>
    <td>test_dhcp_client_desired_address</td>
    <td>Send a DHCP discover packet with the desired ip which is in the server address pool.
 </td>
    <td>DHCP ip address assignment should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_18</td>
    <td>Verify  ip address assignment when desired ip is sent which is out of the pool.</td>
    <td>test_dhcp_client_desired_address_out_of_pool</td>
    <td>Send a DHCP discover packet with the desired ip which is out of the  server address pool.
 </td>
    <td>DHCP NAK message should be sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_19</td>
    <td>Verify  ip address assignment with the lease time information specified.</td>
    <td>test_dhcp_lease_packet</td>
    <td>Send a DHCP discover packet with the least time mentioned.</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>DHCP_20
</td>
    <td>Verify sending N releases from the client </td>
    <td>test_dhcp_Nrelease
</td>
    <td>Send multiple DHCP release packet from the client to the server</td>
    <td>All IP addresses should get released back to the server and should be able to rediscover

</td>
    <td>Pass

</td>
  </tr>
  <tr>
    <td>DHCP_21</td>
    <td>Verify broadcast address in dhcp offer</td>
    <td>test_dhcp_client_expected_broadcast_address </td>
    <td>1. Send DHCP discover message.
2. Extract option broadcast address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Broadcast address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_22</td>
    <td>Verify dns address in dhcp offer</td>
    <td>test_dhcp_client_expected_dns_address </td>
    <td>1. Send DHCP discover message.
2. Extract option dns address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Dns address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_23</td>
    <td>Verify router address in dhcp offer</td>
    <td>test_dhcp_client_expected_router_address </td>
    <td>1. Send DHCP discover message.
2. Extract option router address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Router address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_24</td>
    <td>Verify Subnet mask in dhcp offer</td>
    <td>test_dhcp_client_expected_subnet_mask </td>
    <td>1.Send DHCP discover message.
2.Extract option Subnet mask from dhcp offer message.
3.Check with your server configuration</td>
    <td>Subnet mask should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_25</td>
    <td>Verify sending dhcp discover with wrong broadcast address</td>
    <td>test_dhcp_client_sends_dhcp_request_with_wrong_broadcast_address </td>
    <td>1. Send DHCP discover message with wrong broadcast address.
2. Extract option Broadcast address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration broadcast address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_26</td>
    <td>Verify sending dhcp discover with wrong DNS address</td>
    <td>test_dhcp_client_sends_dhcp_request_with_wrong_dns_address </td>
    <td>1. Send DHCP discover message with wrong dns address.
2. Extract option DNS server from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration DNS address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_27</td>
    <td>Verify sending dhcp discover with wrong router address</td>
    <td>test_dhcp_client_sends_dhcp_request_with_wrong_router_address </td>
    <td>1. Send DHCP discover message with wrong router address.
2. Extract option router address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration Router address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_28</td>
    <td>Verify sending dhcp discover with wrong Subnet mask address</td>
    <td>test_dhcp_client_sends_dhcp_request_with_wrong_subnet_mask </td>
    <td>1. Send DHCP discover message with wrong Subnet mask.
2. Extract option Subnet mask address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration Subnet mask should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_29</td>
    <td>Verify dhcp client renew process</td>
    <td>test_dhcp_client_renew_time </td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server</td>
    <td>Since the server is up and reachable, it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_30</td>
    <td>Verify dhcp client rebind process</td>
    <td>test_dhcp_client_rebind_time </td>
    <td>After Rebind timer expires, a DHCP request message which is broadcast is being sent.</td>
    <td>Since the server is up and reachable, it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_31</td>
    <td>Verify lease time check</td>
    <td>test_dhcp_lease_packet</td>
    <td>1. Send DHCP discover message.
2. Send DHCP request now.
3. Extract the option lease time in DHCP ACK packet.</td>
    <td>1. DHCP offer should be received.
2. DHCP Ack packet should be received with the default lease time of 600 sec.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_32</td>
    <td>Measure average no. of transactions in DHCP server in 1 second</td>
    <td>test_dhcp_server_transactions_per_second </td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses.
2. Calculate total running time and total no. of transactions after repeating the procedure for 3 times.
3. Divide total no. of transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_33</td>
    <td>Measure average no. of consecutive successful  transactions in DHCP server in 1 second</td>
    <td>test_dhcp_server_consecutive_successes_per_second</td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses.
2. Calculate total running time and total no. of successful transactions after repeating the procedure for 3 times.
3. Divide total no. of successful transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_34</td>
    <td>Measure average number of clients (DHCP discover) in 1 second</td>
    <td>test_dhcp_server_clients_per_second </td>
    <td>1. Send DHCP discover packets continuously from different mac address.
 2.Calculate total running time and total no. Of clients after repeating the procedure for 3 times.
3. Divide total no. of clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_35</td>
    <td>Measure average no. of consecutive successful  clients in DHCP server in 1 second</td>
    <td>test_dhcp_server_consecutive_successful_clients_per_second</td>
    <td>1. Send DHCP discover packets continuously from different mac address.
 2.Calculate total running time and total no. Of successful clients after repeating the procedure for 3 times.
3. Divide total no. Of successful clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass</td>
  </tr>
</table>


**Subscriber **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Subs_1</td>
    <td>Verify subscriber joining and receiving traffic
</td>
    <td>test_subscriber_join_recv_channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to a particular group.
</td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. Interface should receive traffic. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_2</td>
    <td>Verify joining and jumping to the next channel for channel surfing</td>
    <td>test_subscriber_join_jump_channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next ip.
3. Jump to the next channel and verify the traffic
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. Interface should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_3</td>
    <td>Test subscriber join next for channels</td>
    <td>test_subscriber_join_next_channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Join the next channel and verify the traffic. </td>
    <td>1.TLS authentication should be successful.
2. Interface should receive traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_4</td>
    <td>Verify subscriber TLS authentication by sending invalid client certificate</td>
    <td>test_subscriber_authentication_with_invalid_certificate_and_channel_surfing</td>
    <td>1. Send an invalid Client Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.
 </td>
    <td>1. Authentication should not be successful.
2. Subscriber should not receive any ip from DHCP server. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_5</td>
    <td>Verify subscriber TLS authentication by sending no client certificate</td>
    <td>test_subscriber_authentication_with_no_certificate_and_channel_surfing</td>
    <td>1. Send an blank Client Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.
 </td>
    <td>1.Authentication should not be successful.
2.Subscriber shouldn’t receive any ip from DHCP server. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_6</td>
    <td>Verify subscriber TLS authentication by sending self signed certificate </td>
    <td>test_subscriber_authentication_with_self_signed_certificate_and_channel_surfing</td>
    <td>1. Send a self sigend Client Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.</td>
    <td>1.Authentication should not be successful.
2.Subscriber shouldn’t receive any ip from DHCP server. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_7</td>
    <td>Verify subscribers TLS authenticatiby sending non ca  certificate. </td>
    <td>test_subscriber_authentication_with_non_ca_authorized_certificate_and_channel_surfing</td>
    <td>1. Send a non ca Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.</td>
    <td>1.Authentication should not be successful.
2.Subscriber shouldn’t receive any ip from DHCP server. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_8</td>
    <td>Verify subscriber with dhcp rediscover functionality</td>
    <td>test_subscriber_authentication_with_dhcp_discover_and_channel_surfing</td>
    <td>1. Send a DHCP discover packet from the subscriber.
2. Send DHCP release and again send dhcp discover from the client.</td>
    <td>1. DHCP Ack should get received.
2. After releasing and then re-sending, dhcp ip address assignment should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_9</td>
    <td>Verify the DHCP process when the subscriber becomes down and  up.</td>
    <td>test_subscriber_authentication_with_dhcp_client_reboot_scenario_and_channel_surfing</td>
    <td>After DHCP address assignment to the client, make the subscriber down and then make it up.</td>
    <td>Once its up, DHCP request message should be sent from the client to the server which is unicast.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_10</td>
    <td>Verify the DHCP process when the DHCP server becomes down and  up.
</td>
    <td>test_subscriber_authentication_with_dhcp_server_reboot_scenario_and_channel_surfing</td>
    <td>1. Send a DHCP discover packet .
2. Send a DHCP request packet from the client.
3. Make the DHCP server down.
4. Make the DHCP server up.</td>
    <td>1. DHCP offer packet generated.
2. DHCP Ack packet generated.
3. Client should have the same ip till the lease time expires.
4. DHCP Ack should be sent from the server. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_11</td>
    <td>Verify dhcp subscriber rebind process</td>
    <td>test_subscriber_authentication_with_dhcp_client_rebind_and_channel_surfing</td>
    <td>After Rebind timer expires, a DHCP request message which is broadcast is being sent .</td>
    <td>Since the server is up and reachable , it should respond back with DHCP Ack packet</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_12</td>
    <td>Verify DHCP subscriber starvation attack </td>
    <td>test_subscriber_authentication_with_dhcp_starvation_scenario_and_channel_surfing</td>
    <td>1. Let the authentication be successful.
2. Send a lot of dummy DHCP requests, with random source Mac address (using Scapy)</td>
    <td>After few second, there is no more IP addresses available in the pool, thus successfully performing denial of service attack to other subscriber</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_13</td>
    <td>Verify ip address assignment is successful when DHCP discover is sent twice.
</td>
    <td>test_subscriber_authentication_with_multiple_dhcp_discover_for_same_subscriber_and_channel_surfing</td>
    <td> Let authentication be successful.
Send DHCP discover message twice from the client.

</td>
    <td>DHCP server should give the same ip to the client using the DHCP Ack packet. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_14</td>
    <td>Verify ip address assignment is successful when DHCP request is sent twice.</td>
    <td>test_subscriber_authentication_with_multiple_dhcp_request_for_same_subscriber_and_channel_surfing</td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message.
3. Again send DHCP request message.
</td>
    <td>1. DHCP offer should be sent from the server.
2. DHCP Ack should get received.
</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_15</td>
    <td>Verify subscriber ip address assignment is successful when desired ip is sent.</td>
    <td>test_subscriber_authentication_with_dhcp_client_requested_ip_and_channel_surfing</td>
    <td>1.Let the authentication be successful.
Send a DHCP discover packet with the desired ip which is in the server address pool.
2.Send DHCP discover message twice from the client.</td>
    <td>DHCP ip address assignment should be successful.
</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_16</td>
    <td>Verify ip address assignment when dhcp request and offer ip are different </td>
    <td>test_subscriber_authentication_with_dhcp_non_offered_ip_and_channel_surfing</td>
    <td>1.  Let the authentication be successful.
2. Send a DHCP discover message from the client.
3.  Send DHCP request message with a different ip.
 </td>
    <td>2. DHCP offer should be sent from server.
3. DHCP NAK should be sent from the server.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_17</td>
    <td>Verify subscriber ip address assignment when desired ip is sent which is out of the pool. </td>
    <td>test_subscriber_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing</td>
    <td>1. Let the authentication be successful.
2. Send a DHCP discover packet with the desired ip which is out of the  server address pool</td>
    <td>DHCP NAK message should be sent</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_18</td>
    <td>Verify subscriber ip address assignement with the lease time information specified.</td>
    <td>test_subscriber_authentication_with_dhcp_specified_lease_time_functionality_and_channel_surfing</td>
    <td>1. Let the authentication be successful.
2. Send a DHCP discover packet with the least time mentioned.
</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_19</td>
    <td>Verify subscriber join and receive with multiple channels 100</td>
    <td>test_subscriber_join_recv_100channels</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to 100 channels
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. All interfaces  should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_20</td>
    <td>Verify subscribers jumping to 100channels.</td>
    <td>test_subscribers_join_jump_100channel</td>
    <td>1.Send a DHCP discover from 10 subscribers.
2. Jump to 5 channels and verify the traffic</td>
    <td>1.IP address should be assigend to all the subscribers.
2. All interfaces should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_21</td>
    <td>Verify subscribers joining next to 100 channels.</td>
    <td>test_subscribers_join_next_100channel</td>
    <td>1.Send a DHCP discover from 10 subscribers.
2. Join next to 5 channels and verify the traffic</td>
    <td>1.IP address should be assigend to all the subscribers.
2. All interfaces should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_22</td>
    <td>Verify subscriber join and receive with multiple channels 400</td>
    <td>test_subscriber_join_recv_400channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to 400 channels
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. All interfaces  should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_23</td>
    <td>Verify subscriber join and receive with multiple channels 800</td>
    <td>test_subscriber_join_recv_800channels</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to 800 channels
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. All interfaces  should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_24</td>
    <td>Verify subscriber join and receive with 1500 multiple channels</td>
    <td>test_subscriber_join_recv_1500channel</td>
    <td>1. Send a EAPOL start message for TLS authentication from a subscriber
2. Send a DHCP discover packet
3. Verify joining to 1500 channels. </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to all the clients.
3. All interfaces  should receive traffic.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_25</td>
    <td>Verify joining and jumping to 400 channels for channel surfing</td>
    <td>test_subscriber_join_jump_400channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next 400 channels and verify the traffic
 </td>
    <td>1. TLS authentication should be successful.
2. All Interfaces should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_26</td>
    <td>Verify joining and jumping to  800 channels for channel surfing</td>
    <td>test_subscriber_join_jump_800channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next 800 channels and verify the traffic
 </td>
    <td>1. TLS authentication should be successful.
2. All Interfaces should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_27</td>
    <td>Verify joining and jumping to  1200 channels for channel surfing</td>
    <td>test_subscriber_join_jump_1200channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next 1200 channels and verify the traffic
 </td>
    <td>1. TLS authentication should be successful.
2. All Interfaces should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_28</td>
    <td>Verify joining and jumping to  1500 channels for channel surfing</td>
    <td>test_subscriber_join_jump_1500channel</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next 1500 channels and verify the traffic
 </td>
    <td>1. TLS authentication should be successful.
2. All Interfaces should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_29</td>
    <td>Test subscriber join next for 400 channels</td>
    <td>test_subscriber_join_next_400channel</td>
    <td>1. Send a EAPOL start message for TLS authentication from a subscriber
2.  Join the next 400 channels and verify the traffic</td>
    <td>1. TLS authentication should be successful.
2. Interfaces should receive traffic. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_30</td>
    <td>Test subscriber join next for 800 channels</td>
    <td>test_subscriber_join_next_800channel</td>
    <td>1. Send a EAPOL start message for TLS authentication from a subscriber
2.  Join the next 800 channels and verify the traffic</td>
    <td>1. TLS authentication should be successful.
2. Interfaces should receive traffic. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_31</td>
    <td>Test subscriber join next for 1200 channels</td>
    <td>test_subscriber_join_next_1200channel</td>
    <td>1. Send a EAPOL start message for TLS authentication from a subscriber
2.  Join the next 1200 channels and verify the traffic</td>
    <td>1. TLS authentication should be successful.
2. Interfaces should receive traffic. </td>
    <td></td>
  </tr>
  <tr>
    <td>Subs_32</td>
    <td>Test subscriber join next for 1500 channels</td>
    <td>test_subscriber_join_next_1500channel</td>
    <td>1. Send a EAPOL start message for TLS authentication from a subscriber
2.  Join the next 1500 channels and verify the traffic</td>
    <td>1. TLS authentication should be successful.
2. Interfaces should receive traffic. </td>
    <td></td>
  </tr>
</table>


**Vrouter **

** **

** Start the quagga container and activate the Vrouter app.**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Vrouter_1</td>
    <td>Test vrouter with 5 routes</td>
    <td>test_vrouter_with_5_routes</td>
    <td> 1.Generate vrouter configuration with new network configuration file
Start onos and Quagga
Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_2</td>
    <td>Test vrouter with 5 routes with 2 peers</td>
    <td>test_vrouter_with_5_routes_2_peers</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 2 peers and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_3</td>
    <td>Test vrouter with 5 routes with stopping Quagga</td>
    <td>test_vrouter_with_5_routes_stopping_quagga</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check
4. Stop Quagga and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_4</td>
    <td>Test vrouter with 50 routes with stopping Quagga</td>
    <td> test_vrouter_with_50_routes_stopping_quagga</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check
4. Stop Quagga and check</td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_5</td>
    <td>Test vrouter with 6 routes with 3 peers</td>
    <td> test_vrouter_with_6_routes_3_peers</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 2 peers and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_6</td>
    <td>Test vrouter with 50 routes</td>
    <td> test_vrouter_with_50_routes</td>
    <td> 1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_7</td>
    <td>Test vrouter with 50 routes and 5 peers</td>
    <td> test_vrouter_with_50_routes_5_peers</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 5 peers and check</td>
    <td>It should be successful..</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_8</td>
    <td>Test vrouter with 100 routes</td>
    <td> test_vrouter_with_100_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_9</td>
    <td>Test vrouter with 100 routes and 10 peers</td>
    <td> test_vrouter_with_100_routes_10_peers</td>
    <td>   1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes with 10 peers and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_10</td>
    <td>Test vrouter with 300 routes</td>
    <td> test_vrouter_with_300_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_11</td>
    <td>Test vrouter with 1000 routes</td>
    <td> test_vrouter_with_1000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>It should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_12</td>
    <td>Test vrouter with 10000 routes</td>
    <td> test_vrouter_with_10000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_13</td>
    <td>Test vrouter with 100000 routes</td>
    <td> test_vrouter_with_100000_routes</td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_14</td>
    <td>Test vrouter with 1000000 routes</td>
    <td>test_vrouter_with_1000000_routes </td>
    <td>  1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes and check</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_15</td>
    <td>Test vrouterwith route update</td>
    <td>test_vrouter_with_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_16</td>
    <td>Test vrouterwith classA route update</td>
    <td>test_vrouter_with_classA_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_17</td>
    <td>Test vrouterwith classB route update</td>
    <td>test_vrouter_with_classB_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_18</td>
    <td>Test vrouterwith class less route update</td>
    <td>test_vrouter_with_classless_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_19</td>
    <td>Test vrouter with classA duplicate route update</td>
    <td>test_vrouter_with_classA_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_20</td>
    <td>Test vrouter with classB duplicate route update</td>
    <td>test_vrouter_with_classB_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_21</td>
    <td>Test vrouter with classless duplicate route update</td>
    <td>test_vrouter_with_classless_duplicate_route_update</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_22</td>
    <td>Test vrouter with invalid peers</td>
    <td>test_vrouter_with_invalid_peers</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Not Tested</td>
  </tr>
  <tr>
    <td>Vrouter_23</td>
    <td>Test vrouter with traffic sent between peers connected to onos</td>
    <td>test_vrouter_with_traffic_sent_between_peers_connected_to_onos</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>Not Tested</td>
  </tr>
  <tr>
    <td>Vrouter_24</td>
    <td>Test vrouter with routes time expire</td>
    <td>test_vrouter_with_routes_time_expire</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_25</td>
    <td>Test vrouter with unreachable route</td>
    <td>test_vrouter_with_unreachable_route</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_26</td>
    <td>Test vrouter with enabling disabling vrouter app</td>
    <td>test_vrouter_with_enabling_disabling_vrouter_app</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_27</td>
    <td>Test vrouter with adding new routes in routing table</td>
    <td>test_vrouter_with_adding_new_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_28</td>
    <td>Test vrouter with removing old routes in routing table</td>
    <td>test_vrouter_with_removing_old_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_29</td>
    <td>Test vrouter modifying nexthop route in routing table</td>
    <td>test_vrouter_modifying_nexthop_route_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_30</td>
    <td>Test vrouter deleting alternative nexthop in routing table</td>
    <td>test_vrouter_deleting_alternative_nexthop_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_31</td>
    <td>Test vrouter deleting some routes in routing table</td>
    <td>test_vrouter_deleting_some_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>Vrouter_32</td>
    <td>Test vrouter deleting and adding routes in routing table</td>
    <td>test_vrouter_deleting_and_adding_routes_in_routing_table</td>
    <td>1.Generate vrouter configuration with new network configuration file
2. Start onos and Quagga
3. Run traffic for routes
4. Config routes on Quagga and check updated route on DUT</td>
    <td>Route installation should be successful</td>
    <td>PASS</td>
  </tr>
</table>


**ACL**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>ACL_1</td>
    <td>Test acl allow rule</td>
    <td>test_acl_allow_rule</td>
    <td>Configure ACL rule with allow action
Verify ACL rule is being created on DUT</td>
    <td>ACL rule has beed created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_2</td>
    <td>Test acl allow rule with 24 bit mask</td>
    <td>test_acl_allow_rule_with_24_bit_mask</td>
    <td>1.  Configure ACL rule with allow action and 24 bit mask
2.  Verify ACL rule is being created on DUT</td>
    <td>ACL rule has beed created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_3</td>
    <td>Test acl deny rule</td>
    <td>test_acl_deny_rule</td>
    <td>1.  Configure ACL rule with deny action
2.  Verify ACL rule is being created on DUT</td>
    <td>ACL rule has beed created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_4</td>
    <td>Test acl deny rule with 24 bit mask</td>
    <td>test_acl_deny_rule_with_24_bit_mask</td>
    <td>1.  Configure ACL rule with deny action and 24 bit mask
2.  Verify ACL rule is being created on DUT</td>
    <td>ACL rule has beed created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_5</td>
    <td>Test acl add remove rule</td>
    <td>test_acl_add_remove_rule</td>
    <td>1.  Configure ACL rule with any action
2.  Verify ACL rule is being created on DUT
3. Delete created ACL rule</td>
    <td>ACL rule has been deleted on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_6</td>
    <td>Test acl add removeall rules</td>
    <td>test_acl_add_remove_all_rules</td>
    <td>1.  Configure ACL rule with any action
2.  Verify ACL rule is being created on DUT
3. Delete created all ACL rule</td>
    <td>All ACL rules has been deleted on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_7</td>
    <td>Test acl remove all rules without add</td>
    <td>test_acl_remove_all_rules_without_add</td>
    <td>1. Delete all ACL rule with out create amy ACL rule</td>
    <td>All ACL rule has been deleted on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_8</td>
    <td>Test acl allow and deny rule for same src and dst ip</td>
    <td>test_acl_allow_and_deny_rule_for_same_src_and_dst_ip</td>
    <td>1.  Configure ACL rule with for same src and dst ip with action allow and deny
2.  Verify ACL rule is not being created on DUT</td>
    <td>ACL rule has not been created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_9</td>
    <td>Test acl allow rules for matched dst ips</td>
    <td>test_acl_allow_rules_for_matched_dst_ips</td>
    <td> Configure ACL rule with for dst ip where already matched ACL rule
Verify ACL rule is not being created on DU</td>
    <td>ACL rule has not been created on DUT</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_10</td>
    <td>Test acl with matching src and dst ip traffic</td>
    <td>test_acl_with_matching_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is allowed</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_11</td>
    <td>Test acl with matching 24bit mask src and  dst ip traffic</td>
    <td>test_acl_with_matching_24bit_mask_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rule with allow action and 24 bit mask
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is allowed</td>
    <td>Not tested</td>
  </tr>
  <tr>
    <td>ACL_12</td>
    <td>Test acl with non matching src and dst ip traffic</td>
    <td>test_acl_with_non_matching_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule non matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is not allowed </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_13</td>
    <td>Test acl deny rule with matching src and dst ip traffic</td>
    <td>test_acl_deny_rule_with_matching_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rule with deny action
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is not  allowed</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_14</td>
    <td>Test acl deny rule with src and dst ip apply ing 24 bit mask for matching traffic</td>
    <td>test_acl_deny_rule_with_src_and_dst_ip_applying_24_bit_mask_for_matching_traffic</td>
    <td>1.  Configure ACL rule with deny action and 24 bit mask
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is not allowed</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_15</td>
    <td>Test acl deny_rule with non matching src and dst ip traffic</td>
    <td>test_acl_deny_rule_with_non_matching_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3.   Check with ACL rule non matched traffic
</td>
    <td>ACL rule has been created on DUT and traffic is not allowed </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_16</td>
    <td>Test acl allow and deny rules with matching src and dst ip traffic</td>
    <td>test_acl_allow_and_deny_rules_with_matching_src_and_dst_ip_traffic</td>
    <td>1.  Configure ACL rules with allow and deny action
2.  Verify ACL rules is being created on DUT
3.   Check with ACL rules matched traffic
</td>
    <td>ACL rules has been created on DUT and matched traffic is allowed for allow action and deny for deny action.</td>
    <td>Not tested</td>
  </tr>
  <tr>
    <td>ACL_17</td>
    <td>Test acl for l4 acl rule</td>
    <td>test_acl_for_l4_acl_rule</td>
    <td>1.  Configure ACL rule with L4 port and allow action
2.  Verify ACL rule is being created on DUT
</td>
    <td>ACL rule has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_18</td>
    <td>Test acl for remove l4 rule</td>
    <td>test_acl_for_remove_l4_rule</td>
    <td>Configure ACL rule with L4 port and allow action
Remove the config ACL rule

</td>
    <td>ACL rule has been created on DUT and able to removed it</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_19</td>
    <td>Test acl for remove l4 rules</td>
    <td>test_acl_for_remove_l4_rules</td>
    <td>1.  Configure ACL rule with L4 port and allow action
2.  Remove the config all ACL rules
</td>
    <td>ACL rule has been created on DUT and able to removed all of acl rules</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_20</td>
    <td>Test acl adding specific l4 and all l4 allow rule</td>
    <td>test_acl_adding_specific_l4_and_all_l4_allow_rule</td>
    <td>1.  Configure ACL rule with specific L4 port and allow action
2.  Verify ACL rule with all L4 port is being created on DUT

</td>
    <td>ACL rules has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_21</td>
    <td>Test acl adding all l4 and specific l4 allow rule</td>
    <td>test_acl_adding_all_l4_and_specific_l4_allow_rule</td>
    <td>1.  Configure ACL rule with all L4 port and allow action
2.  Verify ACL rule with specific L4 port is not being created on DUT
</td>
    <td>ACL rule with all L4 port number has been created on DUT  </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_22</td>
    <td>Test acl with specific l4 deny and all l4 allow rule</td>
    <td>test_acl_with_specific_l4_deny_and_all_l4_allow_rule</td>
    <td>1.  Configure ACL rule with specific L4 port and deny action
2.  Verify ACL rule with all L4 port and allow is being created on DUT

</td>
    <td>ACL rules has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_23</td>
    <td>Test acl with all l4 and specific l4 deny rule</td>
    <td>test_acl_with_all_l4_and_specific_l4_deny_rule</td>
    <td>1.  Configure ACL rule with all L4 port and deny action
2.  Verify ACL rule with specific L4 port and deny is not being created on DUT
</td>
    <td>ACL rule has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_24</td>
    <td>Test acl with specific l4 deny and all l4 allow rule</td>
    <td>test_acl_with_specific_l4_deny_and_all_l4_allow_rule</td>
    <td>1.  Configure ACL rule with specific L4 port and deny action
2.  Verify ACL rule with all L4 port and allow is not being created on DUT
</td>
    <td>ACL rules has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_25</td>
    <td>Test acl deny all l4 and allow specific l4 rule</td>
    <td>test_acl_deny_all_l4_and_allow_specific_l4_rule</td>
    <td>1.  Configure ACL rule with all L4 port and deny action
2.  Verify ACL rule with specific L4 port and allow is not being created on DUT
</td>
    <td>ACL rule has been created on DUT </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>ACL_26</td>
    <td>Test acl tcp port allow rule for matching and non matching traffic</td>
    <td>test_acl_tcp_port_allow_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_27</td>
    <td>Test acl udp port allow rule for matching and non matching traffic</td>
    <td>test_acl_udp_port_allow_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_28</td>
    <td>Test acl icmp port allow rule for matching and non matching traffic</td>
    <td>test_acl_icmp_port_allow_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_29</td>
    <td>Test acl tcp port deny rule for matching and non matching traffic</td>
    <td>test_acl_tcp_port_deny_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with deny action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_30</td>
    <td>Test acl udp port deny rule for matching and non matching traffic</td>
    <td>test_acl_udp_port_deny_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with deny action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_31</td>
    <td>Test acl icmp port deny rule for matching and non matching traffic</td>
    <td>test_acl_icmp_port_deny_rule_for_matching_and_non_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_32</td>
    <td>Test acl two allow rules for tcp port matching traffic</td>
    <td>test_acl_two_allow_rules_for_tcp_port_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic for first ACL</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_33</td>
    <td>Test acl two allow rules for udp port matching traffic</td>
    <td>test_acl_two_allow_rules_for_udp_port_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic for first ACL</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_34</td>
    <td>Test acl two allow rules for src ips dst ips and l4 ports matching traffic</td>
    <td>test_acl_two_allow_rules_for_src_ips_dst_ips_and_l4_ports_matching_traffic</td>
    <td>1.  Configure ACL rule with allow action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic for first ACL</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
  <tr>
    <td>ACL_35</td>
    <td>test_acl allow and deny rules for src ips dst ips and l4 ports matching traffic</td>
    <td>test_acl_allow_and_deny_rules_for_src_ips_dst_ips_and_l4_ports_matching_traffic</td>
    <td>1.  Configure ACL rule with allow and deny action
2.  Verify ACL rule is being created on DUT
3. Check with ACL rule matched traffic
4. Check with ACL rule non matched traffic for first ACL</td>
    <td>ACL rule has been created on DUT and matched traffic is allowed and non-matched is not allowed</td>
    <td>Failed</td>
  </tr>
</table>


**IPV6**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>IPV6_1</td>
    <td>Verify IPv6 Host Discovery before adding intents</td>
    <td> </td>
    <td>1. Add 2 IPV6 hosts .
2. Check in the cli</td>
    <td>Command "hosts" should show IPV6 hosts.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_2</td>
    <td>Verify IPv6 Neighbor Solicitation message</td>
    <td> </td>
    <td>Send an ICMPv6 packet with type as 134. </td>
    <td>Neighbor should be advertised.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_3</td>
    <td>Verify IPv6 Neighbor Advertisement</td>
    <td> </td>
    <td>Send a NS message from the host and check for Neighbor advertisement message </td>
    <td>A value of 136 should be captured in the Type field of ICMP packet header. </td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_4</td>
    <td>Verify ICMP6 Ping </td>
    <td> </td>
    <td>Do an ICMPv6 ping from one host to another</td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_5</td>
    <td>Verify IPv6 Host Intent Addition</td>
    <td> </td>
    <td>1. Add point intents between 2 IPV6 hosts.
2. Check ping between the hosts </td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_6</td>
    <td>Verify Point Intent Addition matching on port numbers</td>
    <td> </td>
    <td>1. Add point intents between 2 IPV6 hosts matching on port numbers.
2. Check ping between the hosts </td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_7</td>
    <td>Verify Installing 300 host intents and verify ping all</td>
    <td> </td>
    <td>1. Add 300 point intents.
2. Ping all across all hosts to test connectivity</td>
    <td>1. 300 point intents should get successfully installed.
2. Ping should be successful. </td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_8</td>
    <td>Randomly bring some core links down and verify ping all</td>
    <td> </td>
    <td>1. Bring down the core links.
2. Check ping between the hosts.</td>
    <td>Even during link down state, connectivity still exists via reroute and ping should be successful. </td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_9</td>
    <td>Bring core links Up that were down and verify ping all</td>
    <td> </td>
    <td>1. Bring the links that were down to up.
2. Check ping between the hosts.</td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_10</td>
    <td>Verify Intents with VLAN-id</td>
    <td> </td>
    <td>1. Add point intents with vlan id .
2. Check hosts command in ONOS.
3. Verify ping between the hosts.</td>
    <td>2.“Hosts”command should discover correct vlan tag.
3. Ping should be successful.
 </td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_11</td>
    <td>Verify the INSTALLED state in intents</td>
    <td> </td>
    <td>Rewrite mac address action in multi point to single point intent.
Check the cli command “Intents “</td>
    <td> Intent's state should be INSTALLED</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_12</td>
    <td>Verify the ping after removing the intents between the hosts.</td>
    <td> </td>
    <td>1. Remove the previously added intents.
2. Check for ping between hosts.</td>
    <td>Ping should fail.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_13</td>
    <td>Verify Modify IPv6 Source Address</td>
    <td> </td>
    <td>1. Configure and connect the Primary-controller.
2. Create a flow with action OFPAT_SET_NW_SRC and output to an egress port.
3. Send matching packet to ingress port. </td>
    <td>packet gets output to egress port with correct IPv6 source address as specified in the flow.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_14</td>
    <td>Verify Modify IPv6 destination address</td>
    <td> </td>
    <td>1. Configure and connect the Primary-controller.
2. Create a flow with action OFPAT_SET_NW_DST and output to an egress port.
3. Send matching packet to ingress port. </td>
    <td>packet gets output to egress port with correct IPv6 destination address as specified in the flow</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_15</td>
    <td>Verify ping between the IPV6 hosts where muti point to single point intent is added</td>
    <td> </td>
    <td>1. Add a multi point to single point intent related SDNIP matching on IP Prefix and rewriting the mac address.
2. Verify the ping </td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>IPV6_16</td>
    <td>Check the ping after adding bidirectional point intents </td>
    <td> </td>
    <td>1. Add a bidirectional point intents between 2 packet layer devices.
2. Verify the ping</td>
    <td>Ping should be successful.</td>
    <td> </td>
  </tr>
</table>


** **

** **

**Flows**

** **

**This is to verify that the flow subsystem is compiling flows correctly.**

**We use a packet generation tool called Scapy which allows us to construct a packet that is tailor made for each flow.**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Flows_1</td>
    <td>Add and verify flows with MAC selectors</td>
    <td>test_flow_mac</td>
    <td>1.Add flow with source and dest mac using REST API.
2. Send packet to verify if flows are correct</td>
    <td>Packet should get received according to flow.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_2</td>
    <td>Add and verify flows with IPv4 selectors</td>
    <td>test_flow_ip</td>
    <td>1. Add flow with source and dest ip using REST API.
2. Send packet to verify if flows are correct.</td>
    <td>Packet should get received according to flow.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_3</td>
    <td>Add and verify flows with TCP ports</td>
    <td>test_flow_tcp_port</td>
    <td>1.Add flow with source and dest tcp ports  using REST API.
2. Send packet to verify if flows are correct.</td>
    <td>Packet should get received according to flow.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_4</td>
    <td>Add and verify flows with UDP ports</td>
    <td>test_flow_udp_port</td>
    <td>1.Add flow with source and dest UDP ports  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packet should get received according to flow.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_5</td>
    <td>Add and verify 5 flows with constant dest mac</td>
    <td>test_5_flow_constant_dst_mac</td>
    <td>1.Add 5 flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_6</td>
    <td>Add and verify 500 flows with constant dest mac</td>
    <td>test_500_flow_constant_dst_mac</td>
    <td>1.Add 500 flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_7</td>
    <td>Add and verify 1k flows with constant dest mac</td>
    <td>test_1k_flow_constant_dst_mac</td>
    <td>1.Add 1k flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_8</td>
    <td>Add and verify 10k flows with constant dest mac</td>
    <td>test_10k_flow_constant_dst_mac</td>
    <td>1.Add 10k flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_9</td>
    <td>Add and verify 100k flows with constant dest mac</td>
    <td>test_100k_flow_constant_dst_mac</td>
    <td>1.Add 100k flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_10</td>
    <td>Add and verify 1000k flows with constant dest mac</td>
    <td>test_1000k_flow_constant_dst_mac</td>
    <td>1.Add 1000k flows with constant dest mac and varying src mac  using REST API.
2. Send a packet to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_11






</td>
    <td>Add and verify 500 flows with varying mac selectors</td>
    <td>test_500_flow_mac</td>
    <td>1.Add 500 flows with varying dest mac and src mac  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_12</td>
    <td>Add and verify 1k flows with varying mac selectors</td>
    <td>test_1k_flow_mac</td>
    <td>1.Add 1k flows with varying dest mac and src mac  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_13</td>
    <td>Add and verify 10k flows with varying mac selectors</td>
    <td>test_10k_flow_mac</td>
    <td>1.Add 10k flows with varying dest mac and src mac  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_14</td>
    <td>Add and verify 100k flows with varying mac selectors</td>
    <td>test_100k_flow_mac</td>
    <td>1.Add 100k flows with varying dest mac and src mac  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_15</td>
    <td>Add and verify 1000k flows with varying mac selectors</td>
    <td>test_1000k_flow_mac</td>
    <td>1.Add 1000k flows with varying dest mac and src mac  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_16</td>
    <td>Add and verify 500 flows with varying ip selectors</td>
    <td>test_500_flow_ip</td>
    <td>1.Add 500 flows with varying dest ip and src ip  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_17</td>
    <td>Add and verify 1k flows with varying ip selectors</td>
    <td>test_1k_flow_ip</td>
    <td>1. Add 1k flows with varying dest ip and src ip  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_18





</td>
    <td>Add and verify 10k flows with varying ip selectors</td>
    <td>test_10k_flow_ip</td>
    <td>1. Add 10k flows with varying dest ip and src ip  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_19</td>
    <td>Add and verify 100k flows with varying ip selectors</td>
    <td>test_100k_flow_ip</td>
    <td>1. Add 100k flows with varying dest ip and src ip  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_20</td>
    <td>Add and verify 1000k flows with varying ip selectors</td>
    <td>test_1000k_flow_ip</td>
    <td>1. Add 1000k flows with varying dest ip and src ip  using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_21</td>
    <td>Add and verify 500 flows with varying tcp ports</td>
    <td>test_500_flow_tcp_port</td>
    <td>1. Add 1000k flows with varying source and dest tcp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_22</td>
    <td>Add and verify 1k flows with varying tcp ports</td>
    <td>test_1k_flow_tcp_port</td>
    <td>1. Add 1k flows with varying source and dest tcp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_23</td>
    <td>Add and verify 10k flows with varying tcp ports</td>
    <td>test_10k_flow_tcp_port</td>
    <td>1. Add 10k flows with varying source and dest tcp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
</table>


<table>
  <tr>
    <td>Flows_24</td>
    <td>Add and verify 500 flows with varying udp ports</td>
    <td>test_500_flow_udp_port</td>
    <td>1. Add 500 flows with varying source and dest udp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_25</td>
    <td>Add and verify 1k flows with varying udp ports</td>
    <td>test_1k_flow_udp_port</td>
    <td>1. Add 1k flows with varying source and dest udp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_26</td>
    <td>Add and verify 10k flows with varying udp ports</td>
    <td>test_10k_flow_udp_port</td>
    <td>1. Add 10k flows with varying source and dest udp ports using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_27</td>
    <td>Add and verify flow with dscp values</td>
    <td>test_flow_dscp</td>
    <td>1. Add flow with dscp value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_28</td>
    <td>Add and verify flows with all possible dscp values</td>
    <td>test_flow_available_dscp</td>
    <td>1. Add flows with all possible dscp values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_29</td>
    <td>Add and verify flow with ecn values</td>
    <td>test_flow_ecn</td>
    <td>1. Add flow with ecn value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_30</td>
    <td>Add and verify flow with all tos values</td>
    <td>test_flow_available_dscp_and_ecn</td>
    <td>1. Add flows with all possible tos values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_31</td>
    <td>Add and verify flow for icmpv4 values</td>
    <td>test_flow_icmp</td>
    <td>1. Add flows with icmpv4 values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_32</td>
    <td>Add and verify flow for different icmpv4 values</td>
    <td>test_flow_icmp_different_types</td>
    <td>1. Add flows with different icmpv4 values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_33</td>
    <td>Add and verify flow for ipv6 selectors</td>
    <td>test_flow_ipv6</td>
    <td>1. Add flows with ipv6 using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_34</td>
    <td>Add and verify flow for ipv6 and icmpv6 selectors</td>
    <td>test_flow_ipv6_and_icmpv6</td>
    <td>1. Add flows with ipv6 and icmpv6 values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
</table>


<table>
  <tr>
    <td>Flows_35</td>
    <td>Add and verify flow for ipv6 extension header</td>
    <td>test_flow_ipv6_extension_header</td>
    <td>1. Add flows with ipv6 extension header values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_36</td>
    <td>Add and verify flow for all available ipv6 extension header</td>
    <td>test_flow_ipv6_available_extension_headers</td>
    <td>1. Add flows with ipv6 all available extension header values using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_37</td>
    <td>Add and verify flow for ipv6 flow label</td>
    <td>test_flow_ipv6_flow_label</td>
    <td>1. Add flows with ipv6 flow label value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_38</td>
    <td>Add and verify flow for icmpv6 destination unreachable value</td>
    <td>test_flow_icmpv6_DestUnreachable</td>
    <td>1. Add flows with icmpv6 destination unreachable value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_39</td>
    <td>Add and verify flow for icmpv6 echo reply value</td>
    <td>test_flow_icmpv6_EchoReply</td>
    <td>1. Add flows with icmpv6 echo reply value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_40</td>
    <td>Add and verify flow for icmpv6 echo request value</td>
    <td>test_flow_icmpv6_EchoRequest</td>
    <td>1. Add flows with icmpv6 echo request value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
</table>


<table>
  <tr>
    <td>Flows_41</td>
    <td>Add and verify flow for icmpv6 packet too big value</td>
    <td>test_flow_icmpv6_PacketTooBig</td>
    <td>1. Add flows with icmpv6 packet too big value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_42</td>
    <td>Add and verify flow for icmpv6 parameter problem value</td>
    <td>test_flow_icmpv6_ParameterProblem</td>
    <td>1. Add flows  icmpv6 parameter problem value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_43</td>
    <td>Add and verify flow for icmpv6 time exceeded value</td>
    <td>test_flow_icmpv6_TimeExceeded</td>
    <td>1. Add flows with icmpv6 time exceeded value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_44</td>
    <td>Add and verify flow for ipv6 Neighbour Advertisement TLL value</td>
    <td>test_flow_icmpv6_NA_TLL</td>
    <td>1. Add flows with ipv6 Neighbour Advertisement TLL value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Flows_45</td>
    <td>Add and verify flow for ipv6 Neighbour Discovery SLL value</td>
    <td>test_flow_icmpv6_ND_SLL</td>
    <td>1. Add flows with ipv6 Neighbour Discovery SLL value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
</table>


<table>
  <tr>
    <td>Flows_46</td>
    <td>Add and verify flow for ipv6 Neighbour Discovery Target address value</td>
    <td>test_flow_icmpv6_ND_Target_address</td>
    <td>1. Add flows with ipv6 Neighbour Discovery Target address value using REST API.
2. Send packets to verify if flows are correct. </td>
    <td>Packets should get received according to flows.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
</table>


** **

**Metrics**

** **

**R****EST API is used for Collecting and Querying System Metrics.**

**1. Install CollectD plugin which is in charging of reporting all metric values to ONOS through REST API.**

**2. Install ONOS and activate CPMan application to receive system metrics from CollectD.**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Functio Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Metrics_1</td>
    <td>Collector- CPU metrics</td>
    <td> </td>
    <td>POST /collector/cpu_metrics</td>
    <td>Collects CPU metrics</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_2</td>
    <td>Collector- network I/O metrics</td>
    <td> </td>
    <td>POST /collector/network_metrics</td>
    <td>Collects network I/O metrics include in/out-bound packets/bytes statistics</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_3</td>
    <td>Collector-disk I/O metrics</td>
    <td> </td>
    <td>POST /collector/disk_metrics</td>
    <td>Collects disk I/O metrics include read and write bytes</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_4</td>
    <td>Collector-system info</td>
    <td> </td>
    <td>POST /collector/system_info</td>
    <td>Collects system information</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_5</td>
    <td>Collector-memory metrics</td>
    <td> </td>
    <td>POST /collector/memory_metrics</td>
    <td>Collects memory metrics</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_6</td>
    <td>Control-Memory metrics</td>
    <td> </td>
    <td>GET /controlmetrics/memory_metrics</td>
    <td>List memory metrics of all network resources</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_7</td>
    <td>Control-message metrics</td>
    <td> </td>
    <td>GET /controlmetrics/messages</td>
    <td>List control message metrics of all devices</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_8</td>
    <td>Control-message metrics</td>
    <td> </td>
    <td>GET /controlmetrics/messages/{deviceId}</td>
    <td>List control message metrics of a given device</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_9</td>
    <td>Control-CPU metrics</td>
    <td> </td>
    <td>GET /controlmetrics/cpu_metrics</td>
    <td>List CPU metrics</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_10</td>
    <td>Control-disk metrics</td>
    <td> </td>
    <td>GET /controlmetrics/disk_metrics</td>
    <td>List disk metrics of all disk resources</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_11</td>
    <td>Verify the intent installation latency</td>
    <td> </td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.                                      3.Install a single intent from the CLI
 </td>
    <td>Command :
onos:intents-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_12</td>
    <td>Verify the intent installation latency in JSON format</td>
    <td> </td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.
3. Install a single intent from the CLI</td>
    <td>Command :
onos:intents-events-metrics --json
Should show the information in json format.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_13</td>
    <td>Listing ONOS intent events</td>
    <td> </td>
    <td>onos> onos:intents-events</td>
    <td>It should list 100 intent related events.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_14</td>
    <td>Verify topology event metrics</td>
    <td> </td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_15</td>
    <td>Verify topology event metrics</td>
    <td> </td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics --json
Should show the information in json format.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Metrics_16</td>
    <td>Listing topology events</td>
    <td> </td>
    <td>onos> onos:topology-events</td>
    <td>This should list last 100 topology events.</td>
    <td> </td>
  </tr>
</table>


** **

** **

** **** **

**Platform tests**

** **

**Docker engine and docker.py should be installed on test host.**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Plat_1</td>
    <td>Verify the docker status</td>
    <td> </td>
    <td> </td>
    <td>If its running, docker status should return true. </td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_2</td>
    <td>Pull (default) "onosproject/onos:latest" image</td>
    <td> </td>
    <td> </td>
    <td>Pulling should be successful.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_3</td>
    <td>Create new container for onos</td>
    <td> </td>
    <td> </td>
    <td>Container should get successfully created.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_4</td>
    <td>Get IP address on ONOS containers</td>
    <td> </td>
    <td> </td>
    <td>Container IPs should get listed.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_5</td>
    <td>check standalone apps status</td>
    <td> </td>
    <td> </td>
    <td>"drivers" app should be in ACTIVE state AND all builtin apps in "INSTALLED" state</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_6</td>
    <td>Activate "proxyarp" and "fwd" apps and check apps status</td>
    <td> </td>
    <td> </td>
    <td>It should be in "ACTIVE" state</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_7</td>
    <td>Deactivate "proxyarp" and "fwd" apps and check app status</td>
    <td> </td>
    <td> </td>
    <td>It should be in "Installed" state</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_8</td>
    <td>ONOS exceptions check</td>
    <td> </td>
    <td> </td>
    <td>After test, there should be no logs for exceptions.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Plat_9</td>
    <td>post-test clean env</td>
    <td> </td>
    <td> </td>
    <td>No containers and images should be left.</td>
    <td> </td>
  </tr>
</table>


** **

** **

**Ovsdb**

** **

**Onos should be running well and Install feature ovsdb-web-provider ovsdb onos-core-netvirt on onos.**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>TestSteps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>OVSDB_1</td>
    <td>OVSDB connection setup and teardown</td>
    <td> </td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS.
2.Configure ovs-vsctl del-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS. </td>
    <td>1.OVSDB connection is up.
2.OVSDB connection is down.</td>
    <td> </td>
  </tr>
  <tr>
    <td>OVSDB_2</td>
    <td>Default configuration of bridge and vxlan install</td>
    <td> </td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1.
2.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1 and OVS2.</td>
    <td>1.OVS1 has an br_int.
2.OVS1 and OVS2 has br_int and vxlan tunnel.
3.ONOS devices add two sw.</td>
    <td> </td>
  </tr>
  <tr>
    <td>OVSDB_3</td>
    <td>OPENFLOW connection setup automatic</td>
    <td> </td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the Openflow connection on ONOS. </td>
    <td>OPENFLOW connection is up.</td>
    <td> </td>
  </tr>
  <tr>
    <td>OVSDB_4</td>
    <td>Default flow tables install</td>
    <td> </td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the default flow tables on OVS and ONOS.</td>
    <td>1.default flows is correct.</td>
    <td> </td>
  </tr>
  <tr>
    <td>OVSDB_5</td>
    <td>Simulation VM go online check flow tables install</td>
    <td> </td>
    <td>1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the flow tables on OVS and ONOS.
2.Create a port on OVS1.Check the flow tables on OVS and ONOS.
3.Create a port on OVS2.Check the flow tables on OVS and ONOS.
 </td>
    <td>1.OVS and ONOS have default flows.
2.OVS and ONOS add correct flows.
3.OVS and ONOS add correct flows. </td>
    <td> </td>
  </tr>
</table>


** **

**Netconf**

** **

**start ONOS and activate the netconf app**

** **

**netconf-cfg.json file ($ONOS_ROOT/tools/test/configs/netconf-cfg.json)**

**{**

**  "devices":{**

**    "netconf:<ip>:<port>":{**

**      "basic":{**

**        "driver": <driver-name>**

**      }**

**    }**

**  },**

**  "apps":{**

**    "org.onosproject.netconf":{**

**      "devices":[{**

**        "name":<username>,**

**        "password":<password>,**

**        "ip":<ip>,**

**        "port":<port>**

**      }]**

**    }**

**  }**

**}**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Netconf_1</td>
    <td>Check for devices in ONOS</td>
    <td> </td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
2.  onos> devices</td>
    <td>Devices should be present in ONOS.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netconf_2</td>
    <td>Verify the logs in ONOS</td>
    <td> </td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
 2. onos> devices.
3. Onos>logs</td>
    <td>logs shouldn't contain NETCONF related exceptions</td>
    <td> </td>
  </tr>
</table>


** **

** **

**Proxy ARP**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>PARP_1</td>
    <td>Verify if Proxy ARP is working properly with 1 host creation</td>
    <td>test_proxyarp_with_1_host </td>
    <td>Configure host and Interface configurations in ONOS
Send an ARP request to host IP</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_2</td>
    <td>Verify if Proxy ARP is working properly with 10 host creation</td>
    <td> test_proxyarp_with_10_hosts</td>
    <td>1. Configure host and Interface configurations in ONOS
2. Send an ARP request to all 10  host IPs</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_3</td>
    <td>Verify if Proxy ARP is working properly with 50 host creation</td>
    <td> test_proxyarp_with_50_hosts</td>
    <td>1. Configure host and Interface configurations in ONOS
2. Send an ARP request to all 50 host IPs.</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td>PASS </td>
  </tr>
  <tr>
    <td>PARP_4</td>
    <td>Verify if Proxy ARP is working properly when it disable and re-enabled</td>
    <td> test_proxyarp_app_with_disabling_and_re_enabling

</td>
    <td>1. Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Disable proxy-arp app in ONSO and send arp requests again </td>
    <td>Proxy Arp should not response once it disabled </td>
    <td> PASS</td>
  </tr>
  <tr>
    <td>PARP_5</td>
    <td>Verify if Proxy ARP is working properly for non-existing Host </td>
    <td>test_proxyarp_nonexisting_host</td>
    <td>1. Dont Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Now configure Host and Interface configurations in ONOS
4. Repeat step 2  </td>
    <td>Proxy Arp should not respond for arp requests sent to non-existing host IPs</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_6</td>
    <td>Verify if Proxy ARP is working properly for already existing host removed </td>
    <td>test_proxyarp_removing_host
</td>
    <td>1. Configure host and Interface configurations in ONOS
2.Send an ARP request
3. Now Remove Host configuration in ONOS
4. Repeat step 2  </td>
    <td>Proxy Arp should not respond to arp  requests once the host configuration removed </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_7</td>
    <td>Verify if Proxy ARP is working properly for multiple arp requests at once</td>
    <td>test_proxyarp_concurrent_requests_with_multiple_host_and_different_interfaces
</td>
    <td>1. Configure 10 host and Interface configurations in ONOS
2. Send an ARP request to all 10 host IPs from 10 ports at once</td>
    <td>Proxy should response to all 10 arp requests received at once</td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_8</td>
    <td>Verify if Proxy ARP is working properly when it disable and re-enabled in case of multiple requests at once</td>
    <td>test_proxyarp_disabling_enabling_app_initiating_concurrent_requests</td>
    <td>1. Configure 10 host and Interface configurations in ONOS
2.Send an ARP request to all 10 host IPs
3. Disable proxy-arp app in ONSO send arp requests again </td>
    <td>Proxy ARP should not respond once its disabled </td>
    <td>PASS</td>
  </tr>
  <tr>
    <td>PARP_9</td>
    <td>Verify if Proxy ARP is working properly in case of both existing and non-existing hosts </td>
    <td>test_proxyarp_with_existing_and_non_existing_hostIPs_initiating_concurrent_requests</td>
    <td>1. Configure 5 host and Interface configurations in ONOS
2.Send an ARP request for 10 host IPs
 </td>
    <td>Proxy ARP should respond to only existing Host IPs</td>
    <td>PASS</td>
  </tr>
</table>


**Network config link provider:**

** **

**The network config link provider allows specifying the link topology via the netcfg mechanism, and disallows any links that are not in the defined configuration.**

** **

**Here is an example of a configuration that defines a set of links in a topology:**

**Sample Config**

**{**

**    "links" : {**

**        "of:0000000000000001/1-of:0000000000000191/1" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000001/3-of:0000000000000192/1" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000002/1-of:0000000000000191/3" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000002/3-of:0000000000000192/3" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000191/1-of:0000000000000001/1" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000192/1-of:0000000000000001/3" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000191/3-of:0000000000000002/1" : {**

**            "basic" : {}**

**        },**

**        "of:0000000000000192/3-of:0000000000000002/3" : {**

**            "basic" : {}**

**        }**

**    },**

**    "apps" : {**

**        "org.onosproject.core" : {**

**            "core" : {**

**                "linkDiscoveryMode" : "STRICT"**

**            }   **

**        }**

**    }**

**}**

** **

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Netcfg_LP_1</td>
    <td>Check for the ACTIVE state of provider</td>
    <td> </td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow</td>
    <td>There should be traffic flow over the links which are configured in netcfg.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_LP_2</td>
    <td>Verify the STRICT state</td>
    <td> </td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow over the links which are not configured</td>
    <td>There should not be any traffic flow over the links which are configured in netcfg.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_LP_3</td>
    <td>Check for the error indication when source and destinat ion will not match</td>
    <td> </td>
    <td>Configure a link in netcfg and check for the error indication when source and destination doesnt match </td>
    <td>A  link is created with an error indication, which allows the GUI to display an error indication to the user</td>
    <td> </td>
  </tr>
</table>


** **

** **

**Network Configuration**

** **

**REST api are used to add/modify/delete and view network configurations in ONOS.**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Netcfg_1</td>
    <td>Uninstall, and install ONOS</td>
    <td> </td>
    <td> </td>
    <td>Installs and Uninstalls ONOS correctly</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_2</td>
    <td>check undiscovered device cfgs  are distributed to all nodes.
 </td>
    <td> </td>
    <td>Add some device configurations for undiscovered devices and then check they are distributed to all
nodes. </td>
    <td>The given NetCfgs should get added and distributed to all ONOS nodes</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_3</td>
    <td>Verify the Network Graph</td>
    <td> </td>
    <td>Check that devices appear or don't appear in the Network Graph according to the initial NetCfgs</td>
    <td>Allowed devices should appear and the disallowed devices shouldn’t appear in Network graph.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_4</td>
    <td>check discovered device cfgs  are distributed to all nodes</td>
    <td> </td>
    <td>Add some device configurations for discovered devices and then check they are distributed to all nodes.
 </td>
    <td>The given NetCfgs should get added and distributed to all ONOS nodes</td>
    <td> </td>
  </tr>
  <tr>
    <td>Netcfg_5</td>
    <td>Remove Network Configurations.</td>
    <td> </td>
    <td>Remove Network Configurations using different methods. I.E. delete a device, delete multiple devices, delete all configs</td>
    <td>The deleted NetCfgs should get deleted from all the nodes.</td>
    <td> </td>
  </tr>
</table>


** **

** **

**Reactive Routing**

** **

**Configure each gateway address together with each IP prefix in the configuration file "sdnip.json" which is located at onos/tools/package/config/sdnip.json.**

** **

** "ip4LocalPrefixes" : [**

**        {**

**                "ipPrefix" : "100.0.0.0/24",**

**                "type" : "PUBLIC",**

**                "gatewayIp" : "100.0.0.1"**

**        },**

**        {**

**                "ipPrefix" : "200.0.0.0/8",**

**                "type" : "PUBLIC",**

**                "gatewayIp" : "200.0.0.3"**

**        },**

**        {**

**                "ipPrefix" : "192.0.0.0/24",**

**                "type" : "PRIVATE",**

**                "gatewayIp" : "192.0.0.254"**

**        }**

**    ],**

**"virtualGatewayMacAddress" : "00:00:00:00:00:01"**

** **

**Activate the apps - "onos-app-sdnip" first, and then “onos-app-reactive-routing”  in ONOS.**

** **

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>RR_1</td>
    <td>Verify the traffic flow when both the hosts are in SDN network</td>
    <td> </td>
    <td>Configure 2 hosts to be in SDN network . Check the traffic flow</td>
    <td>There should be traffic flow between 2 hosts</td>
    <td> </td>
  </tr>
  <tr>
    <td>RR_2</td>
    <td>Verify the traffic flow from SDN host to internet host.</td>
    <td> </td>
    <td>Configure one host in SDN network and another host in internet.
Check the traffic flow</td>
    <td>There should be traffic flow from SDN network to internet</td>
    <td> </td>
  </tr>
  <tr>
    <td>RR_3</td>
    <td>Verify the traffic flow from internet host to SDN host.</td>
    <td> </td>
    <td>Configure one host in internet and another host in SDN network.
Check the traffic flow</td>
    <td>There should be a traffic flow from internet host to SDN network.</td>
    <td> </td>
  </tr>
  <tr>
    <td>RR_4</td>
    <td>Verify the traffic drop when there is no matchable ip prefix</td>
    <td> </td>
    <td>Send a traffic from one host to another host which is not matching with the file sdnip.json
 </td>
    <td>Packets should get dropped.</td>
    <td> </td>
  </tr>
</table>


**DHCPRelay**

** **

**Activate the DHCPRelay app**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>DHCPRelay_1</td>
    <td>Verify the dynamic ip address allocation of client</td>
    <td>test_dhcpRelay_1request</td>
    <td>Send a DHCP discover message from client</td>
    <td>All DHCP messages like DHCP discover, DHCP offer, DHCP request and DHCP Ack should be checked.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_2</td>
    <td>Verify DHCP NAK message from the server</td>
    <td> </td>
    <td>1. Configure pool lets say 20.0.0.1-20.0.0.10 in DHCP server.
2. Let client get the ip address
1. Disconnect this server and Connect another server with IP pool as 80.0.0.1-80.0.0.10
2. Let client send DHCP request message.</td>
    <td>When the client sends DHCPREQUEST it will ask for the previous ip address which is not present in pool so the server will send NAK.</td>
    <td>Not yet implemented</td>
  </tr>
  <tr>
    <td>DHCPRelay_3</td>
    <td>Verify releasing an IP from the client to the server to rediscover</td>
    <td>test_dhcpRelay_1release</td>
    <td>Send DHCP release packet from the client to the server</td>
    <td>IP address should get released back to the server and should be able to rediscover</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_4</td>
    <td>Multiple dhcp servers</td>
    <td> </td>
    <td>Let there be multiple DHCP servers.
Start a dhcp client from one host.</td>
    <td>IP address should get allocated to the host from one of the DHCP servers.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>
DHCPRelay_5</td>
    <td>
Verify DHCP decline message from the client</td>
    <td> test_dhcpRelay_1release</td>
    <td>
1. You need two clients. One static and one through DHCP server.
2. Try to first assign ip address to dhcp client, reboot the client or just remove it from network.
3. Meanwhile give the same static ip to another client.
4. Now connect the dhcp client.</td>
    <td>
When the server assigns the ip address the client will do gracious arp and as static ip is already present it will send DHCPDECLINE message to the Server.</td>
    <td>
Not implemented</td>
  </tr>
  <tr>
    <td>DHCPRelay_6</td>
    <td>Verify restarting the dhcp client</td>
    <td>test_dhcpRelay_client_request_after_reboot</td>
    <td>1. Restart the client which has got previously leased IP address.
2. Check for DHCP Ack message </td>
    <td>If the requested IP address can be used by the client, the DHCP server responds with a DHCPAck message.
   </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_7</td>
    <td>Verify multiple client scenario</td>
    <td>test_dhcpRelay_Nrequest</td>
    <td>Let there be multiple hosts and generate a multiple DHCP request messages</td>
    <td>Server should be able to give ip address to all the hosts.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_8




</td>
    <td>check for Fail over mechanism in dhcp</td>
    <td> </td>
    <td>Let there be 2 dhcp servers in the same subnet or scope.
Make one dhcp server down</td>
    <td>If a DHCP server1 is no longer reachable, then client is able to extend the lease on its current IP address by contacting another DHCP server2.</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHCPRelay_9</td>
    <td>Verify DHCP client renewing State</td>
    <td>test_dhcpRelay_client_renew_time</td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server</td>
    <td>Since the server is up and reachable , it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_10</td>
    <td>Verify the client behavior when DHCP server is rebooted.</td>
    <td>test_dhcpRelay_server_after_reboot</td>
    <td>1. Send a DHCP discover packet .
2. Send a DHCP request packet from the client.
3. Make the DHCP server down.
4. Make the DHCP server up.</td>
    <td>1. DHCP offer packet generated.
2. DHCP Ack packet generated.
3. Client should have the same ip till the lease time expires.
4. DHCP Ack should be sent from the server. </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_11</td>
    <td>Verify generation of DHCP inform message</td>
    <td>test_dhcpRelay_inform_packet</td>
    <td>1. Let client send a DHCP inform message with its own ip address in ciaddr field.
2. Check for DHCP ACk message</td>
    <td>DHCP Ack message should be sent from the server which includes the needed parameters in the appropriate DHCP option fields</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>DHCPRelay_12</td>
    <td>DHCP starvation attack</td>
    <td>test_dhcpRelay_starvation</td>
    <td>Send a lot of dummy DHCP requests, with random source Mac address (using Scapy)</td>
    <td>After few second, there is no more IP addresses available in the pool, thus successfully performing denial of service attack to other network client.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_13

</td>
    <td>Verify DHCP Relay functionality</td>
    <td> </td>
    <td>Make ONOS as DHCP relay agent and Send a DHCP discover message from the client. This inserts the option 82.</td>
    <td>ONOS should forward the DHCP server reply to the client</td>
    <td>Not implemented</td>
  </tr>
  <tr>
    <td>DHCPRelay_14</td>
    <td>Verify sending DHCP discover packet twice</td>
    <td>test_dhcpRelay_same_client_multiple_discover</td>
    <td>Send DHCP discover packet twice from the client.</td>
    <td>DHCP server should give the same ip to the client.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_15</td>
    <td>Verify sending DHCP request packet twice</td>
    <td>test_dhcpRelay_same_client_multiple_request</td>
    <td>Send the DHCP request packet twice form the client</td>
    <td>DHCP Ack should be sent.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_16</td>
    <td>Verify ip address assignment when dhcp request and offer ip are different </td>
    <td>test_dhcpRelay_server_nak_packet</td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message with a different ip.
 </td>
    <td>1. DHCP offer should be sent from server.
2. DHCP NAK should be sent from the server.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_17</td>
    <td>Verify  ip address assignment is successful when desired ip is sent.</td>
    <td>test_dhcpRelay_client_desired_address</td>
    <td>Send a DHCP discover packet with the desired ip which is in the server address pool.
 </td>
    <td>DHCP ip address assignment should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_18</td>
    <td>Verify  ip address assignment when desired ip is sent which is out of the pool.</td>
    <td>test_dhcpRelay_client_desired_address_out_of_pool</td>
    <td>Send a DHCP discover packet with the desired ip which is out of the  server address pool.
 </td>
    <td>DHCP NAK message should be sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_19</td>
    <td>Verify  ip address assignment with the lease time information specified.</td>
    <td>test_dhcpRelay_lease_packet</td>
    <td>Send a DHCP discover packet with the least time mentioned.</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>DHCPRelay_20
</td>
    <td>Verify sending N releases from the client </td>
    <td>test_dhcpRelay_Nrelease
</td>
    <td>Send multiple DHCP release packet from the client to the server</td>
    <td>All IP addresses should get released back to the server and should be able to rediscover

</td>
    <td>Pass

</td>
  </tr>
  <tr>
    <td>DHCPRelay_21</td>
    <td>Verify broadcast address in dhcp offer</td>
    <td>test_dhcpRelay_client_expected_broadcast_address </td>
    <td>1. Send DHCP discover message.
2. Extract option broadcast address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Broadcast address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_22



</td>
    <td>Verify dns address in dhcp offer</td>
    <td>test_dhcpRelay_client_expected_dns_address </td>
    <td>1. Send DHCP discover message.
2. Extract option dns address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Dns address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DCPRelay_23</td>
    <td>Verify router address in dhcp offer</td>
    <td>test_dhcpRelay_client_expected_router_address </td>
    <td>1. Send DHCP discover message.
2. Extract option router address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Router address should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_24</td>
    <td>Verify Subnet mask in dhcp offer</td>
    <td>test_dhcpRelay_client_expected_subnet_mask </td>
    <td>1.Send DHCP discover message.
2.Extract option Subnet mask from dhcp offer message.
3.Check with your server configuration</td>
    <td>Subnet mask should match</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_25</td>
    <td>Verify sending dhcp discover with wrong broadcast address</td>
    <td>test_dhcpRelay_client_sends_dhcp_request_with_wrong_broadcast_address </td>
    <td>1. Send DHCP discover message with wrong broadcast address.
2. Extract option Broadcast address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration broadcast address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_26







</td>
    <td>Verify sending dhcp discover with wrong DNS address</td>
    <td>test_dhcpRelay_client_sends_dhcp_request_with_wrong_dns_address </td>
    <td>1. Send DHCP discover message with wrong dns address.
2. Extract option DNS server from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration DNS address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_27</td>
    <td>Verify sending dhcp discover with wrong router address</td>
    <td>test_dhcpRelay_client_sends_dhcp_request_with_wrong_router_address </td>
    <td>1. Send DHCP discover message with wrong router address.
2. Extract option router address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration Router address should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_28</td>
    <td>Verify sending dhcp discover with wrong Subnet mask address</td>
    <td>test_dhcpRelay_client_sends_dhcp_request_with_wrong_subnet_mask </td>
    <td>1. Send DHCP discover message with wrong Subnet mask.
2. Extract option Subnet mask address from dhcp offer message.
3. Check with your server configuration</td>
    <td>Server configuration Subnet mask should be seen in dhcp offer</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_29</td>
    <td>Verify dhcp client renew process</td>
    <td>test_dhcpRelay_client_renew_time </td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server</td>
    <td>Since the server is up and reachable, it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_30
</td>
    <td>Verify dhcp client rebind process</td>
    <td>test_dhcpRelay_client_rebind_time </td>
    <td>After Rebind timer expires, a DHCP request message which is broadcast is being sent.</td>
    <td>Since the server is up and reachable, it should respond back with DHCP Ack packet</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_31</td>
    <td>Verify lease time check</td>
    <td>test_dhcpRelay_lease_packet</td>
    <td>1. Send DHCP discover message.
2. Send DHCP request now.
3. Extract the option lease time in DHCP ACK packet.</td>
    <td>1. DHCP offer should be received.
2. DHCP Ack packet should be received with the default lease time of 600 sec.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_32</td>
    <td>Measure average no. of transactions in DHCP server in 1 second</td>
    <td>test_dhcpRelay_server_transactions_per_second </td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses.
2. Calculate total running time and total no. of transactions after repeating the procedure for 3 times.
3. Divide total no. of transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_33













</td>
    <td>Measure average no. of consecutive successful  transactions in DHCP server in 1 second</td>
    <td>test_dhcpRelay_server_consecutive_successes_per_second</td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses.
2. Calculate total running time and total no. of successful transactions after repeating the procedure for 3 times.
3. Divide total no. of successful transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_34</td>
    <td>Measure average number of clients (DHCP discover) in 1 second</td>
    <td>test_dhcpRelay_server_clients_per_second </td>
    <td>1. Send DHCP discover packets continuously from different mac address.
 2.Calculate total running time and total no. Of clients after repeating the procedure for 3 times.
3. Divide total no. of clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_35










</td>
    <td>Measure average no. of consecutive successful  clients in DHCP server in 1 second</td>
    <td>test_dhcpRelay_server_consecutive_successful_clients_per_second</td>
    <td>1. Send DHCP discover packets continuously from different mac address.
 2.Calculate total running time and total no. Of successful clients after repeating the procedure for 3 times.
3. Divide total no. Of successful clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass







</td>
  </tr>
</table>


<table>
  <tr>
    <td>DHCPRelay_36</td>
    <td>Measure average no. Of concurrent transactions in DHCP server in 1 second</td>
    <td>test_dhcpRelay_concurrent_transactions_per_second</td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses using Multithreading Programming Enviornment.
2. Calculate total running time and total no. of transactions after repeating the procedure for 3 times.
3. Divide total no. of transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_37













</td>
    <td>Measure average no. Of concurrent consecutive successful  transactions in DHCP server in 1 second</td>
    <td>test_dhcpRelay_concurrent_consecutive_successes_per_second</td>
    <td>1. Send DHCP discover and DHCP request messages from different MAC addresses using Multithreading Programming Enviornment.
2. Calculate total running time and total no. of successful transactions after repeating the procedure for 3 times.
3. Divide total no. of successful transactions with total running time.</td>
    <td>1. DHCP offer and DHCP Ack should be received until there are free addresses in pool of DHCP server.
 </td>
    <td>Pass</td>
  </tr>
</table>


<table>
  <tr>
    <td>DHCPRelay_38</td>
    <td>Measure average number of concurrent clients (DHCP discover) in 1 second</td>
    <td>test_dhcpRelay_concurrent_clients_per_second</td>
    <td>1. Send DHCP discover packets continuously from different mac address using Multithreading Programming Enviornment.
 2.Calculate total running time and total no. Of clients after repeating the procedure for 3 times.
3. Divide total no. of clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCPRelay_39










</td>
    <td>Measure average no. of consecutive successful concurrent clients in DHCP server in 1 second</td>
    <td>test_dhcpRelay_concurrent_consecutive_successes_per_second</td>
    <td>1. Send DHCP discover packets continuously from different mac address using Multithreading Programming Enviornment.
 2.Calculate total running time and total no. Of successful clients after repeating the procedure for 3 times.
3. Divide total no. Of successful clients with total running time.</td>
    <td>DHCP offer should be received until DHCP server pool ip address are exhausted.</td>
    <td>Pass







</td>
  </tr>
</table>


<table>
  <tr>
    <td>DHCPRelay_40










</td>
    <td>Verify 2 DHCP clients conflict Scenario</td>
    <td>test_dhcpRelay_client_conflict</td>
    <td>1. Send DHCP discover packet from one DHCP client.
 2.Extract ip from DHCP offer packet
3. Send DHCP Discover from 2nd DHCP client with extracted ip as desired ip. Then also send DHCP Request.
4.  Now send DHCP Request from 1st DHCP client.  </td>
    <td>No Reply from DHCP Server.</td>
    <td>Pass







</td>
  </tr>
</table>


**Cluster :**

Onos cluster is multi-instance of ONOS deployment.

Each device connected to clustrer, has a master to controller the device.

Each Onos instance in a cluster, can be its state ‘None’, ‘Standby’, or ‘Master’ to a connected device.

<table>
  <tr>
    <td>	ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>cluster_1</td>
    <td>Verify if cluster exists with provided no.of ONOS instances</td>
    <td>test_onos_cluster_formation_verify</td>
    <td>Execute ‘summary’ command on ONOS cli and grep no.of nodes value to verify cluster formation</td>
    <td>If cluster already exists, test case should pass else Fail</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_2</td>
    <td>Verify adding additional ONOS instances to already existing cluster</td>
    <td> test_onos_cluster_adding_members</td>
    <td>1. Verify if cluster already exists
2. Add few more ONOS instances to the cluster.</td>
    <td>A new cluster with added ONOS instances should come up without restarting existing cluster</td>
    <td>Not tested due issues in cluster</td>
  </tr>
  <tr>
    <td>cluster_3</td>
    <td>Verify cluster status if cluster master instance removed </td>
    <td>test_onos_cluster_remove_master</td>
    <td>verify if cluster already exists.
Grep cluster current master instance
Remove master instance ONOS container </td>
    <td>Cluster with one instance less and new mater elected</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_4</td>
    <td>Verify cluster status if one member goes down</td>
    <td> test_onos_cluster_remove_one_member</td>
    <td>Verify if cluster exists.
Grep one of the member ONOS instance
Kill the member container </td>
    <td>Cluster with one member less and with same master should come up</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>
cluster_5</td>
    <td>
Verify cluster status if two member goes down</td>
    <td> test_onos_cluster_remove_two_members</td>
    <td>1. Verify if cluster exists.
2. Grep two of the member ONOS instances
Kill the member containers</td>
    <td>
Cluster with two member less and with  same master should come up</td>
    <td>Pass
</td>
  </tr>
  <tr>
    <td>cluster_6</td>
    <td>Verify cluster status if N member instances goes down</td>
    <td>test_onos_cluster_remove_N_members</td>
    <td>1. Verify if cluster exists .
2. Grep and kill N no.of member ONOS instances  </td>
    <td>Cluster with N instances less and same master should come up.
   </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_7</td>
    <td>Verify cluster if few ONOS instances added and removed  </td>
    <td>test_onos_cluster_add_remove_members</td>
    <td>verify if cluster exists
Add few instances to cluster
Remove the added instances
</td>
    <td>Cluster should be stable before and after addition and deletion of member instances </td>
    <td>Not tested due to cluster issues</td>
  </tr>
  <tr>
    <td>cluster_8




</td>
    <td>Verify cluster status if few instances removed and added </td>
    <td> test_onos_cluster_remove_add_member</td>
    <td>verify if cluster exists
Removed few member instances
Add back the same instances </td>
    <td>Cluster should be stable in each stage</td>
    <td>Not tested due to cluster issues</td>
  </tr>
  <tr>
    <td>cluster_9</td>
    <td>Verify cluster status after entire cluster restart </td>
    <td>test_onos_cluster_restart</td>
    <td>verify if cluster exists
Restart entire cluster</td>
    <td>Cluster should come up with as it is ( master may change )</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_10</td>
    <td>Verify cluster status if  current master restarts.</td>
    <td>test_onos_cluster_master_restart</td>
    <td>Verify cluster exists
Restart current master instance container </td>
    <td>Cluster master restart should success
Cluster with same no.of instances should come up</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_11</td>
    <td>Verify master IP if current master restarts </td>
    <td>test_onos_cluster_master_ip_after_master_restart</td>
    <td>Verify if cluster exists
Restart current master ONOS instance </td>
    <td>cluster with new master should come up</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_12</td>
    <td>Verify cluster status if one member restarts </td>
    <td>test_onos_cluster_one_member_restart</td>
    <td>verify if cluster exists
Grep one of member ONOS instance
Restart  the instance </td>
    <td>Cluster should come up with same master </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_13

</td>
    <td>Verify cluster status if two members restarts </td>
    <td>test_onos_cluster_two_members_restart</td>
    <td>Verify  if cluster exists
Grep two member instances restart the ONOS containers </td>
    <td>Cluster should come up without changing master</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_14</td>
    <td>Verify cluster status if N members restarts </td>
    <td>test_onos_cluster_N_members_restart</td>
    <td>Verify if cluster exists
Grep N no.od ONOS instances and restart  containers </td>
    <td>Cluster should come with same master </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_15</td>
    <td>Verify cluster master can be changed </td>
    <td>test_onos_cluster_master_change</td>
    <td>1.verify if cluster exists with a master
2. using ONOS cli change cluster master to other than existed</td>
    <td>Cluster master should be changed to new master</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_16</td>
    <td>Verify if cluster current master withdraw it mastership </td>
    <td>test_onos_cluster_withdraw_cluster_current_mastership</td>
    <td>1. verify if cluster exists with a master
2. using ONOS cli change cluster master by making current master an none to device
 </td>
    <td>Cluster master should changed to new master</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_17</td>
    <td>Verify routes pushed from Quagga to cluster master distributed to all cluster members</td>
    <td>test_onos_cluster_vrouter_routes_in_cluster_members</td>
    <td>1.verify if cluster exists
2. push few routes from quagga to cluster master
3. verify master has routes
 </td>
    <td>All cluster member should receive the route information </td>
    <td>Not tested due to cluster issues</td>
  </tr>
  <tr>
    <td>cluster_18</td>
    <td>Verify vrouter functionality works fine even if cluster master goes down</td>
    <td>test_onos_cluster_vrouter_master_down</td>
    <td>1.verify if cluster exists
2.push few routes from quagga to onos cluster
3.send traffic to above routes
4. kill cluster master instance container
 </td>
    <td>Verify traffic forwards to routes even after cluster master goes down
</td>
    <td>Not tested due to cluster issues</td>
  </tr>
  <tr>
    <td>cluster_19</td>
    <td>Verify vrouter functionality works fine even if cluster master restarts</td>
    <td>test_onos_cluster_vrouter_master_restarts</td>
    <td>1.verify if cluster exists
2.push few routes from quagga to onos cluster
3.send traffic to above routes
4. restarts cluster master instance container
</td>
    <td>Verify traffic forwards to routes even after cluster master restarts
</td>
    <td>Not tested due to cluster issues</td>
  </tr>
  <tr>
    <td>cluster_20
</td>
    <td>Verify vrouter functionality when vrouter app deactivated on cluster</td>
    <td>test_onos_cluster_vrouter_app_deactivate
</td>
    <td>1.verify cluster exists
2.verify vrouter functionality
3.deactivate vrouter app in onos cluster master instance</td>
    <td>Traffic should not received to routes after the app deactivates

</td>
    <td>Not tested due to cluster issues

</td>
  </tr>
  <tr>
    <td>cluster_21</td>
    <td>Verify vrouter functionality works fine when vrouter app deactivated and cluster master goes down</td>
    <td>test_onos_cluster_vrouter_app_deactivate_master_down</td>
    <td>1.verify if cluster exists
2.verify vrouter works fine
3.deactivate vrouter app and kill master onos instance container</td>
    <td>Vrouter functionality should not work after app deactivate </td>
    <td>Not tested due to cluster issues
</td>
  </tr>
  <tr>
    <td>cluster_22



</td>
    <td>Verify vrouter functionality works fine even if cluster member goes down</td>
    <td>test_onos_cluster_vrouter_member_down</td>
    <td>1.verify if cluster exists
2.push few routes from quagga to onos cluster
3.send traffic to above routes
4. kill cluster member instance container
</td>
    <td>Verify traffic forwards to routes even after cluster member goes down
</td>
    <td>Not tested due to cluster issues
</td>
  </tr>
  <tr>
    <td>cluster_23</td>
    <td>Verify vrouter functionality works fine even if cluster member restarts</td>
    <td>test_onos_cluster_vrouter_member_restart</td>
    <td>1.verify if cluster exists
2.push few routes from quagga to onos cluster
3.send traffic to above routes
4. restart cluster member instance container
</td>
    <td>Verify traffic forwards to routes even after cluster member restarts
</td>
    <td>Not tested due to cluster issues
</td>
  </tr>
  <tr>
    <td>cluster_24</td>
    <td>Verify vrouter functionality works fine even if cluster restarts</td>
    <td>test_onos_cluster_vrouter_cluster_restart</td>
    <td>1.verify if cluster exists
2.push few routes from quagga to onos cluster
3.send traffic to above routes
4. restart cluster
</td>
    <td>traffic should forwards to routes even after cluster restarts
</td>
    <td>Not tested due to cluster issues
</td>
  </tr>
  <tr>
    <td>cluster_25</td>
    <td>Verify flows works fine on cluster even if cluster master goes down</td>
    <td>test_onos_cluster_flow_master_down_flow_udp_port </td>
    <td>1.push a flow to onos cluster master
2.verify traffic forwards to as per flow
3. now kill cluster master onos instance container</td>
    <td>Flow traffic should forward properly as per flow added even after master goes down</td>
    <td>Fail
( flow state is ‘pending_added’ in ONOS)</td>
  </tr>
  <tr>
    <td>cluster_26







</td>
    <td>Verify flows works fine on cluster even if cluster master change</td>
    <td>test_cluster_flow_master_change_flow_ecn</td>
    <td>1.push a flow to onos cluster master
2.verify traffic forwards to as per flow
3. now change cluster master </td>
    <td>Flow traffic should forward properly as per flow added even after master changes</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_27</td>
    <td>Verify flows works fine on cluster even if cluster master restarts</td>
    <td>test_cluster_flow_master_restart_ipv6_extension_header</td>
    <td>1.push a flow to onos cluster master
2.verify traffic forwards to as per flow
3. now restart cluster master</td>
    <td>Flow traffic should forward properly as per flow added even after master restarts</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_28</td>
    <td>Verify igmp include and exclude modes with cluster master restarts </td>
    <td>test_onos_cluster_igmp_include_exclude_modes_master_restart</td>
    <td>1.verify if cluster exists
2.verify cluster include and excludes works fine
3. restart cluster master</td>
    <td>Igmp include and exclude modes should work properly before and after cluster master restarts </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_29</td>
    <td>Verify igmp include and exclude modes with cluster master goes down</td>
    <td>test_onos_cluster_igmp_include_exclude_modes_master_down </td>
    <td>1.verify if cluster exists
2.verify cluster include and excludes works fine
3. Kill onos cluster master instance container </td>
    <td>Igmp include and exclude modes should work properly before and after cluster master goes down</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_30
</td>
    <td>Verify igmp data traffic recovery time when master goes down</td>
    <td>test_onos_cluster_igmp_include_calculate_traffic_recovery_time_after_master_down</td>
    <td>Verify if cluster exists
Keep sending igmp include and verify traffic
Now kill cluster master onos instance container</td>
    <td>Calculate time to recover igmp data traffic after master goes down</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>cluster_31</td>
    <td>Verify Igmp leave after master change</td>
    <td>test_onos_cluster_igmp_leave_group_after_master_change</td>
    <td>Verify if cluster exists
Send igmp include mode and verify traffic
Change cluster master
Send igmp leave now</td>
    <td>New master should process igmp leave and traffic should not receive after sending leave</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_32</td>
    <td>Verify igmp join and traffic with cluster master changing</td>
    <td>test_onos_cluster_igmp_join_after_master_change_traffic_after_master_change_again</td>
    <td>Verify if cluster exists
Send igmp include mode
Change cluster master now
Send data traffic above registered igmp group</td>
    <td>Igmp data traffic should receive to client
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_33













</td>
    <td>Verify eap tls authentication on cluster setup</td>
    <td>test_onos_cluster_eap_tls</td>
    <td>verify if cluster exists
Configure radius server ip in onos cluster master
Initiate eap tls authentication process from client side</td>
    <td>Client should get authenticated for valid certificate
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_34</td>
    <td>Verify eap tls authentication before and after cluster master change</td>
    <td>test_onos_cluster_eap_tls_before_and_after_master_change</td>
    <td>Verify if cluster exists
Verify eap tls authentication process
Change cluster master
Initiate eap tls authentication process again</td>
    <td>Authentication should get success before and after cluster master change</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_35










</td>
    <td>Verify eap tls authentication before and after cluster master goes down</td>
    <td>test_onos_cluster_eap_tls_before_and_after_master_down</td>
    <td>1. Verify if cluster exists
2. Verify eap tls authentication process
3. Kill cluster master onos instance container
4. Initiate eap tls authentication process again</td>
    <td>Authentication should get success before and after cluster master goes down</td>
    <td>Pass







</td>
  </tr>
  <tr>
    <td>cluster_36</td>
    <td>Verify eap tls authentication with no certificate and master restarts </td>
    <td>test_onos_cluster_eap_tls_with_no_cert_before_and_after_member_restart</td>
    <td>verify if cluster exists
Verify eap tls authentication fail with no certificates
Restart master and repeat step 2</td>
    <td>Authentication should get fail before and after cluster master restart</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_37</td>
    <td>Verify proxy arp functionality on cluster setup before and after the app deactivate</td>
    <td>test_onos_cluster_proxyarp_master_change_and_app_deactivate</td>
    <td>verify if cluster exists
Verify proxy arp functionality
Deactivate the app on cluster master
Verify proxy apr functionality again </td>
    <td>Proxy arp functionality should work before app deactivate </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_38</td>
    <td>Verify proxyarp functionality on cluster before and after on member goes down</td>
    <td>test_onos_cluster_proxyarp_one_member_down</td>
    <td>Verify if cluster exists
Verify if proxyarp works fine on cluster setup
Kill one of cluster member onos instance container
Verify proxyarp functionality now </td>
    <td>Proxy arp functionality should before and after cluster member goes down</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_39</td>
    <td>Verify proxyarp functionality with concurrent requests on cluster setup</td>
    <td>test_onos_cluster_proxyarp_concurrent_requests_with_multiple_host_and_different_interfaces</td>
    <td>verify if cluster exists
Create multiple interfaces and hosts on OvS
Initiate multiple proxy arp requests in parallel</td>
    <td>Cluster should be stable for multiple arp requests in parallel and arp replies should receive for all  requests</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_40</td>
    <td>Verify acl rule addition and remove before and after cluster master change</td>
    <td>test_onos_cluster_add_acl_rule_before_master_change_remove_acl_rule_after_master_change</td>
    <td>Verify if cluster exists
Add an acl rule in onos cluster master
Change cluster master
Remove the acl rule in new cluster master</td>
    <td>Should be able to remove acl in new cluster master </td>
    <td>
Pass</td>
  </tr>
  <tr>
    <td>cluster_41</td>
    <td>Verify if acl traffic works fine before and after cluster members goes down</td>
    <td>test_onos_cluster_acl_traffic_before_and_after_two_members_down</td>
    <td>Add an acl rule
Send traffic to match above rule
Kill two onos cluster instance containers
Send acl traffic again

	</td>
    <td>Acl traffic should receive on interface before and after cluster members goes down</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_42</td>
    <td>Verify dhcp relay release on cluster new master </td>
    <td>test_onos_cluster_dhcpRelay_release_dhcp_ip_after_master_change</td>
    <td>Verify if cluster exists
Initiate dhcp discover and get an ip address from server
Change cluster master
Send dhcp  release to release the leased ip</td>
    <td>New master should be able to process dhcp release packet and send to server </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_43</td>
    <td>Verify client gets same dhcp ip after cluster master goes down</td>
    <td>test_onos_cluster_dhcpRelay_verify_dhcp_ip_after_master_down</td>
    <td>Verify if cluster exists
Initiate dhcp process and get ip from  server
Kill cluster master onos instance container
Send dhcp request from client to verify if same ip gets </td>
    <td>Client should receive same ip after cluster master goes down </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_44</td>
    <td>Verify simulating dhcp clients by changing cluster master</td>
    <td>test_onos_cluster_dhcpRelay_simulate_client_by_changing_master</td>
    <td>verify if cluster exists
Simulate dhcp client-1
Change cluster master
Simulate client-2
Change cluster master again
Simulate one more client-3</td>
    <td>All the clients should get valid ip from cluster irrespective cluster change</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Cluster_45</td>
    <td>Verify cord_subscriber functionality works before and after cluster restarts</td>
    <td>test_onos_cluster_cord_subscriber_join_next_before_and_after_cluster_restart</td>
    <td>Verify if cluster exists
Verify cord_subscriber functionality works
Restart cluster
Repeat step 2 </td>
    <td>Cord_subscriber should work properly before and after cluster restarts
</td>
    <td>Not Tested because of cluster issues </td>
  </tr>
  <tr>
    <td>cluster_46</td>
    <td>Verify cord_subscriber on 10 channels when cluster member goes down</td>
    <td>test_onos_cluster_cord_subscriber_join_recv_10channels_one_cluster_member_down</td>
    <td>verify if cluster exists
Verify cord_subscriber on 10 channels
Kill one of the cluster member onos instance container
Repeat step 2</td>
    <td>Cord_subscriber functionality should work properly even after cluster member goes down</td>
    <td>Not Tested because of cluster issues</td>
  </tr>
  <tr>
    <td>cluster_47</td>
    <td>Verify cord_subscriber on 10 channels when cluster members goes down</td>
    <td>test_onos_cluster_cord_subscriber_join_next_10channels_two_cluster_members_down</td>
    <td>1. verify if cluster exists
2.Verify cord_subscriber on 10 channels
3.Kill two of the cluster member onos instance containers
4. Repeat step 2</td>
    <td>Cord_subscriber functionality should work properly even after cluster member s goes down</td>
    <td>Not Tested because of cluster issues</td>
  </tr>
  <tr>
    <td>cluster_48</td>
    <td>Verify multiple devices connected to cluster setup </td>
    <td>test_onos_cluster_multiple_ovs_switches</td>
    <td>verify if cluster exists
Connect multiple devices to cluster setup</td>
    <td>Verify if all the devices connected to onos cluster setup and each device has master elected
</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_49</td>
    <td>Verify multiple devices connected to cluster setup </td>
    <td>test_onos_cluster_verify_multiple_ovs_switches_in_cluster_instances</td>
    <td>1. verify if cluster exists
2. Connect multiple devices to cluster setup</td>
    <td>Each every cluster member should has information all the devices connected to cluster setup</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_50</td>
    <td>Verify multiple switches connected to cluster setup</td>
    <td>test_onos_cluster_verify_multiple_ovs_switches_master_restart</td>
    <td>verify if cluster exists
Connect multiple devices  to cluster setup
Verify devices information in cluster members
Restart master of a device </td>
    <td>When master of a device restarts, new master should elected for that device</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_51</td>
    <td>Verify multiple switches connected to cluster setup</td>
    <td>test_onos_cluster_verify_multiple_ovs_switches_one_master_down</td>
    <td>1.verify if cluster exists
2. Connect multiple devices  to cluster setup
3. Verify devices information in cluster members
4. Kill cluster onos master of a device</td>
    <td>When master of a device goes down, new master should elected for that device</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_52</td>
    <td>Verify multiple switches connected to cluster setup</td>
    <td>test_onos_cluster_verify_multiple_ovs_switches_current_master_withdraw_mastership</td>
    <td>1.verify if cluster exists
2. Connect multiple devices  to cluster setup
3. Verify devices information in cluster members
4. Withdraw cluster onos mastership of a device</td>
    <td>When master of a device withdraws mastership, new master should elected for that device</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_53</td>
    <td>Verify multiple switches connected to cluster setup</td>
    <td>test_onos_cluster_verify_multiple_ovs_switches_cluster_restart</td>
    <td>1. verify if cluster exists
2. Connect multiple devices  to cluster setup
3. Verify devices information in cluster members
4. Restart entire cluster</td>
    <td>All the device information should appear in onos instances after cluster restart.masters may change</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>cluster_54</td>
    <td>Verify cord_subscriber functionality when cluster master withdraw its mastership</td>
    <td>test_onos_cluster_cord_subscriber_join_next_before_and_after_cluster_mastership_withdraw</td>
    <td>Verify if cluster exists
Verify cord-subscriber functionality
Withdraw cluster master
Repeat step 2</td>
    <td>Cord subscriber functionality should work properly before and after cluster master change</td>
    <td>Pass</td>
  </tr>
</table>


**XOS:**

<table>
  <tr>
    <td>	ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>XOS_1</td>
    <td>Verify XOS base container status</td>
    <td>test_xos_base_container_status</td>
    <td>Bring up XOS base container</td>
    <td>Container should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_2</td>
    <td>Verify Ping to XOS base container </td>
    <td> test_xos_base_container_ping</td>
    <td>Bring up XOS base container
Ping to the container </td>
    <td>Container should be Up and running
Ping to XOS base container should success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_3</td>
    <td>Verify XOS base container listening ports </td>
    <td>test_xos_base_container_listening_ports</td>
    <td>Bring up XOS base container
Grep all the listening ports on the container </td>
    <td>Ports status should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_4</td>
    <td>Verify XOS openstack sync container status</td>
    <td>test_xos_sync_openstack_container_status</td>
    <td>Bring up XOS openstack  sync container </td>
    <td>Container should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>
XOS_5</td>
    <td>
Verify Ping to XOS openstack sync container</td>
    <td> test_xos_sync_openstack_container_ping</td>
    <td>Bring up XOS openstack sync container
Ping to the container</td>
    <td>Container should be Up and running
Ping to XOS openstack sync  container should success
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_6</td>
    <td>Verify XOS openstack sync container listening ports</td>
    <td>test_xos_sync_openstack_container_listening_ports</td>
    <td>Bring up XOS openstack sync  container
Grep all the listening ports on the container</td>
    <td>Ports status should be Up
   </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_7</td>
    <td>Verify XOS postgresql container status</td>
    <td>test_xos_postgresql_container_status</td>
    <td>Bring up XOS postgresql container
</td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_8




</td>
    <td>Verify Ping to XOS portgresql container </td>
    <td>test_xos_postgresql_container_ping</td>
    <td>Bring up XOS postgresql container
Ping to the container</td>
    <td>Ping to postgresql container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_9</td>
    <td>Verify XOS postgresql container listening ports</td>
    <td>test_xos_postgresql_container_listening_ports</td>
    <td>Bring up XOS postgresql container
Grep all the listening ports on the container</td>
    <td>Ports should be Up </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_10</td>
    <td>Verify XOS syndicate ms container status</td>
    <td>test_xos_syndicate_ms_container_status</td>
    <td>Bring up  XOS syndicate ms container </td>
    <td>Container should be up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_11</td>
    <td>Verify Ping to XOS syndicate ms  container</td>
    <td>test_xos_syndicate_ms_container_ping</td>
    <td>Bring up  XOS syndicate ms container
Ping to the container</td>
    <td>Ping to the container should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_12</td>
    <td>Verify XOS postgresql container listening ports</td>
    <td>test_xos_syndicate_ms_container_listening_ports</td>
    <td>Bring up  XOS syndicate ms container
Grep all the open ports on the container </td>
    <td>All the ports should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_13

</td>
    <td>Verify XOS sync vtr container status  </td>
    <td>test_xos_sync_vtr_container_status</td>
    <td>Bring up XOS sync vtr container </td>
    <td>Container should be up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_14</td>
    <td>Verify ping to XOS sync vtr container </td>
    <td>test_xos_sync_vtr_container_ping</td>
    <td>Bring up XOS sync vtr container
Ping to the container </td>
    <td>Ping to the container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>cluster_15</td>
    <td>Verify listening ports on XOS sync vtr container  </td>
    <td>test_xos_sync_vtr_container_listening_ports</td>
    <td>Bring up XOS sync vtr container
Grep all the listening ports on the container </td>
    <td>Ports should be Up </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_16</td>
    <td>Verify XOS sync vsg container status</td>
    <td>test_xos_sync_vsg_container_status</td>
    <td>Bring up XOS sync vsg container
 </td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOX_17</td>
    <td>Verify ping to XOS sync vsg container</td>
    <td>test_xos_sync_vsg_container_ping</td>
    <td>Bring up XOS sync vsg container
Ping to the container
 </td>
    <td>Ping to the container should success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_18</td>
    <td>Verify listening ports on XOS sync vsg container</td>
    <td>test_xos_sync_vsg_container_listening_ports</td>
    <td>Bring up XOS sync vsg container
Grep all the listening ports on the container
 </td>
    <td>Ports should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_19</td>
    <td>Verify XOS sync onos container status</td>
    <td>test_xos_sync_onos_container_status</td>
    <td>Bring up XOS sync onos  container

</td>
    <td>Container should be Up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_20
</td>
    <td>Verify ping to XOS sync onos container</td>
    <td>test_xos_sync_onos_container_ping
</td>
    <td>Bring up XOS sync vsg container
Ping to the container
</td>
    <td>Ping to the container should success
</td>
    <td>

</td>
  </tr>
  <tr>
    <td>XOS_21</td>
    <td>Verify listening ports on XOS sync onos container</td>
    <td>test_xos_sync_onos_container_listening_ports</td>
    <td>Bring up XOS sync vsg container
Grep all the listening ports on the container
</td>
    <td>Ports should be Up</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_22



</td>
    <td>Verify XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_status</td>
    <td>Bring up XOS sync fabric container
</td>
    <td>Container should be Up and running
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_23</td>
    <td>Verify ping to XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_ping</td>
    <td>Bring up XOS sync fabric container
Ping to the container
</td>
    <td>Ping to the container should be success
</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_24</td>
    <td>Verify listening ports on XOS sync fabric container </td>
    <td>test_xos_sync_fabric_container_listening_ports</td>
    <td>Bring up XOS sync fabric container
Grep all the open ports on the container</td>
    <td>Ports status should be Up</td>
    <td>
</td>
  </tr>
  <tr>
    <td>XOS_25</td>
    <td>Verify XOS sync vtn container status</td>
    <td>test_xos_sync_vtn_container_status </td>
    <td>Bring up XOS sync vtn container </td>
    <td>Container should be up and running </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_26







</td>
    <td>Verify ping to XOS sync vtn container </td>
    <td>test_xos_sync_vtn_container_ping</td>
    <td>Bring up XOS sync vrn container
Ping to the container </td>
    <td>Ping should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_27</td>
    <td>Verify listening ports on XOS sync vtn container </td>
    <td>test_xos_sync_vtn_container_listening_ports</td>
    <td>Bring up XOS sync vtn container
Grep all the open ports on the container </td>
    <td>Ports status should be Up</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_28</td>
    <td>Verify XOS sync onboarding container status </td>
    <td>test_xos_sync_onboarding_container_status</td>
    <td>Bring up XOS sync onboarding container </td>
    <td>Container status should be Up and running</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_29</td>
    <td>Verify ping to XOS sync onboarding container</td>
    <td>test_xos_sync_onboarding_container_ping </td>
    <td>Bring up XOS sync onboarding container
Ping to the container </td>
    <td>Ping to the container should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_30
</td>
    <td>Verify listening ports on XOS sync onboarding container </td>
    <td>test_xos_sync_onboarding_container_listening_ports</td>
    <td>Bring up XOS sync onboarding container
Grep all the open ports on container </td>
    <td>All the port status should be  Up</td>
    <td></td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_31</td>
    <td>Verify XOS post login api </td>
    <td>test_xos_api_post_login</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/login/
</td>
    <td>Login to post login XOS api should success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_32</td>
    <td>Verify get utils port forwarding XOS api </td>
    <td>test_xos_api_get_utils_port_forwarding</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/portforwarding/</td>
    <td>Get operation of the api should be success
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>XOS_33













</td>
    <td>Verify get utils slices plus XOS api</td>
    <td>test_xos_api_get_utils_slices_plus</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/slicesplus/</td>
    <td>Get operation of the api should be success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_34</td>
    <td>Verify get utils synchronizer XOS api</td>
    <td>test_xos_api_get_utils_synchronizer</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/synchronizer/</td>
    <td>Get operation of the api should be success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XS_35










</td>
    <td>Verify get utils onboarding XOS api</td>
    <td>test_xos_api_get_utils_onboarding_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/onboarding/service/ready</td>
    <td>Get operation of the api should be success
</td>
    <td>







</td>
  </tr>
  <tr>
    <td>XOS_36</td>
    <td>Verify post utils tosca recipe XOS api </td>
    <td>test_xos_api_post_utils_tosca_recipe</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/tosca/run/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_37</td>
    <td>Verify get utils ssh keys XOS api</td>
    <td>test_xos_api_get_utils_ssh_keys</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/utility/sshkeys/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_38</td>
    <td>Verify get tenant all subscribers XOS api</td>
    <td>test_xos_api_get_tenant_all_subscribers</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_39</td>
    <td>Verify get tenant subscriber details XOS api </td>
    <td>test_xos_api_get_tenant_subscribers_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_40</td>
    <td>Verify get
Tenant subscriber  delete XOS api</td>
    <td>test_xos_api_get_tenant_subscriber_delete</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_41</td>
    <td>Verify get tenant subscriber feature details XOS api </td>
    <td>test_xos_api_get_tenant_subscribers_feature_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/</td>
    <td>opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_42</td>
    <td>Verify get tenant read subscriber feature uplink speed XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_uplink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/</td>
    <td>Opening url should return success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_43</td>
    <td>Verify tenant put update subscribers feature uplink speed XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_uplink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uplink_speed/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_44</td>
    <td>Verify get tenant read subscriber download speed XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_downlink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_45</td>
    <td>Verify tenant put update subscribers feature downlink speed XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_downlink_speed</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/downlink_speed/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_46</td>
    <td>Verify get tenant read subscribers feature cdn XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_cdn</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/</td>
    <td>Opening url should return success </td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_47</td>
    <td>Verify tenant put update subscribers feature cdn XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_cdn</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/cdn/</td>
    <td>Opening url should return success</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_48</td>
    <td>Verify get tenant read subscribers feature uverse XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_feature_uverse</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_49</td>
    <td>Verify tenant put update subscribers feature uverse XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_uverse</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/uverse/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_50</td>
    <td>Verify get tenant read subscribers features status XOS api</td>
    <td>test_xos_api_get_tenant_read_subscribers_featurers_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_51</td>
    <td>Verify tenant put update subscribers features status XOS api</td>
    <td>test_xos_api_tenant_put_update_subscribers_feature_status</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/subscriber/subscriber_id/features/status/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_52</td>
    <td>Verify tenant get all  ruckroll</td>
    <td>test_xos_api_tenant_get_all_truckroll </td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_53</td>
    <td>Verify tenant post create truckroll XOS api</td>
    <td>test_xos_api_tenant_post_create_truckroll</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_54</td>
    <td>Verify tenant get truckroll details XOS api</td>
    <td>test_xos_api_tenant_get_truckroll_details</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_55</td>
    <td>Verify tenatn delete truckroll XOS api</td>
    <td>test_xos_api_tenant_delete_trucroll</td>
    <td>Open url https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/truckroll/truckroll_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_56</td>
    <td>Verify tenant get all volt XOS api</td>
    <td>test_xos_api_tenant_get_all_volt</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_57</td>
    <td>Verify tenant post create vOLT XOS api</td>
    <td>test_xos_api_tenant_post_create_vOLT</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_58</td>
    <td>Verify tenant get volt details XOS api</td>
    <td>test_xos_api_tenant_get_volt_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/cord/volt/volt_id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_59</td>
    <td>Verify tenant get all onos apps XOS api</td>
    <td>test_xos_api_tenant_get_all_onos_apps</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/tenant/onos/app/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_60</td>
    <td>Verify service get all example service XOS api</td>
    <td>test_xos_api_service_get_all_example_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/exampleservice/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_61</td>
    <td>Verify service get all onos service XOS api </td>
    <td>test_xos_api_service_get_all_onos_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/onos/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_62</td>
    <td>Verify service get all vsg XOS api</td>
    <td>test_xos_api_service_get_all_vsg</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/exampleservice/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_63</td>
    <td>Verify core get all deployements XOS api</td>
    <td>test_xos_api_core_get_all_deployments</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/onos/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_64</td>
    <td>Verify core post create deployments XOS api</td>
    <td>test_xos_api_core_post_create_deployments</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/service/vsg/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_65</td>
    <td>Verify core get deployment details XOS api</td>
    <td>test_xos_api_core_get_deployment_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_66</td>
    <td>Verify core delete deployment XOS api</td>
    <td>test_xos_api_core_delete_deployment</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_67</td>
    <td>Verify core get all flavours XOS api</td>
    <td>test_xos_api_core_get_all_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/deployments/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_68</td>
    <td>Verify core post create flavors XOS api</td>
    <td>test_xos_api_core_post_create_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>
XOS_69</td>
    <td>Verify core get flavor details XOX api </td>
    <td>test_xos_api_core_get_flavor_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_70</td>
    <td>Verify core delete flavors XOS api</td>
    <td>test_xos_api_core_delete_flavors</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/flavors/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_71</td>
    <td>Verify core get all instances XOS api</td>
    <td>test_xos_api_core_get_all_instances</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_72</td>
    <td>Verify core post create instances XOS api</td>
    <td>test_xos_api_core_post_create_instances</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/?no_hyperlinks=1</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_73</td>
    <td>Verify core get instance details XOS api</td>
    <td>test_xos_api_core_get_instance_details</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/</td>
    <td>
Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_74</td>
    <td>Verify core delete instance XOS api</td>
    <td>test_xos_api_core_delete_instance</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/instances/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_75</td>
    <td>Verify core get all nodes XOS api</td>
    <td>test_xos_api_core_get_all_nodes</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/nodes/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_76</td>
    <td>Verify core get all services XOS api</td>
    <td>test_xos_api_core_get_all_services</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_77</td>
    <td>Verify core post create service XOS api</td>
    <td>test_xos_api_core_post_create_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_78</td>
    <td>Verify core get service details XOS api</td>
    <td>test_xos_api_core_get_service_details</td>
    <td>'https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_79</td>
    <td>Verify core delete service XOS api</td>
    <td>test_xos_api_core_delete_service</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/services/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_80</td>
    <td>Verify core get all sites XOS api</td>
    <td>test_xos_api_core_get_all_sites</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_81</td>
    <td>Verify core get site details XOS api</td>
    <td>test_xos_api_core_get_site_details</td>
    <td>'https://private-anon-873978896e-xos.apiary-mock.com/api/core/sites/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_82</td>
    <td>Verify core get all slices XOS api</td>
    <td>test_xos_api_core_get_all_slices</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/slices/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td>XOS_83</td>
    <td>Verify core get all users XOS api</td>
    <td>test_xos_api_core_get_all_users</td>
    <td>https://private-anon-873978896e-xos.apiary-mock.com/api/core/users/id/</td>
    <td>Opening url should return success
</td>
    <td></td>
  </tr>
  <tr>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
    <td></td>
  </tr>
</table>


**Cbench :**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>cbench_1</td>
    <td>Verify benchamark testing on igmp on ONOS controller</td>
    <td>test_cbench_igmp</td>
    <td>Install cbench tool
Execute cbench commands for igmp traffic test</td>
    <td>Tool should get install
Igmp traffic has to be received properly
ONOS should not hang/crash</td>
    <td></td>
  </tr>
  <tr>
    <td>cbench_2</td>
    <td>Verify throughput benchmark testing on ONOS controller</td>
    <td>test_cbench_throughput_test</td>
    <td>Install cbench tool
Initiate throughput traffic testing </td>
    <td>ONOS should not crash/hang </td>
    <td></td>
  </tr>
  <tr>
    <td>Cbench_3</td>
    <td>Verify latency benchmark testing on ONOS controller </td>
    <td>test_cbench_latency_test</td>
    <td>Install cbench tool
Initiate traffic to test latency
</td>
    <td>ONOS should not crash/hang
 </td>
    <td></td>
  </tr>
</table>


**iPerf :**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>iperf_1</td>
    <td>Verify benchmark testing of ONOS controller for tcp using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp</td>
    <td>Open a tcp session to ONOS controller </td>
    <td>ONOS should not crash/hang</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_2</td>
    <td>Verify benchmark testing of ONOS controller for udp using iperf tool</td>
    <td>test_iperf_network_performance_test_udp</td>
    <td>Open a udp connection to ONSO controller</td>
    <td>ONOS should not crash/hang </td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_3</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_40k</td>
    <td>Open tcp session to ONOS controller by setting window size to 40k
</td>
    <td>ONOS should not crash/hang
 </td>
    <td></td>
  </tr>
  <tr>
    <td>Iperf_4</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_120k</td>
    <td>Open tcp session to ONOS controller by setting window size to 120k</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_5</td>
    <td>Verify benchmark testing of ONOS controller for tcp window size using iperf tool</td>
    <td>test_iperf_network_performance_test_tcp_window_520k</td>
    <td>Open tcp session to ONOS controller by setting window size to 520k</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_6</td>
    <td>Verify benchmark testing  of ONOS controller for multiple tcp sessions </td>
    <td>test_iperf_network_performance_test_multiple_tcp_sessions</td>
    <td>Open multiple tcp sessions to ONOS controller </td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_7</td>
    <td>Verify benchmark testing of ONOS controller for multiple udp sessions</td>
    <td>test_iperf_network_performance_test_multiple_udp_sessions</td>
    <td>Open multiple udp sessions to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_8</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 90bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_90Bytes</td>
    <td>Open a tcp session with mss 90bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_9</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 1490bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_1490Bytes</td>
    <td>Open a tcp session with mss 1490bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
  <tr>
    <td>iperf_10</td>
    <td>Verify benchmark testing of ONOS controller for tcp with mss 9000bytes</td>
    <td>test_iperf_network_performance_test_tcp_mss_9000Bytes</td>
    <td>Open a tcp session with mss 9000bytes to ONOS controller</td>
    <td>ONOS should not crash/hang
</td>
    <td></td>
  </tr>
</table>


**Cord-Subscriber :**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>Cord_subscriber_1</td>
    <td>Test subscriber join and receive for channel surfing</td>
    <td>test_cord_subscriber_join_recv</td>
    <td>Send join to a channel from cord subscriber interface and check join is received on onos
Send data from another interface for join which was send in procedure step 1.</td>
    <td>Check that cord subscribe interface is received multicast data</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_2</td>
    <td>Test subscriber join jump for channel surfing</td>
    <td>test_cord_subscriber_join_jump</td>
    <td>Send join to channel from cord subscriber and then jump to another channel by sending join</td>
    <td>Check that cord subscribe interface is received multicast data</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_3</td>
    <td>Test subscriber join next for channel surfing</td>
    <td>test_cord_subscriber_join_next</td>
    <td>Send join to channel from cord subscriber and then next to another channel by sending join
</td>
    <td>Check that cord subscribe interface is received multicast data
 </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_4</td>
    <td>Test subscriber to auth with invalid Certification and join channel</td>
    <td>test_cord_subscriber_authentication_with_invalid_certificate_and_channel_surfing</td>
    <td>Initiate tls authentication from cord-subscriber with invalid certificates </td>
    <td>Authentication should not get success
</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_5</td>
    <td>Test subscriber to auth with No Certification and join channel</td>
    <td>test_cord_subscriber_authentication_with_no_certificate_and_channel_surfing</td>
    <td>Initiate tls authentication from cord-subscriber with no certificates </td>
    <td>Authentication should not get success

</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_6</td>
    <td>Test subscriber to auth with Self Signed Certification and join channel</td>
    <td>test_cord_subscriber_authentication_with_self_signed_certificate_and_channel_surfing</td>
    <td>Initiate tls authentication from cord-subscriber with self-signed certificates</td>
    <td>Authentication should get success
</td>
    <td></td>
  </tr>
  <tr>
    <td>iCord_subscriber_7</td>
    <td>Test 2 subscribers to auth, one of the subscriber with invalid Certification and join channel</td>
    <td>test_2_cord_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication for two cord-subscribers with valid for one and invalid certificates for other </td>
    <td>Authentication should get success
 For valid certificate subscriber only
</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_8</td>
    <td>Test 2 subscribers to auth, one of the subscriber with No Certification and join channel</td>
    <td>test_2_cord_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication for two cord-subscribers with valid for one and no certificates for other </td>
    <td>Authentication should get success
 For valid certificate subscriber only

</td>
    <td></td>
  </tr>
  <tr>
    <td>iCord_subscriber_9</td>
    <td>Test 2 subscribers to auth, one of the subscriber with Non CA authorized Certificate and join channel</td>
    <td>test_2_cord_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication for two cord-subscribers with valid for one and non ca certificates for other</td>
    <td>Authentication should get success
 For valid certificate subscriber only
</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_10</td>
    <td>Test subscriber auth success, DHCP re-discover with DHCP server and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_discover_and_channel_surfing</td>
    <td>Initiate tls authentication followed by send dhcp discover from a subscriber</td>
    <td>Subscriber should get authenticated and dhcp offer from server
</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_11</td>
    <td>Test subscriber auth success, DHCP client got re-booted and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_client_reboot_and_channel_surfing</td>
    <td>Initiate tls authentication
Get dhcp IP from server
Now reboot the client</td>
    <td>Subscriber should be able to join channel after reboot</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_12</td>
    <td>Test subscriber auth , DHCP server re-boot during DHCP process and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_server_reboot_and_channel_surfing</td>
    <td>1.Initiate tls authentication
2. Get dhcp IP from server
3. Now reboot the  dhcp server </td>
    <td>Subscriber should be able to join channel after reboot</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_13</td>
    <td>Test subscriber auth , DHCP client rebind IP and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_client_rebind_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2. Get dhcp IP from server
3. Client rebinds IP after rebind time </td>
    <td>Subscriber should be able join channel after dhcp rebind time </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_14</td>
    <td>Test subscriber auth , DHCP starvation and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_starvation_and_channel_surfing</td>
    <td>1.Initiate tls authentication
2. Client wont get  dhcp IP from because of starvation  </td>
    <td>Subscriber should not be able to join channel because it don't have dhcp IP</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_15</td>
    <td>Test subscriber auth , sending same DHCP client discover multiple times and join channel</td>
    <td>test_cord_subscriber_authentication_with_multiple_dhcp_discover_for_same_subscriber_and_channel_surfing</td>
    <td>Initiate tls authentication
Send multiple discoveries from same client
Join channel </td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_16</td>
    <td>Test subscriber auth , same DHCP client multiple requests times and join channel</td>
    <td>test_cord_subscriber_authentication_with_multiple_dhcp_request_for_same_subscriber_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2.Send multiple discoveries from same client
3. Join channel</td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_17</td>
    <td>Test subscriber auth with DHCP client requesting ip and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_client_requested_ip_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2.Send dhcp request with desired IP
3. Join channel</td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_18</td>
    <td>Test subscriber auth with DHCP client request for non-offered ip and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_non_offered_ip_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2.Send requests specific IP
3. Join channel</td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_19</td>
    <td>Test subscriber auth with DHCP client requesting out of pool ip and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2.Send requests specific IP from out of pool
3. Join channel</td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_20</td>
    <td>Test subscriber auth with DHCP client specifying lease time and join channel</td>
    <td>test_cord_subscriber_authentication_with_dhcp_specified_lease_time_functionality_and_channel_surfing</td>
    <td>1. Initiate tls authentication
2.Send dhcp requests with specific lease time
3. Join channel</td>
    <td>Subscriber should get authenticated, dhcp IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_21</td>
    <td>Test 1k subscribers to auth, half of the subscribers with invalid Certification and join channel</td>
    <td>test_1k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with invalid certificates for few subscribers </td>
    <td>Authentication should get success only for valid certificate clients </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_22</td>
    <td>Test 1k subscribers to auth, half of the subscribers with No Certification and join channel</td>
    <td>test_1k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with no certificates for few subscribers </td>
    <td>Authentication should get success only for valid certificate clients </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_23</td>
    <td>Test 1k subscribers to auth, half of the subscribers with Non CA authorized Certificate and join channel</td>
    <td>test_1k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with non CA certificates for few subscribers </td>
    <td>Authentication should get success only for valid certificate clients </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_24</td>
    <td>Test 5k subscribers to auth, half of the subscribers with invalid Certification and join channel</td>
    <td>test_5k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with invalid certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_25</td>
    <td>Test 5k subscribers to auth, half of the subscribers with No Certification and join channel</td>
    <td>test_5k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with no certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_26</td>
    <td>Test 5k subscribers to auth, half of the subscribers with Non CA authorized Certificate and join channel</td>
    <td>test_5k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with non CA certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_27</td>
    <td>Test 10k subscribers to auth, half of the subscribers with invalid Certification and join channel</td>
    <td>test_10k_subscribers_authentication_with_valid_and_invalid_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with invalid certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_28</td>
    <td>Test 10k subscribers to auth, half of the subscribers with No Certification and join channel</td>
    <td>test_10k_subscribers_authentication_with_valid_and_no_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with no certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_29</td>
    <td>Test 10k subscribers to auth, half of the subscribers with Non CA authorized Certificate and join channel</td>
    <td>test_10k_subscribers_authentication_with_valid_and_non_ca_authorized_certificates_and_channel_surfing</td>
    <td>Initiate tls authentication with non CA certificates for few subscribers</td>
    <td>Authentication should get success only for valid certificate clients</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_30</td>
    <td>Test 1k subscribers auth success, DHCP re-discover with DHCP server and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_discovers_and_channel_surfing</td>
    <td>Initiate tls authentication for 1k subscribers
Re-discover dhcp server
Join channel  </td>
    <td>All subscribers should be able to get IP and join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_31</td>
    <td>Test 1k subscribers auth success, DHCP client got re-booted and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_client_reboot_and_channel_surfing</td>
    <td>Initiate tls authentication for 1k subscribers
Dhcp clients reboots
3. Join channel</td>
    <td>All subscribers should be able to join channel after reboot also </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_32</td>
    <td>Test 1k subscribers auth , DHCP server re-boot during DHCP process and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_server_reboot_and_channel_surfing</td>
    <td>1. Initiate tls authentication for 1k subscribers
2. Dhcp server reboots during dhcp process
3. Join channel</td>
    <td>All subscribers should be able to join channel after server reboot also</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_33</td>
    <td>Test 1k subscribers auth , DHCP client rebind IP and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_client_rebind_and_channel_surfing</td>
    <td>Initiate tls authentication for 1k subscribers
Dhcp clients rebind IP after rebind time
Joins channel</td>
    <td>All subscribers should be able to join channel after rebind time also</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_34</td>
    <td>Test 1k subscribers auth , DHCP starvation and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_starvation_and_channel_surfing</td>
    <td>1.Initiate tls authentication for 1k subscribers
2.Dhcp clients wont gets IPs because of dhcp starvation
3. Join channel</td>
    <td>Subscribers who has got valid dhcp IP should be able to join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_35</td>
    <td>Test 1k subscribers auth with DHCP client requesting ip and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_client_requested_ip_and_channel_surfing</td>
    <td>1.Initiate tls authentication for 1k subscribers
2.Dhcp clients requests specific IPs
3. Join channel</td>
    <td>All subscribers should be able to join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_36</td>
    <td>Test subscribers auth with DHCP client request for non-offered ip and join channel</td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_non_offered_ip_and_channel_surfing</td>
    <td>1.Initiate tls authentication for 1k subscribers
2.Dhcp clients requests specific IPs
3. Join channel</td>
    <td>All subscribers should be able to join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_37</td>
    <td>Test 4 subscribers join and receive for 5 channels surfing</td>
    <td>test_4_cord_subscribers_join_recv_5channel</td>
    <td>Send igmp joins from 4 subscribers for 5 channels </td>
    <td>All 4 subscribers should be able join in 5 channels </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_38</td>
    <td>Test 4 subscribers jump and receive for 5 channels surfing</td>
    <td>test_4_cord_subscribers_join_jump_5channel</td>
    <td>Send igmp joins from 4 subscribers for 5 channels </td>
    <td>All 4 subscribers should be able join in 5 channels
Channel jump should success  </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_39</td>
    <td>Test 4 subscribers join next for 5 channels</td>
    <td>test_4_cord_subscribers_join_next_5channel</td>
    <td>Send igmp joins from 4 subscribers for 5 channels</td>
    <td>All 4 subscribers should be able join in 5 channels
Channel next should success </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_40</td>
    <td>Test 10 subscribers join and receive for 5 channels surfing</td>
    <td>test_10_cord_subscribers_join_recv_5channel</td>
    <td>Send igmp joins from 10 subscribers for 5 channels </td>
    <td>All 10 subscribers should be able join in 5 channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_41</td>
    <td>Test 10 subscribers jump and receive for 5 channels surfing</td>
    <td>test_10_cord_subscribers_join_jump_5channel</td>
    <td>Send igmp joins from 10 subscribers for 5 channels</td>
    <td>All 10 subscribers should be able join in 5 channels
Channel jump should success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_42</td>
    <td>Test 10 subscribers join next for 5 channels</td>
    <td>test_10_cord_subscribers_join_next_5channel</td>
    <td>Send igmp joins from 10 subscribers for 5 channels</td>
    <td>All 10 subscribers should be able join in 5 channels
Channel next should success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_43</td>
    <td>Test cord subscriber join and receive for 100 channels</td>
    <td>test_cord_subscriber_join_recv_100channels</td>
    <td>Send igmp join from a subscriber to 100 channels</td>
    <td>subscriber should be able join in all 100 channels </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_44</td>
    <td>Test cord subscriber join and receive for 400 channels</td>
    <td>test_cord_subscriber_join_recv_400channels</td>
    <td>Send igmp join from a subscriber to 400 channels</td>
    <td>subscriber should be able join in all 400 channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_45</td>
    <td>Test cord subscriber join and receive for 800 channels</td>
    <td>test_cord_subscriber_join_recv_800channels</td>
    <td>Send igmp join from a subscriber to 800 channels</td>
    <td>subscriber should be able join in all 800 channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_46</td>
    <td>Test cord subscriber join and receive for 1200 channels</td>
    <td>test_cord_subscriber_join_recv_1200channels</td>
    <td>Send igmp join from a subscriber to 1200 channels</td>
    <td>subscriber should be able join in all 1200 channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_47</td>
    <td>Test cord subscriber join and receive for 1500 channels</td>
    <td>test_cord_subscriber_join_recv_1500channels</td>
    <td>Send igmp join from a subscriber to 1500 channels</td>
    <td>subscriber should be able join in all 1500 channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_48</td>
    <td>Test cord subscriber join jump for 100 channels</td>
    <td>test_cord_subscriber_join_jump_100channels</td>
    <td>For a subscriber do channel jump for 100 channel</td>
    <td>100 Channel jump should get success </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_48</td>
    <td>Test cord subscriber join jump for 400 channels</td>
    <td>test_cord_subscriber_join_jump_400channels</td>
    <td>For a subscriber do channel jump for 400 channel</td>
    <td>400 Channel jump should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_49</td>
    <td>Test cord subscriber join jump for 800 channels</td>
    <td>test_cord_subscriber_join_jump_800channels</td>
    <td>For a subscriber do channel jump for 800 channel</td>
    <td>800 Channel jump should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_50</td>
    <td>Test cord subscriber join jump for 1200 channels</td>
    <td>test_cord_subscriber_join_jump_1200channel</td>
    <td>For a subscriber do channel jump for 1200 channel</td>
    <td>1200 Channel jump should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_51</td>
    <td>Test cord subscriber join jump for 1500 channels</td>
    <td>test_cord_subscriber_join_jump_1500channels</td>
    <td>For a subscriber do channel jump for 1500 channel</td>
    <td>1500 Channel jump should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_52</td>
    <td>Test cord subscriber join next for 100 channels</td>
    <td>test_cord_subscriber_join_next_100channels</td>
    <td>For a subscriber do channel next for 100 channel</td>
    <td>Channel next for 100 channels should be successful </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_53</td>
    <td>Test cord subscriber join next for 400 channels</td>
    <td>test_cord_subscriber_join_next_400channels</td>
    <td>For a subscriber do channel next for 400 channel</td>
    <td>Channel next for 400 channels should be successful</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_54</td>
    <td>Test cord subscriber join next for 800 channels</td>
    <td>test_cord_subscriber_join_next_800channels</td>
    <td>For a subscriber do channel next for 800 channel</td>
    <td>Channel next for 800 channels should be successful</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_55</td>
    <td>Test cord subscriber join next for 1200 channels</td>
    <td>test_cord_subscriber_join_next_1200channels</td>
    <td>For a subscriber do channel next for 1200 channel</td>
    <td>Channel next for 1200 channels should be successful</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_56</td>
    <td>Test cord subscriber join next for 1500 channels</td>
    <td>test_cord_subscriber_join_next_1500channels</td>
    <td>For a subscriber do channel next for 1500 channel</td>
    <td>Channel next for 1500 channels should be successful</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_57</td>
    <td>Test cord subscriber auth with dhcp client request out of pool ip channel surfing </td>
    <td>test_1k_cord_subscribers_authentication_with_dhcp_request_out_of_pool_ip_by_client_and_channel_surfing</td>
    <td>Initiate tls authentication for subscriber
Request for dhcp IP from out of pool
Join channel </td>
    <td>Subscriber should get authenticated with IP within pool only.should be able to join channel</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_58</td>
    <td>Test 1k cord subscribers join and receive for 100 channels</td>
    <td>test_1k_cord_subscribers_join_recv_100channel</td>
    <td>1. Send joins for 1k subscribers  to subscribe in 100 channels </td>
    <td>All subscribers should be able to join and receive 100 channels </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_59</td>
    <td>Test 1k cord subscribers join jump for 100 channels</td>
    <td>test_1k_cord_subscribers_join_jump_100channel</td>
    <td>Do 100 channel jump for 1k subscribers </td>
    <td>100 channel jump for all subscribers should get success </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_60</td>
    <td>Test 1k cord subscribers join next for 100 channels</td>
    <td>test_1k_cord_subscribers_join_next_100channel</td>
    <td>Do 100 channel next for 1k subscribers</td>
    <td>100 channel next for all subscribers should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_61</td>
    <td>Test 1k cord subscribers join and receive for 400 channels</td>
    <td>test_1k_cord_subscribers_join_recv_400channel</td>
    <td>Send joins for 400 channels from 1k subscribers </td>
    <td>All subscribers should be able to send/receive from 400 channels </td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_62</td>
    <td>Test 1k cord subscribers join jump for 400 channels</td>
    <td>test_1k_cord_subscribers_join_jump_400channel</td>
    <td>Do 400 channel jump for 1k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_63</td>
    <td>Test 1k cord subscribers join next for 400 channels</td>
    <td>test_1k_cord_subscribers_join_next_400channel</td>
    <td>Do 100 channel next for 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_64</td>
    <td>Test 1k cord subscribers join and receive for 800 channels</td>
    <td>test_1k_cord_subscribers_join_recv_800channel</td>
    <td>Send joins for 800 channels from 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_65</td>
    <td>Test 1k cord subscribers join jump for 800 channels</td>
    <td>test_1k_cord_subscribers_join_jump_800channel</td>
    <td>Do 800 channel jump for 1k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_66</td>
    <td>Test 1k cord subscribers join next for 800 channels</td>
    <td>test_1k_cord_subscribers_join_next_800channel</td>
    <td>Do 800 channel next for 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_67</td>
    <td>Test 1k cord subscribers join and receive for 1200 channels</td>
    <td>test_1k_cord_subscribers_join_recv_1200channel</td>
    <td>Send joins for 1200 channels from 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_68</td>
    <td>Test 1k cord subscribers join jump for 1200 channels</td>
    <td>test_1k_cord_subscribers_join_jump_1200channel</td>
    <td>Do 1200 channel jump for 1k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_69</td>
    <td>Test 1k cord subscribers join next for 1200 channels</td>
    <td>test_1k_cord_subscribers_join_next_1200channel</td>
    <td>Do 1200 channel next for 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_70</td>
    <td>Test 1k cord subscribers join and receive for 1500 channels</td>
    <td>test_1k_cord_subscribers_join_recv_1500channel</td>
    <td>Send joins for 1500 channels from 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_71</td>
    <td>Test 1k cord subscribers join jump for 1500 channels</td>
    <td>test_1k_cord_subscribers_join_jump_1500channel</td>
    <td>Do 1500 channel jump for 1k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_72</td>
    <td>Test 1k cord subscribers join next for 1500 channels</td>
    <td>test_1k_cord_subscribers_join_next_1500channel</td>
    <td>Do 1500 channel next for 1k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_73


</td>
    <td>Test 5k cord subscribers join and receive for 100 channels</td>
    <td>test_5k_cord_subscribers_join_recv_100channel</td>
    <td>Send joins for 100 channels from 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_74</td>
    <td>Test 5k cord subscribers join jump for 100 channels</td>
    <td>test_5k_cord_subscribers_join_jump_100channel</td>
    <td>Do 100 channel jump for 5k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_75</td>
    <td>Test 5k cord subscribers join next  for 100 channels</td>
    <td>test_5k_cord_subscribers_join_next_100channel</td>
    <td>Do 100 channel next for 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_76</td>
    <td>Test 5k cord subscribers join and receive for 400 channels</td>
    <td>test_5k_cord_subscribers_join_recv_400channel</td>
    <td>Send joins for 400 channels from 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_77</td>
    <td>Test 5k cord subscribers join jump for 400 channels</td>
    <td>test_5k_cord_subscribers_join_jump_400channel</td>
    <td>Do 400 channel jump for 5k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_78</td>
    <td>Test 5k cord subscribers join next for 400 channels</td>
    <td>test_5k_cord_subscribers_join_next_400channel</td>
    <td>Do 400 channel next for 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_79</td>
    <td>Test 5k cord subscribers join and receive for 800 channels</td>
    <td>test_5k_cord_subscribers_join_recv_800channel</td>
    <td>Send joins for 800 channels from 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_80</td>
    <td>Test 5k cord subscribers join jump for 800 channels</td>
    <td>test_5k_cord_subscribers_join_jump_800channel</td>
    <td>Do 800 channel jump for 5k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_81</td>
    <td>Test 5k cord subscribers join next for 800 channels</td>
    <td>test_5k_cord_subscribers_join_next_800channel</td>
    <td>Do 800 channel next for 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_82</td>
    <td>Test 5k cord subscribers join and receive for 1200 channels</td>
    <td>test_5k_cord_subscribers_join_recv_1200channel</td>
    <td>Send joins for 1200 channels from 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_83</td>
    <td>Test 5k cord subscribers join jump  for 1200 channels</td>
    <td>test_5k_cord_subscribers_join_jump_1200channel</td>
    <td>Do 1200 channel jump for 5k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_84</td>
    <td>Test 5k cord subscribers join next for 1200 channels</td>
    <td>test_5k_cord_subscribers_join_next_1200channel</td>
    <td>Do 1200 channel next for 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_85</td>
    <td>Test 5k cord subscribers join and receive for 1500 channels</td>
    <td>test_5k_cord_subscribers_join_recv_1500channel</td>
    <td>Send joins for 1500 channels from 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_86</td>
    <td>Test 5k cord subscribers join jump for 1500 channels</td>
    <td>test_5k_cord_subscribers_join_jump_1500channel</td>
    <td>Do 1500 channel jump for 5k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_87</td>
    <td>Test 5k cord subscribers join next for 1500 channels</td>
    <td>test_5k_cord_subscribers_join_next_1500channel</td>
    <td>Do 1500 channel next for 5k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_88</td>
    <td>Test 10k cord subscribers join and receive for 100 channels</td>
    <td>test_10k_cord_subscribers_join_recv_100channel</td>
    <td>Send joins for 100 channels from 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_89</td>
    <td>Test 10k cord subscribers join jump for 100 channels</td>
    <td>test_10k_cord_subscribers_join_jump_100channel</td>
    <td>Do 100 channel jump for 10k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_90</td>
    <td>Test 10k cord subscribers join next for 100 channels</td>
    <td>test_10k_cord_subscribers_join_next_100channel</td>
    <td>Do 100 channel next for 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_91</td>
    <td>Test 100k cord subscribers join and receive for 100 channels</td>
    <td>test_100k_cord_subscribers_join_recv_100channel</td>
    <td>Send joins for 100 channels from 100k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_92</td>
    <td>Test 100k cord subscribers join jump for 100 channels</td>
    <td>test_100k_cord_subscribers_join_jump_100channel</td>
    <td>Do 100 channel jump for 100k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_93</td>
    <td>Test 100k cord subscribers join next for 100 channels</td>
    <td>test_100k_cord_subscribers_join_next_100channel</td>
    <td>Do 100 channel next for 100k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_94</td>
    <td>Test 10k cord subscribers join and receive or 400 channels</td>
    <td>test_10k_cord_subscribers_join_recv_400channel</td>
    <td>Send joins for 400 channels from 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_95</td>
    <td>Test 10k cord subscribers join jump for 400 channels</td>
    <td>test_10k_cord_subscribers_join_jump_400channel</td>
    <td>Do 400 channel jump for 10k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_96</td>
    <td>Test 10k cord subscribers join next for 400 channels</td>
    <td>test_10k_cord_subscribers_join_next_400channel</td>
    <td>Do 400 channel next for 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_97</td>
    <td>Test 10k cord subscribers join and receive for 800 channels</td>
    <td>test_10k_cord_subscribers_join_recv_800channel</td>
    <td>Send joins for 800 channels from 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_98</td>
    <td>Test 10k cord subscribers join jump for 800 channels</td>
    <td>test_10k_cord_subscribers_join_jump_800channel</td>
    <td>Do 800 channel jump for 10k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_99</td>
    <td>Test 10k cord subscribers join next  for 800 channels</td>
    <td>test_10k_cord_subscribers_join_next_800channel</td>
    <td>Do 800 channel next for 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_100</td>
    <td>Test 10k cord subscribers join and receive for 1200 channels</td>
    <td>test_10k_cord_subscribers_join_recv_1200channel</td>
    <td>Send joins for 1200 channels from 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_101</td>
    <td>Test 10k cord subscribers join jump for 1200 channels</td>
    <td>test_10k_cord_subscribers_join_jump_1200channel</td>
    <td>Do 1200 channel jump for 10k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_102</td>
    <td>Test 10k cord subscribers join next for 1200 channels</td>
    <td>test_10k_cord_subscribers_join_next_1200channel</td>
    <td>Do 1200 channel next for 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_103</td>
    <td>Test 10k cord subscribers join and receive for 1500 channels</td>
    <td>test_10k_cord_subscribers_join_recv_1500channel</td>
    <td>Send joins for 1500 channels from 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_104</td>
    <td>Test 10k cord subscribers join jump for 1500 channels</td>
    <td>test_10k_cord_subscribers_join_jump_1500channel</td>
    <td>Do 1500 channel jump for 10k subscribers </td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_105</td>
    <td>Test 10k cord subscribers join next for 1500 channels</td>
    <td>test_10k_cord_subscribers_join_next_1500channel</td>
    <td>Do 1500 channel next for 10k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_106</td>
    <td>Test 100k cord subscribers join and receive for 1500 channels</td>
    <td>test_100k_cord_subscribers_join_recv_1500channel</td>
    <td>Send joins for 1500 channels from 100k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_107</td>
    <td>Test 100k cord subscribers join jump for 1500 channels</td>
    <td>test_100k_cord_subscribers_join_jump_1500channel</td>
    <td>Do 1500 channel jump for 100k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
  <tr>
    <td>Cord_subscriber_108</td>
    <td>Test 100k cord subscribers join next for 1500 channels</td>
    <td>test_100k_cord_subscribers_join_next_1500channel</td>
    <td>Do 1500 channel next for 100k subscribers</td>
    <td>All subscribers should be able to send/receive from all channels</td>
    <td></td>
  </tr>
</table>


**netCondition:**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>netCondition_1</td>
    <td>Verify netCondition for delay between igmp join and data</td>
    <td>test_netCondition_with_delay_between_igmp_join_and_data_recv</td>
    <td>Add delay between igmp join and data traffic </td>
    <td>If delay more than igmp group expiry time, client should not receive traffic </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_2</td>
    <td>Verify netCondition for delay between igmp data and join </td>
    <td>test_netCondition_with_delay_between_data_recv_and_igmp_join</td>
    <td>Initiate igmp data traffic first and after some delay send igmp join </td>
    <td>Join should receive data </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_3</td>
    <td>Verify netCondition for delay between igmp leave and data</td>
    <td>test_netCondition_with_delay_between_igmp_leave_and_data</td>
    <td>Add delay between igmp leave and  data  traffic </td>
    <td>Client should not receive traffic </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_4</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_positive_IdReq_and_tlsHelloReq</td>
    <td>Add delay between tls Id and Hello requests. Positive case  </td>
    <td>Authentication should get successful </td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_5</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_IdReq_and_tlsHelloReq </td>
    <td>Add delay between tls Id and Hello requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_6</td>
    <td>Verify netCondition for delay between tls Hello and Cert request packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_tlsHelloReq_and_eapTlsCertReq </td>
    <td>Add delay between tls Hello and cert requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_7</td>
    <td>Verify netCondition for delay between tls Cert Req and Change cipher spec packets exchange</td>
    <td>test_netCondition_in_eap_tls_with_delay_between_TlsCertReq_and_TlsChangeCipherSpec </td>
    <td>Add delay between tls cert req and change cipher spec  requests</td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_8</td>
    <td>Verify netCondition for delay between tls IdReq and Hello Req packets exchange with no cert </td>
    <td>test_netCondition_in_eap_tls_with_no_cert_and_delay_between_IdReq_and_HelloReq </td>
    <td>Add delay between tls Id and Hello requests with no cert </td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_9</td>
    <td>Verify netCondition for delay between tls Hello Req and CertReq packets exchange with no certificates</td>
    <td>test_netCondition_in_eap_tls_with_delay_and_no_cert_between_tlsHelloReq_and_eapTlsCertReq </td>
    <td>Add delay between tls Hello and Cert Requests with no certificates </td>
    <td>Authentication should fail</td>
    <td> </td>
  </tr>
  <tr>
    <td>netCondition_10</td>
    <td>Verify netCondition for delay between tls CertReq and change cipher spec packets exchange with no certificates </td>
    <td>test_netCondition_in_eap_tls_with_delay_and_no_cert_between_TlsCertReq_and_TlsChangeCipherSpec</td>
    <td>Add delay between tls Cert adn change cipher spec Requests with no certificates</td>
    <td>Authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_11</td>
    <td>Verify netCondition for delay between tls IdReq and Hello packets exchange with invalid certificates</td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_IdReq_and_HelloReq</td>
    <td>Add delay between tls ID and Hello requests with invalid certificates</td>
    <td>Authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_12</td>
    <td>Verify netCondition for delay between tls HelloReq and CertReq packets exchange with invalid certificates </td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_and_delay_between_tlsHelloReq_and_eapTlsCertReq</td>
    <td>Add delay between tls Hello and Cert requests with invalid certificates</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_13</td>
    <td>Verify netCondition for delay between tls CertReq and change cipher spec packets exchange with invalid certificates </td>
    <td>test_netCondition_in_eap_tls_with_invalid_cert_delay_between_TlsCertReq_and_TlsChangeCipherSpec</td>
    <td>Add delay between tls Cert and change cipher spec requests with invalid certificates</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_14</td>
    <td>Verify netCondition in multiple tls requests with delay between tls IdReq and Hello packets exchange</td>
    <td>test_netCondition_in_multiple_eap_tls_requests_with_delay_between_IdReq_and_HelloReq</td>
    <td>Add delay between tls ID and Hello  requests for multiple tls clients </td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_15</td>
    <td>Verify netCondition in multiple tls requests for delay between tls packets exchange</td>
    <td>test_netCondition_with_multiple_authentication_and_delay_between_complete_authentication</td>
    <td>Add delay between tls authentication packets for multiple tls clients</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_16</td>
    <td>Verify netCondition delay for every 100 tls burst when multiple tls requests sent</td>
    <td>test_netCondition_with_multiple_authentication_and_delay_between_every_100_tls_burst</td>
    <td>Add delay between every 100 tls burst packets for multiple tls clients</td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_17</td>
    <td>Verify netCondition for delay between  mac flow and traffic </td>
    <td>test_netCondition_with_delay_between_mac_flow_and_traffic</td>
    <td>Add delay between mac flow and data </td>
    <td>Flow traffic should forward to destination port  </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_18</td>
    <td>Verify netCondition for delay between  ip flow and traffic</td>
    <td>test_netCondition_with_delay_between_ip_flow_and_traffic</td>
    <td>Add delay between ip flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_19</td>
    <td>Verify netCondition for delay between  tcp port flow and traffic</td>
    <td>test_netCondition_with_delay_between_tcp_port_flow_and_traffic</td>
    <td>Add delay between tcp port flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_20</td>
    <td>Verify netCondition for delay below udp port flow and traffic</td>
    <td>test_netCondition_with_delay_between_udp_port_flow_and_traffic</td>
    <td>Add delay between udp port flow and data</td>
    <td>Flow traffic should forward to destination port</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_21</td>
    <td>Verify netCondition for delay between multiple igmp joins and data </td>
    <td>netCondition_with_delay_between_multiple_igmp_joins_and_data</td>
    <td>Add delay between multiple igmp joins and data </td>
    <td>If igmp group not expired, client should receive  data traffic </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_22</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data for multiple subscribers </td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_multiple_subscribers</td>
    <td>Add delay between multiple igmp joins and data for multiple subscribers </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_23</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data for multiple subscribers with low multicast data rate </td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_multiple_subscribers_with_low_multicast_data_rate</td>
    <td>Add delay between multiple igmp joins and data for multiple subscribers with low multicast data rate </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_24</td>
    <td>Verify netCondition for delay between multiple igmp joins and data for same subscribers</td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_for_same_subscriber</td>
    <td>Add delay between multiple igmp joins and data for same subscriber</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_25</td>
    <td>Verify netCondition for delay between same igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_delay_between_same_igmp_joins_and_data_from_multiple_subscriber</td>
    <td>Add delay between join and data for same group from multiple subscribers </td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_26</td>
    <td>Verify netCondition for delay between  multiple igmp joins and data with same source list  for multiple subscribers</td>
    <td>test_netCondition_with_delay_between_multiple_igmp_joins_and_data_from_same_sourcelist_for_multiple_subscriber</td>
    <td>Add delay between join and data for same group from multiple subscribers for same source list</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_27</td>
    <td>Verify netCondition for throttle between multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_throttle_between_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Add Throttle between igmp join and data sent from multiple subscribers</td>
    <td>If igmp group not expired, client should receive  data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_28</td>
    <td>Verify netCondition for invalid igmp type  multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_igmp_type_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send invalid type multiple igmp joins  and data to groups from multiple subscribers </td>
    <td>Igmp joins should not registered and clients  should not receive data traffic </td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_29</td>
    <td>Verify netCondition for invalid igmp ecord type multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_record_type_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send record type multiple igmp joins  and data to groups from multiple subscribers</td>
    <td>Igmp joins should not registered and clients  should not receive data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_30</td>
    <td>Verify netCondition for invalid ttl and multiple igmp joins and data for multiple subscribers</td>
    <td>test_netCondition_with_invalid_ttl_and_multiple_igmp_joins_and_data_from_multiple_subscribers</td>
    <td>Send invalid ttl type multiple igmp joins  and data to groups from multiple subscribers</td>
    <td>Igmp joins should not registered and clients  should not receive data traffic</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_31</td>
    <td>Verify netCondition for tls out of order packets exchange between client and server hello </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_exchanges_between_serverHello_and_client_packet</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_32</td>
    <td>Verify netCondition for tls out of order packets exchange in tls Cert Req packets</td>
    <td>test_netCondition_in_multiple_eap_tls_session_with_out_of_order_exchanges_in_eapTlsCertReq_packets</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_33</td>
    <td>Verify netCondition for tls out of order packets exchange in tls change cipher spec packets </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_with_out_of_order_eapTlsChangeCipherSpec_packets</td>
    <td>Initiate tls authentication from client with out of ordered sequence of packets exchange </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_34</td>
    <td>Verify netCondition for multiple tls sessions dropping Hello request</td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsHelloReq_packets</td>
    <td>Initiate tls authentication from client and drop server hello request packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_35</td>
    <td>Verify netCondition for multiple tls sessions dropping change ciper spec packet </td>
    <td>test_netCondition_in_multiple_eap_tls_sessions_dropping_eapTlsChangeCipherSpec_packets</td>
    <td>Initiate tls authentication from client and drop server change cipher spec request packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_36</td>
    <td>Verify netCondition for invalid eapol version in client authentication packets </td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_version_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client with invalid eapol version in client packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_37</td>
    <td>Verify netCondition for invalid tls type in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_tls_type_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls type in client packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_38</td>
    <td>Verify netCondition for invalid eapol type ID in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_type_ID_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls type ID in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_39</td>
    <td>Verify netCondition for invalid eapol response field in client authentication packets</td>
    <td>test_netCondition_in_eapol_tls_with_invalid_eapol_response_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol  response field in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_40</td>
    <td>Verify netCondition for invalid eap content type in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_eap_content_type_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls content type in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_41</td>
    <td>Verify netCondition for invalid tls version in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_tls_version_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol tls version in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_42</td>
    <td>Verify netCondition for invalid ciper suite field in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_invalid_tls_cipher_suite_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client  with invalid eapol cipher suite in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_43</td>
    <td>Verify netCondition for identifier field mismatch in client authentication packets</td>
    <td>test_netCondition_in_eap_tls_with_id_mismatch_in_identifier_field_in_client_auth_packet</td>
    <td>Initiate tls authentication from client with mismatch in identifier field in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_44</td>
    <td>Verify netCondition for ID mismatch in client hello packet</td>
    <td>test_netCondition_in_eap_tls_with_id_mismatch_in_client_hello_auth_packet</td>
    <td>Initiate tls authentication from client with ID mismatch in client hello packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_45</td>
    <td>Verify netCondition for invalid handshake  type in client hello packet</td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_hello_handshake_type_auth_packet</td>
    <td>Initiate tls authentication from client with invalid handshake type in client hello packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_46</td>
    <td>Verify netCondition for invalid client certReq handhsake type in authentication packet</td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_cert_req_handshake_auth_packet</td>
    <td>Initiate tls authentication from client with invalid client cert request handshake in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_47</td>
    <td>Verify netCondition for client key exchange replace with server key exchange  in tls cleint authentication packets </td>
    <td>test_netCondition_in_eap_tls_with_invalid_client_key_ex_replacing_server_key_ex</td>
    <td>Initiate tls authentication from client with client key exchange replaces server  key exchange in client packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_48</td>
    <td>Verify netCondition emulating tls client authentication without radius server </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_emulating_server_packets_without_radius_server_container</td>
    <td>Initiate tls authentication from client without radius server </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_49</td>
    <td>Verify netCondition for server eap tls id response packet drop </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_server_eapid_response_packet</td>
    <td>Initiate tls authentication from client and drop server eapid response packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_50</td>
    <td>Verify netCondition for  invalid tls eapid response packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_server_eapid_response_packet</td>
    <td>Initiate tls authentication from client  with invalid server eapid response packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_51</td>
    <td>Verify netCondition for server tls hello  packet drop</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_server_hello_packet</td>
    <td>Initiate tls authentication from client and drop server  hello response packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_52</td>
    <td>Verify netCondition for  invalid tls server hello packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_server_hello_packet</td>
    <td>Initiate tls authentication from client with invalid server hello packet </td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_53</td>
    <td>Verify netCondition for dropping client certificate access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_54</td>
    <td>Verify netCondition for invalid  client certificate access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  with invalid server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_55</td>
    <td>Verify netCondition for dropping client certificate with 2nd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_with_2nd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop client certificate with 2nd fragment server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_56</td>
    <td>Verify netCondition for invalid client certificate with 2nd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_with_2nd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  invalid client certificate with 2nd fragment server access challenge  packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_57</td>
    <td>Verify netCondition for dropping client certificate with 3rd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_client_certficate_with_3rd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client and drop client certificate with 3rd  fragment server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_58</td>
    <td>Verify netCondition for invalid client certificate with 3rd fragment access challenge server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_client_certficate_with_3rd_fragment_access_challenge_server_packet</td>
    <td>Initiate tls authentication from client  with invalid client certificate 3rd  fragment server access challenge packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_59</td>
    <td>Verify netCondition for dropping cipher suite request server packet </td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_cipher_suite_request_server_packet</td>
    <td>Initiate tls authentication from client and drop cipher suite requests server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_60</td>
    <td>Verify netCondition for invalid cipher suite request server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_cipher_suite_request_server_packet</td>
    <td>Initiate tls authentication from client  with invalid cipher suite server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_61</td>
    <td>Verify netCondition for dropping access accept  server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_dropped_access_accept_server_packet</td>
    <td>Initiate tls authentication from client and drop access accept  server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
  <tr>
    <td>netCondition_62</td>
    <td>Verify netCondition for invalid access accept  server packet</td>
    <td>test_netCondition_in_eap_tls_with_valid_client_and_invalid_access_accept_server_packet</td>
    <td>Initiate tls authentication from client  with invalid access accept server packet</td>
    <td>Client authentication should fail</td>
    <td></td>
  </tr>
</table>


**Mininet:**

<table>
  <tr>
    <td>ID</td>
    <td>Title</td>
    <td>Function Name</td>
    <td>Test Steps</td>
    <td>Expected Result</td>
    <td>Actual Result</td>
  </tr>
  <tr>
    <td>mininet_1</td>
    <td>Verify creating topology in mininet </td>
    <td>test_miniet_create_topology</td>
    <td> Create topology in mininet</td>
    <td>Topology should created successfully </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_2</td>
    <td>Verify creating  singleswitch topology in mininet</td>
    <td>test_mininet_create_single_switch_topology </td>
    <td>Create topology in mininet using singleswitch topo function</td>
    <td>Topology should created successfully </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_3</td>
    <td>Verify creating linear topology in mininet</td>
    <td> test_mininet_create_linear_topology</td>
    <td>Create topology in mininet using linear topo function </td>
    <td>Topology should created successfully </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_4</td>
    <td>Verify creating tree topology in mininet</td>
    <td> test_mininet_create_tree_topology</td>
    <td>Create topology in mininet using tree topo function  </td>
    <td>Topology should created successfully </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_5</td>
    <td>Verify creating topology in mininet and execute commands from mininet host </td>
    <td>test_mininet_executing_commands_from_mininet_host</td>
    <td>Create topology in mininet and execute system commands in mininet host  </td>
    <td>Topology should created successfully
Command execute from mininet host should  success</td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_6</td>
    <td>Verify creating topology in mininet and pingall </td>
    <td> test_mininet_verifying_pingall_from_mininet</td>
    <td>Create topology in mininet and verify pingall is success </td>
    <td>Topology should created successfully
Pingall should success </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_7</td>
    <td>Verify mininet pingall with onos app ‘fwd’ deactivate </td>
    <td> test_miniet_initiating_pingall_from_mininet_with_onos_app_deactivation</td>
    <td> Create topology in mininet and verify pingall fails with onos app ‘fwd’ deactivated</td>
    <td>After  onos app deactivated, pingall  fails </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_8</td>
    <td>Verify mininet hosts reflecting in ONOS </td>
    <td>test_mininet_verifying_mininet_hosts_in_onos_controller </td>
    <td>Create mininet topology and verify host listed in onos ‘hosts’  </td>
    <td>All the hosts created in mininet should reflect in onos </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_9</td>
    <td>Verify tcp bandwidth measure between mininet hosts </td>
    <td>test_mininet_verifying_tcp_bandwidth_measure_between_mininet_hosts_using_iperf</td>
    <td>Create mininet topology and verify tcp bandwidth between hosts </td>
    <td>Bandwidth measure should success </td>
    <td> </td>
  </tr>
  <tr>
    <td>mininet_10</td>
    <td>Verify udp bandwidth measure between mininet hosts </td>
    <td>test_mininet_verifying_udp_bandwidth_measure_between_mininet_hosts_using_iperf</td>
    <td>Create mininet topology and verify udp bandwidth between hosts</td>
    <td>Bandwidth measure should success</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_11</td>
    <td>Verify tcp bandwidth measure between mininet hosts with one host removed </td>
    <td>test_mininet_verifying_tcp_bandwidth_between_mininet_hosts_using_iperf_with_one_host_removed</td>
    <td>Create mininet topology and verify tcp bandwidth between hosts with one host removed </td>
    <td>Bandwidth measure should success</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_12</td>
    <td>Verify udp bandwidth measure between mininet hosts with one host removed </td>
    <td>test_mininet_verifying_udp_bandwidth_between_mininet_hosts_using_iperf_with_one_host_removed</td>
    <td>Create mininet topology and verify udp  bandwidth between hosts with one host removed </td>
    <td>Bandwidth measure should success</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_13</td>
    <td>Verify assigning non default IP address to mininet hosts </td>
    <td>test_mininet_hosts_assigned_with_non_default_ip_address</td>
    <td>Create mininet topology with non-default IPs assigned to hosts </td>
    <td>Topology should created successfully</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_14</td>
    <td>Verify assigning non default IP addesses in different subnets  to mininet hosts </td>
    <td>test_mininet_hosts_assigned_with_non_default_ip_address_in_different_subnets</td>
    <td>Create mininet topology with non-default IPs  in different subnets assigned to hosts</td>
    <td>Topology should created successfully</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_15</td>
    <td>Verify pingall with removing connection between  switches </td>
    <td>test_mininet_verifying_pingall_with_connection_remove_between_switches</td>
    <td>Create mininet topology and remove connection between switches
And do pingall </td>
    <td>Pingall should not success 100 %</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_16</td>
    <td>Verify pingall with removing host</td>
    <td>test_mininet_verifying_pingall_with_removing_one_mininet_host</td>
    <td>Create mininet topology and remove one host
And do pingall</td>
    <td>Pingall should not success 100 %</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_17</td>
    <td>Verify pingall with removing switch </td>
    <td>test_mininet_verifying_pingall_with_removing_one_mininet_switch</td>
    <td>Create mininet topology and remove one switch
And do pingall</td>
    <td>Pingall should not success 100 %</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_18</td>
    <td>Verify mininet switch status in ONOS controller </td>
    <td>test_mininet_verifying_mininet_switch_status_in_onos_controller</td>
    <td>Create mininet topology
Verify topology in onos controller </td>
    <td>Verify all switches in mininet reflects in onos controller </td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_19</td>
    <td>Verify mininet host status in ONOS after removing host in mininet </td>
    <td>test_mininet_verify_host_status_in_onos_controller_with_removing_one_mininet_host</td>
    <td>Create mininet topology
Remove one host and verify it reflects in onos controller </td>
    <td>Hosts removed in mininet, should also removed in onos ‘hosts’</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_20</td>
    <td>Verify pushing mac flows in ONOS for mininet devices IDs</td>
    <td>test_mininet_verifying_pushing_mac_flows_from_onos_controller_to_mininet_switches</td>
    <td>Create mininet topology
Add mac flows in onos controller for mininet switches device IDs </td>
    <td>Should be able to add flows in onos </td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_21</td>
    <td>Verify pushing IPv4  flows in ONOS for mininet devices IDs</td>
    <td>test_mininet_verifying_pushing_ipv4_flows_from_onos_controller_to_mininet_switches</td>
    <td>Create mininet topology
Add ipv4 flows in onos controller for mininet switches device IDs </td>
    <td>Should be able to add flows in onos</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_22</td>
    <td>Verify pushing IPv6 flows in ONOS for mininet devices IDs</td>
    <td>test_mininet_verifying_pushing_ipv6_flows_from_onos_controller_to_mininet_switches</td>
    <td>Create mininet topology
Add ipv6 flows in onos controller for mininet switches device IDs </td>
    <td>Should be able to add flows in onos</td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_23</td>
    <td>Verify creating 50 switches topology in mininet and verify topology in ONOS </td>
    <td>test_mininet_topology_created_wit_50_switches_in_onos_controller</td>
    <td>Create mininet topology with 50 switches and 50 hosts </td>
    <td>Topology Creation should success and all 50 switches information should present in onos </td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_24</td>
    <td>Verify creating 200 switches topology in mininet and verify topology in ONOS</td>
    <td>test_mininettest_topology_created_wit_200_switches_in_onos_controller</td>
    <td>Create mininet topology with 200 switches and 200 hosts</td>
    <td>Topology Creation should success and all 200 switches information should present in onos </td>
    <td></td>
  </tr>
  <tr>
    <td>mininet_25</td>
    <td>Verify creating and deleting switches in mininet reflects properly in ONOS </td>
    <td>test_mininet_verifying_nodes_removed_in_mininet_status_in_onos_controller</td>
    <td>Cretae mininet topology with 50 switches and remove 20 switches
Verify removed switches status in onos controller </td>
    <td>Switches removed in mininet status should be ‘false’ in onos </td>
    <td></td>
  </tr>
</table>


