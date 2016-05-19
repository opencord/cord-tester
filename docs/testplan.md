# **Cord-Tester**

##Test Cases (Implemented and Planned) : 


**IGMP**


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
</table>



**Authentication:**


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
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_7</td>
    <td>Verify EAP-TLS authentication with self signed client certification</td>
    <td>test_eap_tls_Self_Signed_Crt</td>
    <td>1. Send EAPOL start message from the client . 
2.  Send EAP response with identity. 
3. Send Client Hello TLS payload .
4. Send Self signed Client Hello TLS Certificate.
 </td>
    <td>1. Got EAP Request for identity. 
2. Got hello request for id.
3. Got cert request.
4. Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Auth_8</td>
    <td>Verify EAP-TLS authentication with 2 RGs having the same valid TLS certificate</td>
    <td>test_eap_tls_2RGs_SameValid_Crt</td>
    <td>1.Let one RG start with EAPOL message using the valid TLS certificate.
2. Let 2nd RG start with EAPOL message using the same TLS certificate.</td>
    <td>Access reject message should be seen from ONOS or socket should get timed out.
 </td>
    <td>Pass</td>
  </tr>
</table>


**DHCP:**


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
   If the IP address cannot be used by the client, the DHCP server responds with a DHCPNak message. If this occurs, the client restarts the lease process.</td>
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
    <td>1. Make the DHCP server down after getting an IP address for the client. 
2. Now make the DHCP server up.</td>
    <td>1. Since the server is down, the client receives no reply from the server and it  will regularly re-transmit the unicast DHCPREQUEST to the server. DHCP request message is now broadcasted to all other servers
If no response is received by the time the lease expires, it transitions to the INIT state to get a new lease
2. If the DHCP server is up within the lease time, DHCP Ack message is being sent back to the client.
After the lease time expires, DHCP discover message is broadcasted from the client.</td>
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
    <td>1. Send a lot of dummy DHCP requests, with random source Mac address (using Scapy)</td>
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
    <td>DHVP_15</td>
    <td>Verify sending DHCP discover packet twice</td>
    <td>test_dhcp_same_client_multiple_discover</td>
    <td>Send DHCP discover packet twice from the client.</td>
    <td>DHCP server should give the same ip to the client.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_16</td>
    <td>Verify sending DHCP request packet twice</td>
    <td>test_dhcp_same_client_multiple_request</td>
    <td>Send the DHCP request packet twice form the client</td>
    <td>DHCP Ack should be sent.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_17</td>
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
    <td>DHCP_18</td>
    <td>Verify  ip address assignment is successful when desired ip is sent.</td>
    <td>test_dhcp_client_desired_address</td>
    <td>Send a DHCP discover packet with the desired ip which is in the server address pool.
 </td>
    <td>DHCP ip address assignment should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_19</td>
    <td>Verify  ip address assignment when desired ip is sent which is out of the pool.</td>
    <td>test_dhcp_client_desired_address_out_of_pool</td>
    <td>Send a DHCP discover packet with the desired ip which is out of the  server address pool.
 </td>
    <td>DHCP NAK message should be sent</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>DHCP_20</td>
    <td>Verify  ip address assignment with the lease time information specified.</td>
    <td>test_dhcp_lease_packet</td>
    <td>Send a DHCP discover packet with the least time mentioned.</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td>Fail</td>
  </tr>
  <tr>
    <td>DHCP_21</td>
    <td>Verify sending N releases from the client</td>
    <td>test_dhcp_Nrelease</td>
    <td>Send multiple DHCP release packet from the client to the server</td>
    <td>All IP addresses should get released back to the server and should be able to rediscover</td>
    <td>Pass</td>
  </tr>
</table>


** **

** **

**Subscriber :**

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
    <td>Subs_1</td>
    <td>Verify subscriber joining and receiving traffic</td>
    <td>test_subscriber_join_recv</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to a particular group.
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. Interface should receive traffic.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Subs_2</td>
    <td>Verify joining and jumping to the next channel for channel surfing</td>
    <td>test_subscriber_join_jump</td>
    <td>1. Send a EAPOL start message for TLS authentication.
2.  Jump to the next ip.
3. Jump to the next channel and verify the traffic
 </td>
    <td>1. TLS authentication should be successful. 
2. IP address should be assigned to client.
3. Interface should receive traffic. Also it should show the jump RX stats for subscriber.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Subs_3</td>
    <td>Verify subscriber TLS authentication by sending invalid client certificate</td>
    <td> </td>
    <td>1. Send an invlaid Client Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.
 </td>
    <td>1. Authentication should not be successful.
2. Subscriber should not receive any ip from DHCP server. </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_4</td>
    <td>Verify subscriber TLS authentication by sending no client certificate</td>
    <td> </td>
    <td>1. Send an blank Client Hello TLS Certificate.
2. Send a DHCP discover packet from the subscriber.
 </td>
    <td>1.Authentication should not be successful. 
2.Subscriber should not receive any ip from DHCP server. </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_6</td>
    <td>Verify 2 subscribers TLS authentication</td>
    <td> </td>
    <td>1.Let one RG start with EAPOL message using the valid TLS certificate.
2. Let 2nd RG start with EAPOL message using the same TLS certificate.
3. Send a DHCP discover message to fetch the ip address. </td>
    <td>(1 &2 )Access reject message should be seen from ONOS or socket should get timed out.
3. IP address assignment should not be successful.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_7</td>
    <td>Verify subscriber TLS authentication by sending wrong username</td>
    <td> </td>
    <td>1. Send a EAPOL message with wrong user.
2. Send a DHCP discover packet from the client</td>
    <td>1. TLS authentication should not be successful.
2. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_8</td>
    <td>Verify subscriber TLS authentication by sending correct username and wrong password</td>
    <td> </td>
    <td>1. Send EAP response with MD5 challenge with wrong password.
2. Send a DHCP discover packet from the client.</td>
    <td>1. TLS authentication should not be successful.
2. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_9</td>
    <td>Verify subscriber TLS authentication by sending wrong username and wrong password</td>
    <td> </td>
    <td>1. Send a EAPOL message with wrong user.
2. Send EAP response with MD5 challenge with wrong password.
3. Send a DHCP discover packet from the client.</td>
    <td> 1. TLS authentication should not be successful.
3. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_10</td>
    <td>Verify subscriber joining and receiving traffic using MD5 authentication </td>
    <td> </td>
    <td>1. Send a EAPOL start message for MD5 authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to a particular group.
 </td>
    <td>1. MD5 authentication should be successful.
2. IP address should be assigned to client. 
3. Interface should receive traffic</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_11</td>
    <td>Verify subscriber MD5 authentication by sending wrong username</td>
    <td> </td>
    <td>1. Send a EAPOL message with wrong user. 
2. Send a DHCP discover packet from the client</td>
    <td>1. MD5 authentication should not be successful.
2. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_12</td>
    <td>Verify subscriber MD5 authentication by sending correct username and wrong password</td>
    <td> </td>
    <td>1. Send EAP response with MD5 challenge with wrong password.
2.  Send a DHCP discover packet from the client</td>
    <td>1. MD5 authentication should not be successful.
2. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_13</td>
    <td>Verify subscriber MD5 authentication by sending wrong username and wrong password</td>
    <td> </td>
    <td>1. Send a EAPOL message with wrong user.
2. Send EAP response with MD5 challenge with wrong password.
3.  Send a DHCP discover packet from the client</td>
    <td>1. MD5 authentication should not be successful.
3. IP address should not  be assigned to client.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_14</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending invalid client certificate. </td>
    <td> </td>
    <td>4. Let  1 subscriber join the group.
5. For the 2nd subscriber , Send an invalid Client Hello TLS Certificate.
6. Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface.
2.  TLS authentication should not be successful.
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_15</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending no client certificate. </td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a blank Client Hello TLS Certificate.
3. Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_16</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending self signed client certificate.</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a self signed Client Hello TLS Certificate.
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_17</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending wrong username</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with wrong username
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td> </td>
  </tr>
  <tr>
    <td>Subs_18</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending correct username and wrong password</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with correct username and wrong password.
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_19</td>
    <td>Verify 2 subscribers joining but 1  subscriber authentication failure by sending wrong username and wrong password</td>
    <td> </td>
    <td> 1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with wrong username and wrong password.
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_20</td>
    <td>Verify 2 subscribers joining but 1  subscriber with MD5 method</td>
    <td> </td>
    <td>1. Let 1st subscriber join the group with TLS authentication.
2. Let 2nd subscriber join with MD5 authentication.
3. Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on joining interface.
2. 2nd subscriber should receive traffic on joining interface.
3. IP address assignment should be successful for both the subscribers</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_21</td>
    <td>Verify 2 subscribers joining but 1  subscriber MD5 authentication failure by sending wrong username</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with wrong username
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_22</td>
    <td>Verify 2 subscribers joining but 1  subscriber MD5 authentication failure by sending wrong password and correct username</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with correct username and wrong password.
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_23</td>
    <td>Verify 2 subscribers joining but 1  subscriber MD5 authentication failure by sending wrong password and wrong username</td>
    <td> </td>
    <td>1. Let  1 subscriber join the group. 
2. For the 2nd subscriber , Send a EAPOL start message with wrong username and wrong password.
3.  Check for DHCP ip address assignment for both the subscribers.</td>
    <td>1. 1st subscriber should receive traffic on the joining interface. 
2.  TLS authentication should not be successful. 
3. IP address assignment should be successful only for 1st subscriber.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_24</td>
    <td>Verify ip address assignemt failure due to lack of DHCP address in the pool.</td>
    <td> </td>
    <td>1. Send EAPOL start message to authenticate the subscriber.
2. Send a DHCP discover packet to the server where there are no ip address in the server adress pool.</td>
    <td>1. Authentication is successful.
2. DHCP server should not allocate ip adress to the client.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_25</td>
    <td>Verify ip address assignment successful when subscriber renews ip after DHCP lease time</td>
    <td> </td>
    <td>1. Let the lease time get over.
2.  DHCP request which is unicast is being sent to the server. </td>
    <td>DHCP Ack should get received since the server is up and reachable.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_26</td>
    <td>Verify ip address assignment is successful when DHCP discover is sent twice.</td>
    <td> </td>
    <td>Send DHCP discover message twice from the client.</td>
    <td>DHCP server should give the same ip to the client using the DHCP Ack packet. </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_27</td>
    <td>Verify ip address assignment is successful when DHCP request is sent twice.</td>
    <td> </td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message.
3. Again send DHCP request message. </td>
    <td>1. DHCP offer should be sent from the server.
2. DHCP Ack should get received.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_28</td>
    <td>Verify ip address assignment when dhcp request and offer ip are different </td>
    <td> </td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message with a different ip.
 </td>
    <td>1. DHCP offer should be sent from server.
2. DHCP NAK should be sent from the server.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_29</td>
    <td>Verify subscriber ip address assignment is successful when desired ip is sent.</td>
    <td> </td>
    <td>Send a DHCP discover packet with the desired ip which is in the server address pool.</td>
    <td>DHCP ip address assignment should be successful.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_30</td>
    <td>Verify subscriber ip address assignment when desired ip is sent which is out of the pool.</td>
    <td> </td>
    <td>Send a DHCP discover packet with the desired ip which is out of the  server address pool</td>
    <td>DHCP NAK message should be sent</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_31</td>
    <td>Verify subscriber ip address assignement with the lease time information specified.</td>
    <td> </td>
    <td>Send a DHCP discover packet with the least time mentioned.</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_32</td>
    <td>Verify the DHCP process when the subscriber becomes down and  up.</td>
    <td> </td>
    <td>After DHCP address assignment to the client, make the subscriber down and then make it up.</td>
    <td>Once its up, DHCP request message should be sent from the client to the server which is unicast.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_33</td>
    <td>Verify the DHCP process when the DHCP server becomes down and  up.</td>
    <td> </td>
    <td>1. Send a DHCP discover packet .
2. Send a DHCP request packet from the client.
3. Make the DHCP server down.
4. Make the DHCP server up.</td>
    <td>1. DHCP offer packet generated.
2. DHCP Ack packet generated.
3. Client should have the same ip till the lease time expires.
4. DHCP Ack should be sent from the server. </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_34</td>
    <td>Verify the DHCP process of the subscriber after T1 timer expiry</td>
    <td> </td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server</td>
    <td>Since the server is up and reachable , it should respond back with DHCP Ack packet.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_35</td>
    <td>Verify ip address assignment failure due to lack of DHCP address in the pool for one subscriber </td>
    <td> </td>
    <td>1. Let 1st subscriber send a discover message.
2. Now 2nd subscriber will send a discover message to a server where there is no ip address available.</td>
    <td>1. Ip address assignment should be  successful.
2. DHCP NAK should be sent.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_36</td>
    <td>Verify ip address assignment is successful when one subscriber renews ip after DHCP lease time</td>
    <td> </td>
    <td>1. Let the lease time get over for the 2nd subscribe
2.  DHCP request which is unicast is being sent to the server. </td>
    <td>DHCP Ack should get received to the subscribers since the server is up and reachable.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_37</td>
    <td>Verify ip address assignment is successful when DHCP discover is sent twice by 2nd subscriber.</td>
    <td> </td>
    <td>Send DHCP discover message twice from the 2nd Subscriber</td>
    <td>DHCP server should give the same ip to the client using the DHCP Ack packet. </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_38</td>
    <td>Verify ip address assignment is successful when DHCP request is sent twice by 2nd subscriber.</td>
    <td> </td>
    <td>Send a DHCP discover message from the client1 and client 2.
 Send DHCP request message.
3. Again send DHCP request message from      client 2.</td>
    <td>1. DHCP offer should be sent from the server.
DHCP Ack should get received on both the clients..</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_39</td>
    <td>Verify ip address assignment when dhcp request and offer  ip are different for 2nd subscriber</td>
    <td> </td>
    <td>1. Send a DHCP discover message from the client.
2. Send DHCP request message with a different ip from the subscriber 2.
 </td>
    <td>1. DHCP offer should be sent from server.
2. DHCP NAK should be sent from the server to subscriber2.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_40</td>
    <td>Verify ip address assignment is successful when desired ip is sent by the 2nd subscriber.</td>
    <td> </td>
    <td>Send a DHCP discover packet with the desired ip which is in the server address pool by the 2nd subscriber</td>
    <td>DHCP ip address assignment should be successful.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_41</td>
    <td>Verify subscriber ip address assignment when desired ip is sent which is out of the pool by the 2nd subscriber. </td>
    <td> </td>
    <td>Send a DHCP discover packet with the desired ip which is out of the  server address pool by the 2nd subscriber.</td>
    <td>DHCP NAK message should be sent to the subscriber2.
IP address assignment should be successful for subscriber 1.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_42</td>
    <td>Verify subscriber ip address assignement with the lease time information specified by 2nd subscriber</td>
    <td> </td>
    <td>Send a DHCP discover packet with the least time mentioned by t he 2nd subscriber.</td>
    <td>DHCP ip address assignment should be successful with the mentioned lease time.</td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_43
</td>
    <td>Verify the DHCP process when the subscriber2 becomes down and  up.
</td>
    <td></td>
    <td>After DHCP address assignment to the client, make the subscriber2 down and then make it up.</td>
    <td>Once its up, DHCP request message should be sent from the client to the server which is unicast.
Subscriber1 should not get disturbed.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_44</td>
    <td>Verify the DHCP process when the DHCP server becomes down and  up w.r.t  2 subscribers.</td>
    <td> </td>
    <td>Send a DHCP discover packet from both the clients .
Send a DHCP request packet from both the clients.
Make the DHCP server down
Make the DHCP server up.</td>
    <td>DHCP offer packet generated for both the clients.
 DHCP Ack packet generated for both the clients.
3. Clients should have the same ip till the lease time expires.
4. DHCP Ack should be sent from the server.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_45</td>
    <td>Verify the DHCP process of the subscriber2 after T1 timer expiry</td>
    <td> </td>
    <td>After T1 timer expires, a DHCP request message which is unicast is being sent to the same server from the subscriber2</td>
    <td>Since the server is up and reachable , it should respond back with DHCP Ack packet.
Subscriber1 should not get disturbed.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_46</td>
    <td>Verify Subscriber joining to 1 channel</td>
    <td> </td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to one channel
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. Interface should receive traffic for that particular channel.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
  <tr>
    <td>Subs_47</td>
    <td>Verify subscriber joining to 10 channels.</td>
    <td> </td>
    <td>1. Send a EAPOL start message for TLS authentication.
2. Send a DHCP discover packet from the client.
3. Verify joining to 10 channels.
 </td>
    <td>1. TLS authentication should be successful.
2. IP address should be assigned to client.
3. Interface should receive traffic for all the channels respectively.
 </td>
    <td>To Be Implemeneted</td>
  </tr>
</table>


**Vrouter :**

 

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
    <td></td>
    <td></td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_2</td>
    <td>Test vrouter with 10000 routes</td>
    <td></td>
    <td></td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_3</td>
    <td>Test vrouter by installing 5 routes, removing Quagga and re-starting Quagga back</td>
    <td></td>
    <td></td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_4</td>
    <td>Test vrouter by installing 50 routes, removing Quagga and re-starting Quagga back</td>
    <td></td>
    <td></td>
    <td>Route installation should be successfull</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_5</td>
    <td>Test vrouter with 5 routes with 2 peers</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_6</td>
    <td>Test vrouter with 6 routes with 3 peers</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_7</td>
    <td>Test vrouter with 50 routes</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_8</td>
    <td>Test vrouter with 50 routes and 5 peers</td>
    <td></td>
    <td></td>
    <td>It should be successful..</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_9</td>
    <td>Test vrouter with 100 routes</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_10</td>
    <td>Test vrouter with 100 routes and 10 peers</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_11</td>
    <td>Test vrouter with 300 routes</td>
    <td></td>
    <td></td>
    <td>It should be successful.</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_12</td>
    <td>Test vrouter with 1000 routes</td>
    <td></td>
    <td></td>
    <td>It should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_13</td>
    <td>Test vrouter with 25000 routes</td>
    <td></td>
    <td></td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_14</td>
    <td>Test vrouter with 250000 routes</td>
    <td></td>
    <td></td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
  <tr>
    <td>Vrouter_!5</td>
    <td>Test vrouter with 100000 routes</td>
    <td></td>
    <td></td>
    <td>Route installation should be successful</td>
    <td>Pass</td>
  </tr>
</table>


 

**IPV6:**

 

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
    <td></td>
    <td>1. Add 2 IPV6 hosts .
2. Check in the cli</td>
    <td>Command "hosts" should show IPV6 hosts.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_2</td>
    <td>Verify IPv6 Neighbor Solicitation message</td>
    <td></td>
    <td>Send an ICMPv6 packet with type as 134. </td>
    <td>Neighbor should be advertised</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_3</td>
    <td>Verify IPv6 Neighbor Advertisement</td>
    <td></td>
    <td>Send a NS message from the host and check for Neighbor advertisement message </td>
    <td>A value of 136 should be captured in the Type field of ICMP packet header.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_4</td>
    <td>Verify ICMP6 Ping </td>
    <td></td>
    <td>Do an ICMPv6 ping from one host to another</td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_5</td>
    <td>Verify IPv6 Host Intent Addition</td>
    <td></td>
    <td>1. Add point intents between 2 IPV6 hosts.
2. Check ping between the hosts </td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_6</td>
    <td>Verify Point Intent Addition matching on port numbers</td>
    <td></td>
    <td>1. Add point intents between 2 IPV6 hosts matching on port numbers.
2. Check ping between the hosts </td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_7</td>
    <td>Verify Installing 300 host intents and verify ping all</td>
    <td></td>
    <td>1. Add 300 point intents.
2. Ping all across all hosts to test connectivity</td>
    <td>1. 300 point intents should get successfully installed.
2. Ping should be successful.
 </td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_8</td>
    <td>Randomly bring some core links down and verify ping all</td>
    <td></td>
    <td>1. Bring down the core links.
2. Check ping between the hosts.</td>
    <td>Even during link down state, connectivity still exists via reroute and ping should be successful.
 </td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_9</td>
    <td>Bring core links Up that were down and verify ping all</td>
    <td></td>
    <td>1. Bring the links that were down to up.
2. Check ping between the hosts.</td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_10</td>
    <td>Verify Intents with VLAN-id</td>
    <td></td>
    <td>1. Add point intents with vlan id .
2. Check hosts command in ONOS.
3. Verify ping between the hosts.</td>
    <td>2.“Hosts”command should discover correct vlan tag.
3. Ping should be successful.
 </td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_11</td>
    <td>Verify the INSTALLED state in intents</td>
    <td></td>
    <td>Rewrite mac address action in multi point to single point intent.
Check the cli command “Intents “</td>
    <td> Intent's state should be INSTALLED</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_12</td>
    <td>Verify the ping after removing the intents between the hosts.</td>
    <td></td>
    <td>1. Remove the previously added intents.
2. Check for ping between hosts.</td>
    <td>Ping should fail.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_13</td>
    <td>Verify Modify IPv6 Source Address</td>
    <td></td>
    <td>1. Configure and connect the Primary-controller. 
2. Create a flow with action OFPAT_SET_NW_SRC and output to an egress port. 
3. Send matching packet to ingress port. </td>
    <td>packet gets output to egress port with correct IPv6 source address as specified in the flow.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_14</td>
    <td>Verify Modify IPv6 destination address</td>
    <td></td>
    <td>1. Configure and connect the Primary-controller. 
2. Create a flow with action OFPAT_SET_NW_DST and output to an egress port. 
3. Send matching packet to ingress port. </td>
    <td>packet gets output to egress port with correct IPv6 destination address as specified in the flow</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_15</td>
    <td>Verify ping between the IPV6 hosts where muti point to single point intent is added</td>
    <td></td>
    <td>1. Add a multi point to single point intent related SDNIP matching on IP Prefix and rewriting the mac address.
2. Verify the ping </td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>IPV6_16</td>
    <td>Check the ping after adding bidirectional point intents </td>
    <td></td>
    <td>1. Add a bidirectional point intents between 2 packet layer devices.
2. Verify the ping</td>
    <td>Ping should be successful.</td>
    <td></td>
  </tr>
</table>


** **

 

**Flows:**

 

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
    <td>Simple packet flow</td>
    <td></td>
    <td>Send a simple packet using scapy with just an IP frame</td>
    <td>Packet should be received in ONOS</td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_2</td>
    <td>Ethernet frame packet</td>
    <td></td>
    <td>Add a flow with only the MAC address</td>
    <td>Packets should be received by filtering for only the mac address</td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_3</td>
    <td>Ethernet and IP frame packet</td>
    <td></td>
    <td>Add a flow with an IPv4 src, dst, and ethernet type selectors specified</td>
    <td>Packets should be received by filtering for only IP packets</td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_4</td>
    <td>Ethernet frame and VLAN tag packet</td>
    <td></td>
    <td>Add a flow with the VLAN selector specified</td>
    <td>Packets should be received by filtering on the VLAN interface and for packets with a VLAN tag
 </td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_5</td>
    <td>Ethernet frame and MPLS label packet</td>
    <td></td>
    <td>Add a flow with the MPLS selector specified</td>
    <td>Packets should be received by filtering for the specified MPLS label</td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_6</td>
    <td>Ethernet, IP, and TCP frame</td>
    <td></td>
    <td>Add a flow with the TCP dst, ethernet type, and ip protocol selectors specified</td>
    <td>Packet should be received by filtering for only TCP packets.
 </td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_7</td>
    <td>Ethernet, IP, and UDP frame</td>
    <td></td>
    <td>Add a flow with the UDP dst, ethernet type, and ip protocol selectors specified</td>
    <td>Packets should be received by filtering for only UDP packets.</td>
    <td></td>
  </tr>
  <tr>
    <td>Flows_8</td>
    <td>Deletion of flows</td>
    <td></td>
    <td>Delete flows that were added</td>
    <td>HTTP response is 204</td>
    <td></td>
  </tr>
</table>


 

** **

**Metrics:**

**1. Install CollectD plugin which is in charging of reporting all metric values to ONOS through REST API.**

**2. Install ONOS and activate CPMan application to receive system metrics from CollectD**.

 

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
    <td></td>
    <td>POST /collector/cpu_metrics</td>
    <td>Collects CPU metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_2</td>
    <td>Collector- network I/O metrics</td>
    <td></td>
    <td>POST /collector/network_metrics</td>
    <td>Collects network I/O metrics include in/out-bound packets/bytes statistics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_3</td>
    <td>Collector-disk I/O metrics</td>
    <td></td>
    <td>POST /collector/disk_metrics</td>
    <td>Collects disk I/O metrics include read and write bytes</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_4</td>
    <td>Collector-system info</td>
    <td></td>
    <td>POST /collector/system_info</td>
    <td>Collects system information</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_5</td>
    <td>Collector-memory metrics</td>
    <td></td>
    <td>POST /collector/memory_metrics</td>
    <td>Collects memory metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_6</td>
    <td>Control-Memory metrics</td>
    <td></td>
    <td>GET /controlmetrics/memory_metrics</td>
    <td>List memory metrics of all network resources</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_7</td>
    <td>Control-message metrics</td>
    <td></td>
    <td>GET /controlmetrics/messages</td>
    <td>List control message metrics of all devices</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_8</td>
    <td>Control-message metrics</td>
    <td></td>
    <td>GET /controlmetrics/messages/{deviceId}</td>
    <td>List control message metrics of a given device</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_9</td>
    <td>Control-CPU metrics</td>
    <td></td>
    <td>GET /controlmetrics/cpu_metrics</td>
    <td>List CPU metrics</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_10</td>
    <td>Control-disk metrics</td>
    <td></td>
    <td>GET /controlmetrics/disk_metrics</td>
    <td>List disk metrics of all disk resources</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_11</td>
    <td>Verify the intent installation latency</td>
    <td></td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.                                      3.Install a single intent from the CLI
 </td>
    <td>Command :
onos:intents-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_12</td>
    <td>Verify the intent installation latency in JSON format</td>
    <td></td>
    <td>1. Install the intent metrics feature by  "onos-app-metrics-intent" in the ONOS_FEATURE configuration list.
2. Load the "onos-app-metrics-intent" feature from the ONOS CLI while ONOS is running.
3. Install a single intent from the CLI</td>
    <td>Command :
onos:intents-events-metrics --json
Should show the information in json format.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_13</td>
    <td>Listing ONOS intent events</td>
    <td></td>
    <td>onos> onos:intents-events</td>
    <td>It should list 100 intent related events.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_14</td>
    <td>Verify topology event metrics</td>
    <td></td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics
Should show the detailed information of all the event rate and the last event timestamp</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_15</td>
    <td>Verify topology event metrics</td>
    <td></td>
    <td>Disable a switch port with a link connecting that switch to another one</td>
    <td>Command :
onos:topology-events-metrics --json
Should show the information in json format.</td>
    <td></td>
  </tr>
  <tr>
    <td>Metrics_16</td>
    <td>Listing topology events</td>
    <td></td>
    <td>onos> onos:topology-events</td>
    <td>This should list last 100 topology events.</td>
    <td></td>
  </tr>
</table>


 

 

**Platform tests:**

 

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
    <td></td>
    <td></td>
    <td>If its running, docker status should return true. </td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_2</td>
    <td>Pull (default) "onosproject/onos:latest" image</td>
    <td></td>
    <td></td>
    <td>Pulling should be successful.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_3</td>
    <td>Create new container for onos</td>
    <td></td>
    <td></td>
    <td>Container should get successfully created.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_4</td>
    <td>Get IP address on ONOS containers</td>
    <td></td>
    <td></td>
    <td>Container IPs should get listed.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_5</td>
    <td>check standalone apps status</td>
    <td></td>
    <td></td>
    <td>"drivers" app should be in ACTIVE state AND all builtin apps in "INSTALLED" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_6</td>
    <td>Activate "proxyarp" and "fwd" apps and check apps status</td>
    <td></td>
    <td></td>
    <td>It should be in "ACTIVE" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_7</td>
    <td>Deactivate "proxyarp" and "fwd" apps and check app status</td>
    <td></td>
    <td></td>
    <td>It should be in "Installed" state</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_8</td>
    <td>ONOS exceptions check</td>
    <td></td>
    <td></td>
    <td>After test, there should be no logs for exceptions.</td>
    <td></td>
  </tr>
  <tr>
    <td>Plat_9</td>
    <td>post-test clean env</td>
    <td></td>
    <td></td>
    <td>No containers and images should be left.</td>
    <td></td>
  </tr>
</table>


 

**Ovsdb:**

**Onos should be running well and Install feature ovsdb-web-provider ovsdb onos-core-netvirt on onos.**


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
    <td></td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS.
2.Configure ovs-vsctl del-manager tcp:{ip}:6640 on OVS.Check the OVSDB connection on ONOS. </td>
    <td>1.OVSDB connection is up.
2.OVSDB connection is down.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_2</td>
    <td>Default configuration of bridge and vxlan install</td>
    <td></td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1.
2.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1.Check the OVSDB connection on ONOS.Check the bridge and vxlan configuration on OVS1 and OVS2.</td>
    <td>1.OVS1 has an br_int.
2.OVS1 and OVS2 has br_int and vxlan tunnel.
3.ONOS devices add two sw.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_3</td>
    <td>OPENFLOW connection setup automatic</td>
    <td></td>
    <td>Single ONOS and one OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS.Check the Openflow connection on ONOS. </td>
    <td>OPENFLOW connection is up.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_4</td>
    <td>Default flow tables install</td>
    <td></td>
    <td>Single ONOS and two OVS
1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the default flow tables on OVS and ONOS.</td>
    <td>1.default flows is correct.</td>
    <td></td>
  </tr>
  <tr>
    <td>OVSDB_5</td>
    <td>Simulation VM go online check flow tables install</td>
    <td></td>
    <td>1.Configure ovs-vsctl set-manager tcp:{ip}:6640 on OVS1 and OVS2.Check the flow tables on OVS and ONOS.
2.Create a port on OVS1.Check the flow tables on OVS and ONOS.
3.Create a port on OVS2.Check the flow tables on OVS and ONOS.
 </td>
    <td>1.OVS and ONOS have default flows.
2.OVS and ONOS add correct flows.
3.OVS and ONOS add correct flows. </td>
    <td></td>
  </tr>
</table>


 

 

**Netconf:**

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
    <td></td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
2.  onos> devices</td>
    <td>Devices should be present in ONOS.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netconf_2</td>
    <td>Verify the logs in ONOS</td>
    <td></td>
    <td>1. Upload the configuration(netconf-cfg.json ) in the local host using curl command.
 2. onos> devices.
3. Onos>logs</td>
    <td>logs shouldn't contain NETCONF related exceptions</td>
    <td></td>
  </tr>
</table>


** **

 

**Proxy ARP:**

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
    <td>PRARP_1</td>
    <td>Verify if Proxy ARP is working properly</td>
    <td></td>
    <td>Send an ARP request to a host which is on the other side of the gateway</td>
    <td>Proxy ARP should repsond back to the ARP requests.</td>
    <td></td>
  </tr>
  <tr>
    <td>PRARP_2</td>
    <td>Verify that if the target host is on the same network, then proxy arp (ONOS)shouldnt respond</td>
    <td></td>
    <td>Send an ARP request to a host which is on the same network.</td>
    <td>Proxy ARP (ONOS) shouldn't respond.</td>
    <td></td>
  </tr>
  <tr>
    <td>PRARP_3</td>
    <td>Check the behavior when the Destination route is not in the table</td>
    <td></td>
    <td>Let the destination route be not present in the config file.</td>
    <td>Packets should get dropped.</td>
    <td></td>
  </tr>
  <tr>
    <td>PRARP_4</td>
    <td>Check the behavior when proxy arp is disabled.</td>
    <td></td>
    <td>1. Send an ARP request which is on different network.
2. Disable the Proxy ARP.</td>
    <td>Packets should get dropped.</td>
    <td></td>
  </tr>
</table>


 

 

**Network config link provider:**

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
    <td></td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow</td>
    <td>There should be traffic flow over the links which are configured in netcfg.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_LP_2</td>
    <td>Verify the STRICT state</td>
    <td></td>
    <td>1. Configure the links in netcfg.
2. Check the traffic flow over the links which are not configured</td>
    <td>There should not be any traffic flow over the links which are configured in netcfg.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_LP_3</td>
    <td>Check for the error indication when source and destinat ion will not match</td>
    <td></td>
    <td>Configure a link in netcfg and check for the error indication when source and destination doesnt match </td>
    <td>A  link is created with an error indication, which allows the GUI to display an error indication to the user</td>
    <td></td>
  </tr>
</table>


** **

** **

**Network Configuration:**

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
    <td></td>
    <td> </td>
    <td>Installs and Uninstalls ONOS correctly</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_2</td>
    <td>check undiscovered device cfgs  are distributed to all nodes.
 </td>
    <td></td>
    <td>Add some device configurations for undiscovered devices and then check they are distributed to all 
nodes. </td>
    <td>The given NetCfgs should get added and distributed to all ONOS nodes</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_3</td>
    <td>Verify the Network Graph</td>
    <td></td>
    <td>Check that devices appear or don't appear in the Network Graph according to the initial NetCfgs</td>
    <td>Allowed devices should appear and the disallowed devices shouldn’t appear in Network graph.</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_4</td>
    <td>check discovered device cfgs  are distributed to all nodes</td>
    <td></td>
    <td>Add some device configurations for discovered devices and then check they are distributed to all nodes.
 </td>
    <td>The given NetCfgs should get added and distributed to all ONOS nodes</td>
    <td></td>
  </tr>
  <tr>
    <td>Netcfg_5</td>
    <td>Remove Network Configurations.</td>
    <td></td>
    <td>Remove Network Configurations using different methods. I.E. delete a device, delete multiple devices, delete all configs</td>
    <td>The deleted NetCfgs should get deleted from all the nodes.</td>
    <td></td>
  </tr>
</table>


 

 

**Reactive Routing:**

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
    <td></td>
    <td>Configure 2 hosts to be in SDN network . Check the traffic flow</td>
    <td>There should be traffic flow between 2 hosts</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_2</td>
    <td>Verify the traffic flow from SDN host to internet host.</td>
    <td></td>
    <td>Configure one host in SDN network and another host in internet.
Check the traffic flow</td>
    <td>There should be traffic flow from SDN network to internet</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_3</td>
    <td>Verify the traffic flow from internet host to SDN host.</td>
    <td></td>
    <td>Configure one host in internet and another host in SDN network.
Check the traffic flow</td>
    <td>There should be a traffic flow from internet host to SDN network.</td>
    <td></td>
  </tr>
  <tr>
    <td>RR_4</td>
    <td>Verify the traffic drop when there is no matchable ip prefix</td>
    <td></td>
    <td>Send a traffic from one host to another host which is not matching with the file sdnip.json
 </td>
    <td>Packets should get dropped.</td>
    <td></td>
  </tr>
</table>


 

 

 

 

