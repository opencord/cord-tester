**CORD Subscriber Test Plan**

**CORD Subscriber Test Cases (Implemented and Planned) : **


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

