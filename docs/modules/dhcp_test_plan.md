**DHCP  Test Plan**

**DHCP Test Cases (Implemented and Planned) : **

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

