**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**? Functional Testing**

**? Regression testing for CORD related component development**

**? Acceptance testing of a deployed CORD POD**

**? Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Cord-Subscriber Test Cases (Implemented and Planned) :

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
