**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Test Cases (Implemented and Planned) :**

**vSG** - **Virtual Subscriber Gateway**

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
    <td>vsg_1</td>
    <td>Verify Ping to all vsg vms success</td>
    <td>test_vsg_health</td>
    <td>1. Login to compute node
2. Ping to all vSG VMs </td>
    <td>All the vSGs should be reachable </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_2</td>
    <td>Verify Ping to specific vSG VM</td>
    <td>test_vsg_health_check</td>
    <td>1. Login to compute node
2. Ping to specified vSG VM</td>
    <td>vSG should be reachable </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_3</td>
    <td>Verify at least  one vSG vm and compute node combination exists in setup</td>
    <td>test_vsg_for_vcpe</td>
    <td>Get all compute nodes
Get all vSG VMs</td>
    <td>At least one compute node and one vSG VM should exists  </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_4</td>
    <td>Verify accessing to vSG VM </td>
    <td>test_vsg_for_login</td>
    <td>1. Login to compute node VM
2. Get all vSGs
3. Verifying login to vSG is success
</td>
    <td>Login to vSG VM should success </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_5</td>
    <td>Verify default route exists in test client to vcpe instance</td>
    <td>test_vsg_for_default_route_through_testclient</td>
    <td>Login to head node
Get default route output on test client </td>
    <td>A default route should exist in test client  </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_6</td>
    <td>Verify external connectivity via vcpe container from test client </td>
    <td>test_vsg_for_external_connectivity_through_testclient</td>
    <td>Login to head node
Execute command  in test client to ping to external network </td>
    <td>External network should be reachable from test client </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_7</td>
    <td>Verify external connectivity via vcpe instance from cord-tester</td>
    <td>test_vsg_for_external_connectivity</td>
    <td>Get dhcp IP to vcpe interface
Ping to the external network </td>
    <td>Should be able to reach external network from cord-tester  via vcpe instance </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_8</td>
    <td>Verify external connectivity to google from cord-tester via vcpe instance </td>
    <td>test_vsg_for_external_connectivity_to_google</td>
    <td>1. Get dhcp IP to vcpe interface
2. Ping to google </td>
    <td>Should be able to reach external network from cord-tester  via vcpe instance</td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_9</td>
    <td>Validate path mtu to google from cord-tester</td>
    <td>test_vsg_to_retrieve_content_from_google_to_validate_path_mtu</td>
    <td>Get dhcp IP to vcpe interface
Get google page contents
Validate path mtu </td>
    <td>Path mtu should be validated </td>
    <td> </td>
  </tr>
  <tr>
    <td>vsg_10</td>
    <td>Validate path mtu to rediff  from cord-tester</td>
    <td>test_vsg_to_retrieve_content_from_rediff_to_validate_path_mtu</td>
    <td>1. Get dhcp IP to vcpe interface
2. Get rediff  page contents
3. Validate path mtu</td>
    <td>Path mtu should be validated </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_11</td>
    <td>Validate path mtu to yahoo from cord-tester</td>
    <td>test_vsg_to_retrieve_content_from_yahoo_to_validate_path_mtu</td>
    <td>1. Get dhcp IP to vcpe interface
2. Get  yahoo page  contents
3. Validate path mtu</td>
    <td>Path mtu should be validated </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_12</td>
    <td>Validate path mtu to facebook from cord-tester</td>
    <td>test_vsg_to_retrieve_content_from_facebook_to_validate_path_mtu</td>
    <td>1. Get dhcp IP to vcpe interface
2. Get  facebook page contents
3. Validate path mtu</td>
    <td>Path mtu should be validated </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_13</td>
    <td>Verify external connectivity for invalid host from cord-tester via vcpe instance </td>
    <td>test_vsg_for_external_connectivity_to_invalid_host</td>
    <td>Get dhcp IP to vcpe interface
Try to ping to invalid external host </td>
    <td>Ping to invalid external host should be failed </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_14</td>
    <td>Verify external connectivity with ttl 1 from cord-tester via vcpe instance</td>
    <td>test_vsg_for_external_connectivity_with_ttl_1</td>
    <td>Get dhcp ip to vcpe interface
Ping to external IP with ttl 1 </td>
    <td>Ping to external should be failed </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_15</td>
    <td>Verify external connectivity from cord-tester withj  vcpe instance wan interface toggle </td>
    <td>test_vsg_for_external_connectivity_with_wan_interface_toggle_in_vcpe</td>
    <td>Get dhcp IP to vcpe interface
Ping to external network with vcpe container wan interface toggle </td>
    <td>Should be able to ping to external even after interface toggle </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_16</td>
    <td>Verify external connectivity from cord-tester withj  vcpe instance lan interface toggle </td>
    <td>test_vsg_for_external_connectivity_with_lan_interface_toggle_in_vcpe</td>
    <td>Get dhcp ip to vcpe interface
Ping to external network with vcpe container lan interface toggle </td>
    <td>Should be able to ping to external even after interface toggle </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_17</td>
    <td>Verify simulating multiple subscribers for same vcpe instance form cord-tester</td>
    <td>test_vsg_multiple_subscribers_for_same_vcpe_instace</td>
    <td>Configure multiple vcpe interfaces in cord-tester with same s and c tags
Get all the interfaces dhcp IPs
</td>
    <td>All the subscribe should get dhcp IP</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_18</td>
    <td>Verify external connectivity from multiple subscribers of same vcpe instance from cord-tester</td>
    <td>test_vsg_for_multiple_subscribers_with_same_vcpe_instance_and_validate_external_connectivity</td>
    <td>Configure multiple vcpe interfaces in cord-tester with same s and c tags
Get all the interfaces dhcp IPs
Ping to external network  </td>
    <td>Should be able to reach external network for all subscribers </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_19</td>
    <td>Verify subscriber gets dhcp ip after vcpe interface toggles in cord-tester</td>
    <td>test_vsg_vcpe_interface_and_validate_dhcp_ip_after_interface_toggle</td>
    <td>Get dhcp IP to vcpe interface
Toggle the interface and get dhcp IP again </td>
    <td>Vcpe Interface should get dhcp IP even after toggle </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_20</td>
    <td>Verify external connectivity from cord-tester via vcpe instance after the instance restart </td>
    <td>test_vsg_for_external_connectivity_after_restarting_vcpe_instance</td>
    <td>Get dhcp ip to vcpe interface
Ping to external network
Restart vcpe instance and ping again to external </td>
    <td>Should be able to reach external network even after vcpe restart  </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_21</td>
    <td>Verify external connectivity from cord-tester via vcpe instance after the vSG VM restart</td>
    <td>test_vsg_for_external_connectivity_after_restarting_vsg_vm</td>
    <td>1. Get dhcp ip to vcpe interface
2. Ping to external network
3. Restart vSG VM and ping again to external</td>
    <td>Should be able to reach external network even after vSG restart</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_22</td>
    <td>Verify external connectivity from cord-tester via vcpe instance after the instance paused</td>
    <td>test_vsg_for_external_connectivity_with_vcpe_container_paused</td>
    <td>1. Get dhcp ip to vcpe interface
2. Ping to external network
3. Pause  vcpe instance and ping again to external</td>
    <td>Should be able to reach external network even after vcpe paused </td>
    <td></td>
  </tr>
  <tr>
    <td>Vsg_firewall_23</td>
    <td>Verify vcpe firewall functionality to deny destination IP </td>
    <td>test_vsg_firewall_with_deny_destination_ip</td>
    <td>Get dhcp ip to  vcpe interface
Configure a static route via vcpe interface
Add  a deny dest ip firewall rule in vcpe instance
Ping to destination IP</td>
    <td>Ping to destination IP should fail after adding the rule </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_24</td>
    <td>Verify vcpe firewall functionality to deny destination IP with rule add and delete</td>
    <td>test_vsg_firewall_with_rule_add_and_delete_dest_ip</td>
    <td>1. Get dhcp ip to  vcpe interface
2. Configure a static route via vcpe interface
3. Add  a deny dest ip firewall rule in vcpe instance
4. Ping to destination IP
5. Delete the rule and ping again </td>
    <td>Ping to destination IP should fail after adding the rule and delete </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_25</td>
    <td>Verify non-denied IP address can  be reachable from cord-tester </td>
    <td>test_vsg_firewall_verifying_reachability_for_non_blocked_dest_ip</td>
    <td>1. Get dhcp ip to  vcpe interface
2. Configure a static route via vcpe interface
3. Add  a deny dest ip firewall rule in vcpe instance
4. Ping to destination IP
5. Ping to non-denied IP </td>
    <td>Ping to non-blocked  IP should success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_26</td>
    <td>Verify appending firewall rule in vcpe instance </td>
    <td>test_vsg_firewall_appending_rules_with_deny_dest_ip</td>
    <td>1. Get dhcp ip to  vcpe interface
2. Configure a firewall rule
3. Append one more rule </td>
    <td>Appending firewall rule should get success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_27</td>
    <td>Verify removing one firewall rule wont impact on remaining rules </td>
    <td>test_vsg_firewall_removing_one_rule_denying_dest_ip</td>
    <td>Get dhcp IP to vcpe interface
Configure two firewall rules
Remove one rule </td>
    <td>Removing  firewall rule should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_28</td>
    <td>Verify changing firewall rule id wont change functionality </td>
    <td>test_vsg_firewall_changing_rule_id_deny_dest_ip</td>
    <td>Get dhcp ip to vcpe interface
Configure firewall rule
Change the rule id </td>
    <td>Changing firewall rule should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_29</td>
    <td>Verify changing firewall rule action from deny to accept </td>
    <td>test_vsg_firewall_changing_deny_rule_to_accept_dest_ip</td>
    <td>1 Get dhcp ip to vcpe interface
2 . Configure deny firewall rule
3. Change the rule to accept </td>
    <td>Changing  firewall rule should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_30</td>
    <td>Verify firewall rule to deny destination network  </td>
    <td>test_vsg_firewall_denying_destination_network</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny dest network </td>
    <td>Firewall rule should success
</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_31</td>
    <td>Verify firewall rule to deny destination network with subnet modification </td>
    <td>test_vsg_firewall_denying_destination_network_subnet_modification</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny dest network
3. Change dest network in firewall rule  </td>
    <td>Subnet modification in firewall rule should success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_32</td>
    <td>Verify firewall to deny source IP</td>
    <td>test_vsg_firewall_with_deny_source_ip</td>
    <td>Get dhcp ip to vcpe interface
Configure firewall rule to deny source IP</td>
    <td>Firewall to deny source IP should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_33</td>
    <td>Verify firewall to deny source IP with rule add and deleted</td>
    <td>test_vsg_firewall_rule_with_add_and_delete_deny_source_ip</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny source IP
3. Delete the rule  </td>
    <td>Deleting a firewall rule should success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_34</td>
    <td>Verify firewall rule to deny icmp requests type packets </td>
    <td>test_vsg_firewall_rule_with_deny_icmp_protocol_echo_requests_type</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp requests messages </td>
    <td>Firewall to deny icmp should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_35</td>
    <td>Verify firewall rule to deny icmp reply type packets</td>
    <td>test_vsg_firewall_rule_with_deny_icmp_protocol_echo_reply_type</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp reply messages</td>
    <td>Firewall to deny icmp should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_36</td>
    <td>Verify firewall rule to change deny rule accept icmp requests type packets </td>
    <td>test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_requests_type</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp requests messages
3. Change the rule to accept </td>
    <td>Firewall to deny icmp should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_37</td>
    <td>Verify firewall rule to change deny rule accept icmp reply type packets </td>
    <td>test_vsg_firewall_changing_deny_rule_to_accept_rule_with_icmp_protocol_echo_reply_type</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp reply messages
3. Change the rule to accept </td>
    <td>Changing firewall rule should get success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_38</td>
    <td>Verify firewall rule to deny icmp protocol </td>
    <td>test_vsg_firewall_for_deny_icmp_protocol</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp protocol</td>
    <td>Firewall to deny icmp should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_39</td>
    <td>Verify firewall rule to deny both icmp protocol and destination IP</td>
    <td>test_vsg_firewall_rule_deny_icmp_protocol_and_destination_ip</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp protocol and dest IP </td>
    <td>Firewall to deny icmp should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_40</td>
    <td>Verify flushing all configured firewall rules </td>
    <td>test_vsg_firewall_flushing_all_configured_rules</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rules
3. Flush all the rules  </td>
    <td>All the rules should get deleted after flush </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_41</td>
    <td>Verify firewall rule to deny all IPv4 traffic </td>
    <td>test_vsg_firewall_deny_all_ipv4_traffic</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny IPv4 traffic </td>
    <td>All the IPv4 traffic should be blocked </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_42</td>
    <td>Verify replacing deny firewall with accept </td>
    <td>test_vsg_firewall_replacing_deny_rule_to_accept_rule_ipv4_traffic</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny IPv4 traffic
3. Change the rule to accept </td>
    <td>Replacing a rule should get success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_43</td>
    <td>Verify denying all the traffic coming lan interface on vcpe instance </td>
    <td>test_vsg_firewall_deny_all_traffic_coming_on_lan_interface_in_vcpe</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny lan traffic
 </td>
    <td>All the traffic on lan interface should be dropped </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_44</td>
    <td>Verify denying all the traffic going out on wan interface on vcpe instance </td>
    <td>test_vsg_firewall_deny_all_traffic_going_out_of_wan_interface_in_vcpe</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny wan traffic </td>
    <td>All the traffic on wan interface should be dropped </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_45</td>
    <td>Verify denying all the traffic flow from lan to wan  interface in vcpe instance </td>
    <td>test_vsg_firewall_deny_all_traffic_from_lan_to_wan_in_vcpe</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny lan to wan traffic </td>
    <td>All the traffic from  lan to wan interface should be dropped </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_46</td>
    <td>Verify denying all dns traffic via vcpe instance </td>
    <td>test_vsg_firewall_deny_all_dns_traffic</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny dns traffic </td>
    <td>All the DNS traffic should be dropped </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_firewall_47</td>
    <td>Verify deny all IPv4 traffic with vcpe restart </td>
    <td>test_vsg_firewall_deny_all_ipv4_traffic_vcpe_container_restart</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure firewall rule to deny icmp requests messages
3. Restart vcpe container </td>
    <td>After vcpe restart ping to external should work </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_nat_48</td>
    <td>Verify vsg nat with modifying destination IP address </td>
    <td>test_vsg_nat_dnat_modifying_destination_ip</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure DNAT rule </td>
    <td>DNAT rule should be able to configured </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_nat_49</td>
    <td>Verify vsg nat with modifying destination IP address and delete the rule </td>
    <td>test_vsg_nat_dnat_modifying_destination_ip_and_delete</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure DNAT rule
3. Delete the rule </td>
    <td>DNAT rule should be able to configured and delete </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_nat_50</td>
    <td>Verify vsg nat with modifying destination IP address with modifying the address </td>
    <td>test_vsg_nat_dnat_change_modifying_destination_ip_address</td>
    <td>1. Get dhcp ip to vcpe interface
2. Configure DNAT rule
3. Modify the destination IP in the rule </td>
    <td>DNAT rule should be able to  modify destination IP configured </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_51</td>
    <td>Verify creating default vcpe instance </td>
    <td>test_vsg_xos_subscriber_create_reserved</td>
    <td>1. Create default vcpe in default vSG VM</td>
    <td>Default vcpe creation should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_52</td>
    <td>Verify creating vcpe instance for interfaces created in cord-tester</td>
    <td>test_vsg_xos_subscriber_create_all</td>
    <td>1. Create vcpes using XOS for interfaces created in cord-tester </td>
    <td>Vcpes corresponding to interfaces created in cord-tester should be created </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_53</td>
    <td>Verify deleting vcpe instance for interfaces created in cord-tester</td>
    <td>test_vsg_xos_subscriber_delete_all</td>
    <td>2. Delete vcpes using XOS for interfaces created in cord-tester</td>
    <td>All vcpes  should be cleared </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_54</td>
    <td>Verify creating vcpe instance for  1st interface created in cord-tester</td>
    <td>test_vsg_xos_subscriber_create_and_delete</td>
    <td>1. Create vpce for 1st interface in cord-tester using XOS </td>
    <td>Should be able to create and delete vcpe by XOS</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_55</td>
    <td>Verify creating vcpe instance for  2nd interface created in cord-tester</td>
    <td>test_vsg_xos_subscriber_2_create_and_delete</td>
    <td>Create vpce for 2nd  interface in cord-tester using XOS</td>
    <td>Should be able to create and delete vcpe by XOS</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_56</td>
    <td>Verify creating vcpe instance for  3rd interface created in cord-tester</td>
    <td>test_vsg_xos_subscriber_3_create_and_delete</td>
    <td>Create vpce for 3rd interface in cord-tester using XOS</td>
    <td>Should be able to create and delete vcpe by XOS</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_57</td>
    <td>Verify creating vcpe instance for  4th interface created in cord-tester</td>
    <td>test_vsg_xos_subscriber_4_create_and_delete</td>
    <td>Create vpce for 4th interface in cord-tester using XOS</td>
    <td>Should be able to create and delete vcpe by XOS</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_58</td>
    <td>Verify creating vcpe instance for  5th interface created in cord-tester</td>
    <td>test_vsg_xos_subscriber_5_create_and_delete</td>
    <td>Create vpce for 5th  interface in cord-tester using XOS</td>
    <td>Should be able to create and delete vcpe by XOS</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_59</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS</td>
    <td>test_vsg_xos_subscriber_external_connectivity_through_vcpe_instance</td>
    <td>Create vpce for interface in cord-tester using XOS
Ping to external network from the interface </td>
    <td>External connectivity via XOS created vcpe should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_60</td>
    <td>Verify external connectivity from cord-tester via vcpe without created by XOS </td>
    <td>test_vsg_xos_subscriber_external_connectivity_without_creating_vcpe_instance</td>
    <td>1. Do not Create vpce for interface in cord-tester using XOS
2. Ping to external network from the interface </td>
    <td>External connectivity via XOS created vcpe should  not be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_61</td>
    <td>Verify external connectivity from cord-tester via vcpe  after created and removed by XOS</td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_remove_vcpe_instance_from_xos</td>
    <td>1. Create vpce for interface in cord-tester using XOS
2. Ping to external network from the interface
3. Remove the vcpe instance and ping again </td>
    <td>External connectivity via XOS created vcpe should  not be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_62</td>
    <td>Verify external connectivity from cord-tester via vcpe  after restarting vcpe created by XOS</td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_restart_vcpe_instance</td>
    <td>1. Create vpce for interface in cord-tester using XOS
2. Ping to external network from the interface
3. Restart the vcpe instance and ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_63</td>
    <td>Verify external connectivity from cord-tester via vcpe  after stop and start the vcpe created by XOS</td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_stop_and_start_vcpe_instance</td>
    <td>1. Create vpce for interface in cord-tester using XOS
2. Ping to external network from the interface
3. Stop and start vcpe instance and ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_64</td>
    <td>Verify creating vcpes in different vSG VMs</td>
    <td>test_vsg_create_xos_subscribers_in_different_vsg_vm</td>
    <td>1. Create vcpe instances in different vSG VMs</td>
    <td>Should be able to create vcpe in different vSG VMs</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_65</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vcpe  goes down</td>
    <td>test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_goes_down</td>
    <td>Create two vcpe instances
Ping to external via both vcpes
Kill one vcpe
Ping again </td>
    <td>External connectivity via active vcpe should be success </td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_66</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vcpe removed and added back </td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_vcpe_remove_and_add_again</td>
    <td>1. Create two vcpe instances
2. Ping to external via both vcpes
3. Remove and add one vcpe
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_67</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vcpe  restarts </td>
    <td>test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_restarts</td>
    <td>1. Create two vcpe instances
2. Ping to external via both vcpes
3. Restart one vcpe
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_68</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vcpe  pauses</td>
    <td>test_vsg_xos_multiple_subscribers_external_connectivity_if_one_vcpe_pause</td>
    <td>1. Create two vcpe instances
2. Ping to external via both vcpes
3. pause one vcpe
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_69</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vcpe  stops </td>
    <td>test_vsg_xos_subscriber_external_connectivity_if_one_vcpe_stops</td>
    <td>1. Create two vcpe instances
2. Ping to external via both vcpes
3. Stop one vcpe
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_70</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vSG VM stops</td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_vsg_vm_stop</td>
    <td>1. Create two vcpe instances in different vSG VMs
2. Ping to external via both vcpes
3. Stop one vSG VM
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_71</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vSG VM restarts </td>
    <td>test_vsg_xos_subscriber_external_connectivity_after_vsg_vm_restart</td>
    <td>Create two vcpe instances in different vSG VMs
2. Ping to external via both vcpes
3. Restart one vSG VM
4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_72</td>
    <td>Verify external connectivity from cord-tester via vcpe created by XOS if vSG VM stops and starts </td>
    <td>test_vsg_xos_multiple_subscribers_external_connectivity_if_two_vsgs_stop_and_start</td>
    <td>1. Create two vcpe instances in different vSG VMs
2. Ping to external via both vcpes
3. Stop two VMs and start 4. Ping again</td>
    <td>External connectivity via XOS created vcpe should be success</td>
    <td></td>
  </tr>
  <tr>
    <td>vsg_xos_subscriber_73</td>
    <td>Verify firewall functionality with XOS created vcpe </td>
    <td>test_vsg_xos_subscriber_external_connectivity_with_creating_firewall_rule</td>
    <td>Create a vcpe instance
Add firewall in vcpe </td>
    <td>Firewall functionality should work as per configured </td>
    <td></td>
  </tr>
</table>



