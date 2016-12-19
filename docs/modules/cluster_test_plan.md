**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Cluster **

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
