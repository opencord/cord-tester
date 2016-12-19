**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**● Functional Testing**

**● Regression testing for CORD related component development**

**● Acceptance testing of a deployed CORD POD**

**● Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Mininet Test Cases (Implemented and Planned) : **

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

