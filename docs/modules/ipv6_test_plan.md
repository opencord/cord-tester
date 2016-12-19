**Cord-Tester**



**CORD Automated Tester Suite:**

**The CORD Automated Tester Suite (CATS) is an extensible end-to-end system test suite targeting CORD PODs. It is typically deployed as one or more Docker containers, either on the CORD POD or adjacent to the POD and interacts with the POD through the PODs interfaces.**

**Its intended use includes:**

**? Functional Testing**

**? Regression testing for CORD related component development**

**? Acceptance testing of a deployed CORD POD**

**? Health-testing of an existing CORD POD (including non-service-impacting and possibly service-impacting tests)**

**Test Cases (Implemented and Planned) : **

**IPv6 Test Cases (Implemented and Planned) :


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
