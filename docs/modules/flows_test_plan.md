**Flow Install  Test Plan**

**Flow Install Test Cases (Implemented and Planned) : **

**This is to verify that the flow subsystem is compiling flows correctly.**

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

