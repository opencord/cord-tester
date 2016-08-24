**ACL  Test Plan**

**ACL Test Cases (Implemented and Planned) : **
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
