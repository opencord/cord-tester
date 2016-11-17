***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS ACL Application Functionality 1
  [Documentation]  Test ONOS ACL Application for allow rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 2
  [Documentation]  Test ONOS ACL Application for allow rule with 24 bit mask
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule_with_24_bit_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 3
  [Documentation]  Test ONOS ACL Application for deny rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_deny_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 4
  [Documentation]  Test ONOS ACL Application for deny rule with 24 bit mask
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_deny_rule_with_24_bit_mask
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 5
  [Documentation]  Test ONOS ACL Application for add and remove a rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_add_remove_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 6
  [Documentation]  Test ONOS ACL Application for add and remove all rules
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_add_remove_all_rules
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 7
  [Documentation]  Test ONOS ACL Application for remove all rules without add
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_remove_all_rules_without_add
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 8
  [Documentation]  Test ONOS ACL Application for allow and deny
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_and_deny_rule_for_same_src_and_dst_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 9
  [Documentation]  Test ONOS ACL Application for allow rule for matched dest IP
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rules_for_matched_dst_ips
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 10
  [Documentation]  Test ONOS ACL Application for matching src and dest IPs
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_with_matching_src_and_dst_ip_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 11
  [Documentation]  Test ONOS ACL Application for matching 24 bit src and dest IPs
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_with_matching_24bit_mask_src_and_dst_ip_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 12
  [Documentation]  Test ONOS ACL Application for non-matching IP traffic
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_with_non_matching_src_and_dst_ip_traffic
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 13
  [Documentation]  Test ONOS ACL Application for allow rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 14
  [Documentation]  Test ONOS ACL Application for allow rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 15
  [Documentation]  Test ONOS ACL Application for allow rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule
  Should Be Equal As Integers  ${rc}  0

Verify ONOS ACL Application Functionality 16
  [Documentation]  Test ONOS ACL Application for allow rule
  ${rc}=  Run Cord Tester  acl:acl_exchange.test_acl_allow_rule
  Should Be Equal As Integers  ${rc}  0

