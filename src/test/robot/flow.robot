***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS FLOWS Functionality 1
  [Documentation]  Test ONOS Flows functionality for mac flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 2
  [Documentation]  Test ONOS Flows functionality for IP flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 3
  [Documentation]  Test ONOS Flows functionality for tcp port flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_tcp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 4
  [Documentation]  Test ONOS Flows functionality for udp port flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_udp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 5
  [Documentation]  Test ONOS Flows functionality for vlan flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_vlan
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 6
  [Documentation]  Test ONOS Flows functionality for ipv6 flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ipv6
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 7
  [Documentation]  Test ONOS Flows functionality for ipv6 flow lable flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ipv6_flow_label
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 8
  [Documentation]  Test ONOS Flows functionality for ipv6 extension header flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ipv6_extension_header
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 9
  [Documentation]  Test ONOS Flows functionality for ipv6 available extentions headers flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ipv6_available_extension_headers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 10
  [Documentation]  Test ONOS Flows functionality for ip dscp flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_dscp
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 11
  [Documentation]  Test ONOS Flows functionality for available ip dscp flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_available_dscp
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 12
  [Documentation]  Test ONOS Flows functionality for ecn flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ecn
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 13
  [Documentation]  Test ONOS Flows functionality for available ecn flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_available_ecn
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 14
  [Documentation]  Test ONOS Flows functionality for available ip dscp and ecn flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_available_dscp_and_ecn
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 15
  [Documentation]  Test ONOS Flows functionality for icmp flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmp
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 16
  [Documentation]  Test ONOS Flows functionality for different types of icmp messages flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmp_different_types
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 17
  [Documentation]  Test ONOS Flows functionality for icmpv6 echo request flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_EchoRequest
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 18
  [Documentation]  Test ONOS Flows functionality for icmpv6 echo reply flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_EchoReply
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 19
  [Documentation]  Test ONOS Flows functionality for icmpv6 destination unreachable flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_DestUnreachable
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 20
  [Documentation]  Test ONOS Flows functionality for icmpv6 too big messages flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_PacketTooBig
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 21
  [Documentation]  Test ONOS Flows functionality for icmpv6 time exceeded messages flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_TimeExceeded
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 22
  [Documentation]  Test ONOS Flows functionality for icmpv6 parameter problem flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_ParameterProblem
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 23
  [Documentation]  Test ONOS Flows functionality for ipv6 neighbor discover flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_ND_Target_address
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 24
  [Documentation]  Test ONOS Flows functionality for ipv6 ND SLL flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_ND_SLL
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 25
  [Documentation]  Test ONOS Flows functionality for ipv6 NA TLL flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_icmpv6_NA_TLL
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 26
  [Documentation]  Test ONOS Flows functionality for ipv6 and icmpv6 flow
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_flow_ipv6_and_icmpv6
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 27
  [Documentation]  Test ONOS Flows functionality for constant dest mac 5 flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_5_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 28
  [Documentation]  Test ONOS Flows functionality for constant dest mac 500 flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 29
  [Documentation]  Test ONOS Flows functionality for constant dest mac 1k flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1k_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 30
  [Documentation]  Test ONOS Flows functionality for constant dest mac 10k flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_10k_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 31
  [Documentation]  Test ONOS Flows functionality for constant dest mac 100k flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_100k_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 32
  [Documentation]  Test ONOS Flows functionality for constant dest mac 1000k flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1000k_flow_constant_dst_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 33
  [Documentation]  Test ONOS Flows functionality for constant source mac 5 flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_5_flow_constant_src_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 34
  [Documentation]  Test ONOS Flows functionality for 500 mac flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 35
  [Documentation]  Test ONOS Flows functionality for 1k mac flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1k_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 36
  [Documentation]  Test ONOS Flows functionality for 10k mac flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_10k_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 37
  [Documentation]  Test ONOS Flows functionality for 100k mac flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_100k_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 38
  [Documentation]  Test ONOS Flows functionality for 1000k  mac flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1000k_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 39
  [Documentation]  Test ONOS Flows functionality for 100 mac flows rate
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_rate_100_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 40
  [Documentation]  Test ONOS Flows functionality for 500 mac flows rate
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_rate_500_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 41
  [Documentation]  Test ONOS Flows functionality for 1k mac flows rate
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_rate_1k_flow_mac
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 42
  [Documentation]  Test ONOS Flows functionality for 500 IP flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 43
  [Documentation]  Test ONOS Flows functionality for 1k IP flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1k_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 44
  [Documentation]  Test ONOS Flows functionality for 10k IP flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_10k_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 45
  [Documentation]  Test ONOS Flows functionality for 100k IP flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_100k_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 46
  [Documentation]  Test ONOS Flows functionality for 1000k IP  flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1000k_flow_ip
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 47
  [Documentation]  Test ONOS Flows functionality for 500 tcp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_tcp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 48
  [Documentation]  Test ONOS Flows functionality for 1k tcp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_1k_flow_tcp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 49
  [Documentation]  Test ONOS Flows functionality for 10k tcp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_10k_flow_tcp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 50
  [Documentation]  Test ONOS Flows functionality for 500 udp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_udp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 51
  [Documentation]  Test ONOS Flows functionality for 1k udp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_500_flow_udp_port
  Should Be Equal As Integers  ${rc}  0

Verify ONOS FLOWS Functionality 52
  [Documentation]  Test ONOS Flows functionality for 10k udp flows
  ${rc}=  Run Cord Tester  flows:flows_exchange.test_10k_flow_udp_port
  Should Be Equal As Integers  ${rc}  0

