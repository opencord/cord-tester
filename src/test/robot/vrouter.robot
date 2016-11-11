***settings ***
Documentation  Run Cord verification test cases
Resource  cord_resource.robot
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown

*** Test Cases ***

Verify ONOS VROUTER Application Functionality 1
  [Documentation]  Test ONOS VROUTER Application with 5 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_5_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 2
  [Documentation]  Test ONOS VROUTER Application with 5 routes 2 peers
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_5_routes_2_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 3
  [Documentation]  Test ONOS VROUTER Application with 6 routes 3 peers
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_6_routes_3_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 4
  [Documentation]  Test ONOS VROUTER Application with 50 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_50_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 5
  [Documentation]  Test ONOS VROUTER Application with 50 routes 5 peers
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_50_routes_5_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 6
  [Documentation]  Test ONOS VROUTER Application with 100 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_100_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 7
  [Documentation]  Test ONOS VROUTER Application with 100 routes 10 peers
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_100_routes_10_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 8
  [Documentation]  Test ONOS VROUTER Application with 300 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_300_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 9
  [Documentation]  Test ONOS VROUTER Application with 1000 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_1000_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 10
  [Documentation]  Test ONOS VROUTER Application with 10000 routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_10000_routes
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 11
  [Documentation]  Test ONOS VROUTER Application with 100000 routes
  #${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_100000_routes
  #Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 12
  [Documentation]  Test ONOS VROUTER Application with 1000000 routes
  #${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_1000000_routes
  #Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 13
  [Documentation]  Test ONOS VROUTER Application with 5 routes stopping Quagga
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_5_routes_stopping_quagga
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 14
  [Documentation]  Test ONOS VROUTER Application with 50 routes stopping Quagga
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_50_routes_stopping_quagga
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 15
  [Documentation]  Test ONOS VROUTER Application with route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 16
  [Documentation]  Test ONOS VROUTER Application with class A route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classA_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 17
  [Documentation]  Test ONOS VROUTER Application with 5 class B route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classB_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 18
  [Documentation]  Test ONOS VROUTER Application with classless route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classless_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 19
  [Documentation]  Test ONOS VROUTER Application with class A duplicate route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classA_duplicate_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 20
  [Documentation]  Test ONOS VROUTER Application with class B duplicate route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classB_duplicate_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 21
  [Documentation]  Test ONOS VROUTER Application with classless duplicate route update
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_classless_duplicate_route_update
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 22
  [Documentation]  Test ONOS VROUTER Application with invalid peers
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_invalid_peers
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 23
  [Documentation]  Test ONOS VROUTER Application with traffic sent between peers
  #${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_traffic_sent_between_peers_connected_to_onos
  #Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 24
  [Documentation]  Test ONOS VROUTER Application with routes time expire
  #${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_routes_time_expire
  #Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 25
  [Documentation]  Test ONOS VROUTER Application with unreachable routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_unreachable_route
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 26
  [Documentation]  Test ONOS VROUTER Application with disable and re-enable vrouter app
  #${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_enabling_disabling_vrouter_app
  #Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 27
  [Documentation]  Test ONOS VROUTER Application with adding new routes to routing table
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_adding_new_routes_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 28
  [Documentation]  Test ONOS VROUTER Application with  removing old routes
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_removing_old_routes_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 29
  [Documentation]  Test ONOS VROUTER Application with modifying next in route table
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_modifying_nexthop_route_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 30
  [Documentation]  Test ONOS VROUTER Application with deleting alternate next hop in route table
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_deleting_alternative_nexthop_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 31
  [Documentation]  Test ONOS VROUTER Application with deleting few routes in route table
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_deleting_some_routes_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 32
  [Documentation]  Test ONOS VROUTER Application with  deleting and adding routes in route table
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_deleting_and_adding_routes_in_routing_table
  Should Be Equal As Integers  ${rc}  0

Verify ONOS VROUTER Application Functionality 33
  [Documentation]  Test ONOS VROUTER Application with toggling next hop interface
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_toggling_nexthop_interface
  Should Be Equal As Integers  ${rc}  0

