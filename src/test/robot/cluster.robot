*** Settings ***
Documentation  Run Cord verification test cases for Cluster
Resource  cord_resource.robot
Suite Setup  Cord Cluster Setup
Suite Teardown  Cord Teardown

*** Variables ***
${NODES}          3
${EXTRA_OPTS}     -v

*** Test Cases ***
Verify Onos DHCP Server Functionality
  [Documentation]  Make a DHCP request to ONOS to get an IP
  ${rc}=  Run Cord Tester  dhcp:dhcp_exchange.test_dhcp_1request
  Should Be Equal As Integers  ${rc}  0

Verify ONOS DHCP Relay Server Functionality
  [Documentation]  Make a DHCP request to a relay server through ONOS to get an IP
  ${rc}=  Run Cord Tester  dhcprelay:dhcprelay_exchange.test_dhcpRelay_1request
  Should Be Equal As Integers  ${rc}  0

Verify Onos AAA Functionality
  [Documentation]  Make a TLS client request to a RADIUS server through ONOS AAA application
  ${rc}=  Run Cord Tester  tls:eap_auth_exchange.test_eap_tls
  Should Be Equal As Integers  ${rc}  0

Verify Onos IGMP Functionality
  [Documentation]  Make a IGMP join leave request through ONOS IGMP snooping application
  ${rc}=  Run Cord Tester  igmp:igmp_exchange.test_igmp_join_verify_traffic
  Should Be Equal As Integers  ${rc}  0

Verify Cord SUBSCRIBER Functionality
  [Documentation]  Simulate Channel Surfing experience
  ${rc}=  Run Cord Tester  cordSubscriber:subscriber_exchange.test_cord_subscriber_join_jump
  Should Be Equal As Integers  ${rc}  0

Verify Cord VROUTER Functionality
  [Documentation]  Start Quagga container, connect it to ONOS before validating ONOS routing works
  ${rc}=  Run Cord Tester  vrouter:vrouter_exchange.test_vrouter_with_5_routes
  Should Be Equal As Integers  ${rc}  0

*** Keywords ***
Cord Cluster Setup
  [Documentation]  Configure a ${NODES} node ONOS cluster for cord tester
  ${output}  Run  sudo docker ps |grep cord-onos | tr -s ' ' | awk '{print $NF}' | xargs docker kill
  Cord Setup