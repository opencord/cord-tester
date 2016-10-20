*** Settings ***
Documentation  Run Cord verification test cases
Suite Setup  Cord Setup
Suite Teardown  Cord Teardown
Library    OperatingSystem

*** Variables ***
${CORD_TESTER}    %{HOME}/cord-tester/src/test/setup/cord-test.py

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
Cord Setup
  [Documentation]  Setup the cord tester
  ${rc}=  Run and Return RC  sudo ${CORD_TESTER} setup --olt --start-switch
  Should Be Equal As Integers  ${rc}  0
  ${test_container}=  Run  sudo docker ps -l | tail -1 | tr -s ' ' | awk '{print $NF}'
  Set Suite Variable  ${test_container}

Cord Teardown
  [Documentation]  Teardown the cord tester setup
  ${output}=  Run  sudo ${CORD_TESTER} cleanup --olt

Run Cord Tester
  [Arguments]   ${test_case}
  ${status}  ${output}=  Run and Return RC and Output  sudo ${CORD_TESTER} run --container=${test_container} -t ${test_case}
  Log  ${output}
  [Return]    ${status}

