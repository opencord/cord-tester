*** Settings ***
Documentation  Common definitions of variables and keywords for running cord tester
Library  OperatingSystem
Library  Collections
Library  String
Library  RequestsLibrary

*** Variables ***
${CORD_TESTER}    %{HOME}/cord-tester/src/test/setup/cord-test.py
${RESTPORT}  8181
${NODES}  1
${EXTRA_OPTS}

*** Keywords ***
Cord Setup
  [Documentation]  Setup the cord tester
  Cord Teardown
  ${rc}=  Run and Return RC  sudo ${CORD_TESTER} setup --olt --start-switch -n ${NODES} ${EXTRA_OPTS}
  Should Be Equal As Integers  ${rc}  0
  ${test_container}=  Run  sudo docker ps | grep cord-tester | tail -1 | tr -s ' ' | awk '{print $NF}'
  ${controllers}=  Run  sudo docker ps | grep cord-onos | tr -s ' ' | awk '{print $NF}' | tr -s '\n' ' '
  @{controller_names}=  Split String  ${controllers}
  @{controller_list}=  Create List
  : FOR  ${controller}  IN  @{controller_names}
  \  ${ip}=  Run  sudo docker inspect -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' ${controller}
  \  Append To List  ${controller_list}  ${ip}

  Set Suite Variable  ${test_container}
  Set Suite Variable  @{controller_list}
  Create HTTP Sessions
  Wait Until Keyword Succeeds  30s  2s  Verify If All Controllers Are Up

Cord Teardown
  [Documentation]  Teardown the cord tester setup
  ${output}=  Run  sudo ${CORD_TESTER} cleanup --olt

Create HTTP Sessions
  [Documentation]  Create controller http sessions
  ${AUTH}=  Create List  karaf  karaf
  : FOR  ${ip}  IN  @{controller_list}
  \  Create Session  ${ip}  http://${ip}:${RESTPORT}  auth=${AUTH}

Verify If All Controllers Are Up
  [Documentation]  Make a rest call to the controller to see if its responding
  : FOR  ${ip}  IN  @{controller_list}
  \  ${resp}=  ONOS Get  ${ip}  devices
  \  Should Be Equal As Strings  ${resp.status_code}  200

ONOS Get
  [Documentation]  Make a rest call to ONOS controller
  [Arguments]  ${session}  ${noun}
  ${resp}=  Get Request  ${session}  /onos/v1/${noun}
  Log  ${resp.content}
  [Return]  ${resp}

Run Cord Tester
  [Arguments]   ${test_case}
  ${status}  ${output}=  Run and Return RC and Output  sudo ${CORD_TESTER} run --onos-instances=${NODES} --container=${test_container} -t ${test_case}
  Log  ${output}
  [Return]    ${status}
