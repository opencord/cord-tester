# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

*** Settings ***
Documentation     Test various E2E conditions for seba-in-a-box
Suite Setup       Setup
Suite Teardown    Teardown
Test Teardown     Debug Tests
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           bbsim_utils.py
Library           ../../Framework/utils/utils.py
Library           ../../Framework/restApi.py
Resource          ../../Framework/Subscriber.robot
Resource          ../../Framework/ATTWorkFlowDriver.robot
Resource          ../../Framework/Kubernetes.robot
Resource          ../../Framework/ONU.robot
Resource          ../../Framework/DHCP.robot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${number_of_onus}    16
${timeout}           300s

*** Test Cases ***
Create Subscriber and Whitelist for ONUs
    [Documentation]    Creates whitelists in ATT-WF for each onu device
    [Tags]    create
    ${att_workflow_service_id}=    Get Service Owner Id    ${ATT_SERVICE}
    ${volt_service_id}=    Get Service Owner Id    ${VOLT_SERVICE}
    ${rcord_service_id}=    Get Service Owner Id    /xosapi/v1/rcord/rcordservices
    CORD Post    ${VOLT_DEVICE}    {'device_type': 'openolt', 'host': 'bbsim.voltha.svc', 'port': 50060, 'switch_datapath_id': 'of:0000000000000002', 'switch_port': '3', 'outer_tpid': '0x8100', 'uplink': '65536', 'nas_id': 'NAS_ID', 'serial_number': 'bbsim.voltha.svc:50060', 'volt_service_id': ${volt_service_id}}
    @{subscribers}=    Generate Subscribers    ${number_of_onus}    ${rcord_service_id}
    : FOR    ${subscriber}    IN    @{subscribers}
    \    CORD Post    ${VOLT_SUBSCRIBER}    ${subscriber}
    @{whitelists}=    Generate Whitelists    ${number_of_onus}    ${att_workflow_service_id}
    : FOR    ${whitelist}    IN    @{whitelists}
    \    CORD Post    ${ATT_WHITELIST}    ${whitelist}

Validate ONUs in VOLTHA
    [Documentation]    Verify number of onus that appear in voltha and its states
    [Tags]    voltha
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Voltha    ${number_of_onus}

Validate OLT and AAA-Users in ONOS
    [Documentation]    Verify olt devices in ONOS and all onus are authenticated via AAA app
    [Tags]    onos
    Wait Until Keyword Succeeds    ${timeout}    5s    OLT Device in ONOS
    Wait Until Keyword Succeeds    ${timeout}    5s    Verify Number of AAA-Users    ${number_of_onus}

Validate ONUs in XOS
    [Documentation]    Validates All ONU Devices are discovered in XOS
    [Tags]    onudiscovery
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Number of ONU Devices    ${number_of_onus}

Validate ONU States in XOS
    [Documentation]    Validates All ONU Device states are "enabled" and "active"
    [Tags]    onustates
    : FOR    ${onu}    IN    @{serial_numbers}
    \    Wait Until Keyword Succeeds    ${timeout}    5s    Validate ONU States    ACTIVE    ENABLED    ${onu}

Validate Hosts and DHCP Allocations in ONOS
    [Documentation]    Verify number of hosts in ONOS match number of onus and verify number of DHCP allocations
    [Tags]    onosdhcp
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate Hosts in ONOS    ${number_of_onus}
    Wait Until Keyword Succeeds    ${timeout}    5s    Validate DHCP Allocations    ${number_of_onus}

Validate ATT WF Driver SIs
    [Documentation]    Validates all service instances per onu devices become "approved" and "dhcpdiscovered"
    [Tags]    serviceinstances
    : FOR    ${onu}    IN    @{serial_numbers}
    \    Wait Until Keyword Succeeds    ${timeout}    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu}
    \    Wait Until Keyword Succeeds    ${timeout}    5s    Validate ATT Workflow Driver SI DHCP State    DHCPACK    ${onu}

*** Keywords ***
Setup
    ${server_ip}=    Get Environment Variable    SERVER_IP    localhost
    ${port}=    Get Environment Variable    SERVER_PORT    30001
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${voltha_auth}=    Create List    voltha    admin
    ${onos_auth}=    Create List    karaf    karaf
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    XOS    http://${server_ip}:${port}    auth=${AUTH}    headers=${HEADERS}
    Create Session    VOLTHA    http://${server_ip}:30125    auth=${VOLTHA_AUTH}    headers=${HEADERS}
    Create Session    ONOS    http://${server_ip}:30120    auth=${ONOS_AUTH}
    @{container_list}=    Create List
    Append To List    ${container_list}    att-workflow-att-workflow-driver
    Append To List    ${container_list}    seba-services-volt
    Append To List    ${container_list}    seba-services-rcord
    Append To List    ${container_list}    seba-services-fabric-crossconnect
    Append To List    ${container_list}    seba-services-onos-service
    Append To List    ${container_list}    xos-core
    Append To List    ${container_list}    vcore
    Set Suite Variable    ${container_list}

Teardown
    Delete All Sessions

Validate Number of ONU Devices
    [Arguments]    ${expected_onus}
    ${resp}=    CORD Get    ${ONU_DEVICE}
    Validate ONUs in Response    ${resp}    ${expected_onus}

Validate Voltha
    [Arguments]    ${expected_onus}
    ${resp}=    Get Request    VOLTHA    api/v1/devices
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    Validate ONUs in Response    ${resp}    ${expected_onus}
    Validate ONU States in Voltha    ${resp}

Validate ONUs in Response
    [Arguments]    ${resp}    ${expected_onus}
    ${jsondata}=    To Json    ${resp.content}
    Should Not Be Empty    ${jsondata['items']}
    ${length}=    Get Length    ${jsondata['items']}
    @{serial_numbers}=    Create List
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${sn}=    Get From Dictionary    ${value}    serial_number
    \    ${contains}=    Evaluate    "BBSM" in """${sn}"""
    \    Run Keyword if    '${contains}' == 'True'    Append To List    ${serial_numbers}    ${sn}
    Set Suite Variable    ${serial_numbers}
    ${length_of_bbsim_onus}=    Get Length    ${serial_numbers}
    Should Be Equal as Integers    ${length_of_bbsim_onus}    ${expected_onus}

Validate ONU States in Voltha
    [Arguments]    ${resp}
    ${jsondata}=    To Json    ${resp.content}
    Should Not Be Empty    ${jsondata['items']}
    ${length}=    Get Length    ${jsondata['items']}
    @{serial_numbers}=    Create List
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${admin_state}=    Get From Dictionary    ${value}    admin_state
    \    ${oper_status}=    Get From Dictionary    ${value}    oper_status
    \    Should Be Equal As Strings    ${admin_state}    ENABLED
    \    Should Be Equal As Strings    ${oper_status}    ACTIVE

CORD Get
    [Documentation]    Make a GET call to XOS
    [Arguments]    ${service}
    ${resp}=    Get Request    XOS    ${service}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Post
    [Documentation]    Make a POST call to XOS
    [Arguments]    ${service}    ${data}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    XOS    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to the CORD controller
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    XOS    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

Verify Number of AAA-Users
    [Arguments]    ${expected_onus}
    ${aaa_users}=    Execute ONOS Command    aaa-users | wc -l
    Should Contain    ${aaa_users}    ${expected_onus}

Validate Hosts in ONOS
    [Arguments]    ${expected_onus}
    ${hosts}=    Execute ONOS Command    hosts | grep -v 65537 | wc -l
    Should Contain    ${hosts}    ${expected_onus}

Validate DHCP Allocations
    [Arguments]    ${expected_onus}
    ${allocations}=    Execute ONOS Command    dhcpl2relay-allocations | wc -l
    Should Contain    ${allocations}    ${expected_onus}

OLT Device in ONOS
    ${resp}=    Get Request    ONOS    onos/v1/devices
    ${jsondata}=    To Json    ${resp.content}
    Should Not Be Empty    ${jsondata['devices']}
    ${length}=    Get Length    ${jsondata['devices']}
    @{serial_numbers}=    Create List
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['devices']}    ${INDEX}
    \    ${sn}=    Get From Dictionary    ${value}    serial
    \    ${dpid}=    Get From Dictionary    ${value}    id
    Should Be Equal As Strings    ${dpid}    of:0000626273696d76
    Should Be Equal As Strings    ${sn}    bbsim.voltha.svc:50060

Execute ONOS Command
    [Arguments]    ${cmd}
    ${conn_id}=    SSHLibrary.Open Connection    localhost    port=30115    prompt=onos>    timeout=300s
    SSHLibrary.Login    karaf    karaf
    ${output}=    SSHLibrary.Execute Command    ${cmd}
    SSHLibrary.Close Connection
    [Return]    ${output}

Debug Tests
    ${flows}=    Execute ONOS Command    flows
    ${onos_logs}=    Execute ONOS Command    log:display
    Log    ${flows}
    Log    ${onos_logs}
