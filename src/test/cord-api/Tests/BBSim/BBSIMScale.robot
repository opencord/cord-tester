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
    [Tags]    voltha
    Wait Until Keyword Succeeds    120s    5s    Validate Voltha    ${number_of_onus}

Validate ONUs in XOS
    [Documentation]    Validates All ONU Devices are discovered and retrieve SNs
    [Tags]    onudiscovery
    Wait Until Keyword Succeeds    120s    5s    Validate Number of ONU Devices    ${number_of_onus}

Validate ONU States in XOS
    [Documentation]    Validates All ONU Device states are "enabled" and "active"
    [Tags]    onustates
    : FOR    ${onu}    IN    @{serial_numbers}
    \    Wait Until Keyword Succeeds    120s    5s    Validate ONU States    ACTIVE    ENABLED    ${onu}

*** Keywords ***
Setup
    ${server_ip}=    Get Environment Variable    SERVER_IP    localhost
    ${port}=    Get Environment Variable    SERVER_PORT    30001
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    XOS    http://${server_ip}:${port}    auth=${AUTH}    headers=${HEADERS}
    Create Session    VOLTHA    http://${server_ip}:30125    headers=${HEADERS}
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
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_SUBSCRIBER}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_WHITELIST}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${VOLT_DEVICE}
    Wait Until Keyword Succeeds    60s    2s    Clean Up Objects    ${ATT_SERVICEINSTANCES}
    Delete All Sessions
    #Get Pod Logs

Get Pod Logs
    : FOR    ${pod}    IN    @{container_list}
    \    ${full_pod_name}=    Run    kubectl get pods --all-namespaces | grep '${pod}' | head -1 | awk '{print $2}'
    \    ${namespace}=    Run    kubectl get pods --all-namespaces | grep ' ${pod}' | head -1 | awk '{print $1}'
    \    ${output}=    Run    kubectl logs --timestamps -n ${namespace} ${full_pod_name}
    \    Log    ${output}

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
