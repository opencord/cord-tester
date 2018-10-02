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
Library           ../../Framework/utils/utils.py
Resource          ../../Framework/utils/utils.robot
Library           ../../Framework/restApi.py
Resource          ../../Framework/Subscriber.robot
Resource          ../../Framework/ATTWorkFlowDriver.robot
Resource          ../../Framework/ONU.robot
Resource          ../../Framework/DHCP.robot
Variables         ../../Properties/RestApiProperties.py

*** Variables ***
${WHITELIST_PATHFILE}     ${CURDIR}/data/SIABWhitelist.json
${SUBSCRIBER_PATHFILE}    ${CURDIR}/data/SIABSubscriber.json
${VOLT_DEVICE_PATHFILE}    ${CURDIR}/data/SIABOLTDevice.json

*** Test Cases ***
Send Auth Request and Validate PING
    [Documentation]    Validate successful pings from valid auth request
    [Tags]    inittest
    Execute EAPOL Request and Verify
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw -r
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw
    Wait Until Keyword Succeeds    10s    2s    Validate ONU States    ACTIVE    ENABLED
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled
    Wait Until Keyword Succeeds    60s    2s    Ping From RG    PASS

Disable Subscriber
    [Documentation]    Validate pings fail when subscriber disabled
    [Tags]    disable
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Put    ${VOLT_SUBSCRIBER}    {"status":"disabled"}    ${subscriber_id}
    Wait Until Keyword Succeeds    60s    2s    Ping From RG    FAIL

Enable Subscriber
    [Documentation]    Validate pings pass when subscriber enabled
    [Tags]    enable
    ${subscriber_id}=    Retrieve Subscriber    ${c_tag}
    CORD Put    ${VOLT_SUBSCRIBER}    {"status":"enabled"}    ${subscriber_id}
    Wait Until Keyword Succeeds    60s    2s    Ping From RG    PASS

Change Whitelist to Wrong Port Location
    [Documentation]    Validate pings fail from when onu port location in whitelist is changed
    [Tags]    negative
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_sn}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 55 }    ${whitelist_id}
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    DISABLED    AWAITING
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    awaiting-auth
    Wait Until Keyword Succeeds    60s    2s    Ping From RG    FAIL
    [Teardown]    Restart RG Pod

Update Whitelist to Correct Port Location
    [Documentation]    Validate pings pass from when whitelist updated to correct port location
    [Tags]    update
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_sn}
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 1 }    ${whitelist_id}
    Execute EAPOL Request and Verify
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw -r
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw
    Wait Until Keyword Succeeds    60s    2s    Validate ATT Workflow Driver SI    ENABLED    APPROVED
    Wait Until Keyword Succeeds    60s    2s    Validate Subscriber Status    enabled
    Wait Until Keyword Succeeds    60s    2s    Ping From RG    PASS
    [Teardown]    Restart RG Pod

*** Keywords ***
Setup
    ${auth} =    Create List    ${XOS_USER}    ${XOS_PASSWD}
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    ${att_workflow_service_id}=    Get Service Owner Id    ${ATT_SERVICE}
    ${volt_service_id}=    Get Service Owner Id    ${VOLT_SERVICE}
    ${AttWhiteListList}=    utils.jsonToList    ${WHITELIST_PATHFILE}   AttWhiteListInfo
    Set Suite Variable    ${alist}    ${AttWhiteListList}
    ${AttWhiteListList} =    Get Variable Value    ${alist}
    ${AttWhiteListDict}=    utils.listToDict    ${AttWhiteListList}    0
    ${AttWhiteListDict}=    utils.setFieldValueInDict    ${AttWhiteListDict}    owner_id    ${att_workflow_service_id}
    ${onu_sn}=   Get From Dictionary    ${AttWhiteListDict}    serial_number
    Log    ${onu_sn}
    Set Global Variable    ${onu_sn}
    ${SubscriberList}=    utils.jsonToList    ${SUBSCRIBER_PATHFILE}   SubscriberInfo
    Set Global Variable    ${slist}    ${SubscriberList}
    ${SubscriberList} =    Get Variable Value    ${slist}
    ${SubscriberDict}=    utils.listToDict    ${SubscriberList}    0
    ${s_tag}=    utils.getFieldValueFromDict    ${SubscriberDict}   s_tag
    ${c_tag}=    utils.getFieldValueFromDict    ${SubscriberDict}   c_tag
    ${VoltDeviceList}=    utils.jsonToList    ${VOLT_DEVICE_PATHFILE}   VOLTDeviceInfo
    Set Global Variable    ${vlist}    ${VoltDeviceList}
    Set Suite Variable    ${s_tag}
    Set Suite Variable    ${c_tag}
    ${whitelist_id}=    Retrieve Whitelist Entry    ${onu_sn}
    Set Suite Variable    ${whitelist_id}
    ${att_si_id}=    Retrieve ATT Service Instance ID    ${onu_sn}
    Set Suite Variable    ${att_si_id}
    ${RG_CONTAINER}=    Run    kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}
    ## Validate ATT Workflow SI
    Wait Until Keyword Succeeds    90s    2s    Validate ATT Workflow Driver SI    ENABLED    AWAITING

Teardown
    [Documentation]    Restores ATT SI back to initial awaiting state
    Log    Suite Teardown cleanup/restoring back to initial state
    CORD Put    ${ATT_WHITELIST}    {"pon_port_id": 1 }    ${whitelist_id}
    CORD Put    ${ATT_SERVICEINSTANCES}    {"authentication_state": "AWAITING"}    ${att_si_id}
    Delete All Sessions

Restart RG Pod
    Run    kubectl -n voltha delete pod ${RG_CONTAINER}
    ${RG_CONTAINER}=    Wait Until Keyword Succeeds    60s    1s    Run    kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1
    Set Suite Variable    ${RG_CONTAINER}
    Run    kubectl wait -n voltha pod/${RG_CONTAINER} --for condition=Ready --timeout=180s

Validate ONU States
    [Arguments]    ${expected_op_status}    ${expected_admin_status}
    ${operational_status}    ${admin_status}    ONU Status Check    ${onu_sn}
    Should Be Equal    ${operational_status}    ${expected_op_status}
    Should Be Equal    ${admin_status}    ${expected_admin_status}

Validate ATT Workflow Driver SI
    [Arguments]    ${expected_status}    ${expected_auth_status}
    ${onu_state}   ${authentication_status}   Service Instance Status Check    ${onu_sn}
    Should Be Equal    ${onu_state}    ${expected_status}
    Should Be Equal    ${authentication_status}    ${expected_auth_status}

Validate Subscriber Status
    [Arguments]    ${exepected_status}
    ${status}    Subscriber Status Check    ${onu_sn}
    Should Be Equal    ${status}    ${exepected_status}

Execute EAPOL Request and Verify
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- rm -f wpa.log
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- wpa_supplicant -B -i eth0 -Dwired -c /etc/wpa_supplicant/wpa_supplicant.conf -f wpa.log
    Wait Until Keyword Succeeds    30s    1s    Authentication Completed

Authentication Completed
    ${output}=    Run    kubectl -n voltha exec ${RG_CONTAINER} -- cat wpa.log
    Should Contain    ${output}    authentication completed successfully

Ping From RG
    [Arguments]    ${status}
    ${result}=    Run    kubectl -n voltha exec ${RG_CONTAINER} -- ping -c 5 172.18.0.10
    Run Keyword If    '${status}' == 'PASS'    Should Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'PASS'    Should Contain    ${result}    0% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    100% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    80% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    60% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    40% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    20% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    Destination Host Unreachable
    Run Keyword If    '${status}' == 'FAIL'    Should Not Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'FAIL'    Should Contain    ${result}    100% packet loss
    Log To Console    \n ${result}