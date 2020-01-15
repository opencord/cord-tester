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
Documentation     Library of functions related a subscriber (RG)
Resource          ATTWorkFlowDriver.resource
Resource          DHCP.resource
Resource          Network.resource
Resource          ONOS.resource
Resource          utils.resource
Resource          XOS.resource

*** Keywords ***
Subscriber Status Check
    [Documentation]    Returns Status from Subscribers List for a particular ONU device
    [Arguments]    ${onu_device}
    ${json_result}=    CORDRobot.ApiGet    VOLT_SUBSCRIBER
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    CORDRobot.getDictFromListOfDict    ${json_result_list}
    ...    onu_device    ${onu_device}
    ${status}=    Get From Dictionary    ${getJsonDict}    status
    [Return]    ${status}

Validate Subscriber Status
    [Documentation]    Check that a subscriber has the expected status
    [Arguments]    ${expected_status}    ${onu_device}    ${accepted_status}=${EMPTY}
    ${status}    Subscriber Status Check    ${onu_device}
    Run Keyword If    '${accepted_status}' == '${EMPTY}'
    ...    Should Be Equal    ${status}    ${expected_status}
    ...    ELSE
    ...    Should Contain Any    ${status}    ${expected_status}    ${accepted_status}

Create Subscriber
    [Documentation]    Sends a POST to create a subscriber in XOS
    [Arguments]    ${subscriber_list}    ${list_index}
    ${slist} =    Get Variable Value    ${subscriber_list}
    ${subscriber_dictionary}=    CORDRobot.listToDict    ${slist}    ${list_index}
    ${api_result}=    CORDRobot.ApiPost    VOLT_SUBSCRIBER    ${subscriber_dictionary}
    Should Be True    ${api_result}
    ${Subscriber_id}=    Get From Dictionary    ${api_result}    id
    Set Global Variable    ${Subscriber_id}
    [Return]    ${Subscriber_id}

Retrieve Subscriber
    [Documentation]    Returns the subscriber id based on the subscriber's C-Tag
    [Arguments]    ${ctag}
    ${json_result}=    CORDRobot.ApiGet    VOLT_SUBSCRIBER
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    CORDRobot.getDictFromListOfDict    ${json_result_list}
    ...    c_tag    ${ctag}
    ${id}=    Get From Dictionary    ${getJsonDict}    id
    [Return]    ${id}

Delete Subscriber
    [Documentation]    Deletes a given subscriber based on its c_tag
    [Arguments]    ${ctag}
    ${id}=    Retrieve Subscriber    ${ctag}
    ${api_result}=    CORDRobot.ApiChameleonDelete    VOLT_SUBSCRIBER    ${id}
    Should Be True    ${api_result}

Send EAPOL Message
    [Documentation]    Executes a particular auth request on the RG via wpa_supplicant
    ...    Requested packet should exist on src.
    [Arguments]    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    rm -f /tmp/wpa.log; wpa_supplicant -B -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file} -f /tmp/wpa.log
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Validate Authentication
    [Documentation]    Executes a particular auth request on the RG and verifies if it succeeds
    ...    auth_pass determines if authentication should pass
    [Arguments]    ${auth_pass}    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Send EAPOL Message    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}
    ...    ${container_type}    ${container_name}
    # FIXME: Use an If/Else block, not Three separate checks, bools instead of truthy strings
    Run Keyword If    '${auth_pass}' == 'True'
    ...    Wait Until Keyword Succeeds    120s    2s
    ...    Check Remote File Contents    True
    ...    /tmp/wpa.log    authentication completed successfully
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Run Keyword If    '${auth_pass}' == 'False'
    ...    Sleep    20s
    Run Keyword If    '${auth_pass}' == 'False'
    ...    Check Remote File Contents    False
    ...    /tmp/wpa.log    authentication completed successfully
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Run Multicast Client
    [Documentation]    Executes mcjoin (a simple multicast client) on the RG.
    [Arguments]    ${iface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    rm -f /tmp/mcjoin.log; timeout 10 mcjoin -c 5 -i eth0 > /tmp/mcjoin.log || true
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Validate Multicast
    [Documentation]    Executes a particular auth request on the RG and verifies
    ...    if it succeeds. auth_pass determines if authentication should pass
    [Arguments]    ${auth_pass}    ${iface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Run Multicast Client    ${iface}    ${ip}    ${user}    ${pass}
    ...    ${container_type}    ${container_name}
    Run Keyword If    '${auth_pass}' == 'True'
    ...    Check Remote File Contents    True
    ...    /tmp/mcjoin.log    Received total: 5 packets
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Run Keyword If    '${auth_pass}' == 'False'
    ...    Check Remote File Contents    True
    ...    /tmp/mcjoin.log    Received total: 0 packets
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Validate DHCP and Ping
    [Documentation]    Check that DHCP address has been acquired and Ping works
    [Arguments]    ${dhcp_should_pass}    ${ping_should_pass}
    ...    ${src_iface}    ${s_tag}    ${c_tag}
    ...    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}=${None}
    ...    ${src_container_type}=${None}    ${src_container_name}=${None}
    ...    ${dst_dp_iface}=${None}    ${dst_ip}=${None}
    ...    ${dst_user}=${None}    ${dst_pass}=${None}
    ...    ${dst_container_type}=${None}    ${dst_container_name}=${None}
    Run Keyword If    '${dst_ip}' != '${None}'    Run Keywords
    ...    Add Double Vlan Interface on Host    ${dst_dp_iface}    ${s_tag}    ${c_tag}
    ...    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    ...    AND
    ...    Add IP Address on Interface on Host
    ...    ${dst_dp_ip}/24    ${dst_dp_iface}.${s_tag}.${c_tag}
    ...    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    ...    AND
    ...    Start DHCP Server on Remote Host    ${dst_dp_iface}.${s_tag}.${c_tag}    ${dst_ip}
    ...    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Run Keyword If    '${src_container_type}' != 'K8S'
    ...    Send Dhclient Request    ${src_iface}    ${src_ip}
    ...    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    ...    ELSE
    ...    Send Dhclient Request K8S
    Run Keyword If    '${dhcp_should_pass}' == 'True'
    ...    Wait Until Keyword Succeeds    90s    5s
    ...    Check IPv4 Address on DHCP Client    True    ${src_iface}    ${src_ip}
    ...    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${dhcp_should_pass}' == 'False'
    ...    Sleep    15s
    Run Keyword If    '${dhcp_should_pass}' == 'False'
    ...    Check IPv4 Address on DHCP Client    False    ${src_iface}    ${src_ip}
    ...    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${ping_should_pass}' == 'True'
    ...    Wait Until Keyword Succeeds    60s    2s
    ...    Check Ping    True    ${dst_dp_ip}    ${src_iface}    ${src_ip}
    ...    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    ...    ELSE
    ...    Wait Until Keyword Succeeds    60s    2s
    ...    Check Ping    False    ${dst_dp_ip}    ${src_iface}    ${src_ip}
    ...    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}

Validate Subscriber Service Chain
    [Documentation]    Check if serial number is list of subcribed_links_ids
    [Arguments]    ${serial_no}    ${expected}=True
    ${resp}=    CORD Get    ${VOLT_SUBSCRIBER}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    FOR    ${INDEX}    IN RANGE    0    ${length}
        ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
        ${sl}=    Get From Dictionary    ${value}    subscribed_links_ids
        ${result}    ${slinks}=    Run Keyword And Ignore Error
        ...    Get From List    ${sl}    0
        ${sn}=    Get From Dictionary    ${value}    onu_device
        Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    END

Validate Fabric CrossConnect SI
    [Documentation]    Build list of s_tags in fabric crossconnect
    [Arguments]    ${stag}    ${expected}=True
    ${resp}=    CORD Get    ${FABRIC_CROSSCONNECT_SERVICEINSTANCES}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    @{tags}=    Create List
    FOR    ${INDEX}    IN RANGE    0    ${length}
        ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
        ${tag}=    Get From Dictionary    ${value}    s_tag
        Append To List    ${tags}    ${tag}
    END

Validate Subscriber Count
    [Documentation]    Check if subscriber count matches passed value
    [Arguments]    ${expected_no}
    ${resp}=    CORD Get    ${VOLT_SUBSCRIBER}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    Should Be Equal As Integers    ${length}    ${expected_no}

Subscriber Ready to Authenticate
    [Documentation]    Check if subscriber is in awaiting-auth state
    [Arguments]    ${onu_device}
    Wait Until Keyword Succeeds    60s    15s
    ...    Validate ONU States    ACTIVE    ENABLED    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate ATT Workflow Driver SI    ENABLED    AWAITING    ${onu_device}
    ...    ONU has been validated - Awaiting Authentication
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Subscriber Status    awaiting-auth    ${onu_device}

Subscriber Provisioned
    [Documentation]    Check if subscriber has successfully authenticated
    [Arguments]    ${server_ip}    ${onu_device}    ${stag}
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    ...    ONU has been validated - Authentication succeeded
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Subscriber Status    enabled    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Subscriber Service Chain    ${onu_device}    True
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate XConnect in ONOS    ${server_ip}    ${stag}    True

Subscriber Service Chain Created
    [Documentation]    Check if subscriber service chain has been created
    [Arguments]    ${onu_device}    ${stag}
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate ATT Workflow Driver SI    ENABLED    APPROVED    ${onu_device}
    ...    ONU has been validated - Authentication succeeded
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Subscriber Status    enabled    ${onu_device}
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Subscriber Service Chain    ${onu_device}    True
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate Fabric CrossConnect SI    ${stag}    True
    Wait Until Keyword Succeeds    60s    2s
    ...    Validate XConnect in ONOS    ${server_ip}    ${stag}    True
