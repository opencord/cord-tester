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
Documentation     Library of functions related to RG (source host)
Library           OperatingSystem
Library           SSHLibrary
Library           restApi.py
Resource          ../../Framework/utils/utils.robot
Resource          ../../Framework/DHCP.robot

*** Keywords ***
Subscriber Status Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns Status from Subscribers List for a particular ONU device
    ${json_result}=    restApi.ApiGet    VOLT_SUBSCRIBER
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    onu_device    ${onu_device}
    ${status}=    Get From Dictionary    ${getJsonDict}   status
    [Return]    ${status}

Create Subscriber
    [Arguments]    ${subscriber_list}    ${list_index}
    [Documentation]    Sends a POST to create a subscriber in XOS
    ${slist} =    Get Variable Value    ${subscriber_list}
    ${subscriber_dictionary}=    utils.listToDict    ${slist}    ${list_index}
    ${api_result}=    restApi.ApiPost    VOLT_SUBSCRIBER    ${subscriber_dictionary}
    Should Be True    ${api_result}
    ${Subscriber_id}=    Get From Dictionary    ${api_result}    id
    Set Global Variable    ${Subscriber_id}
    [Return]    ${Subscriber_id}

Retrieve Subscriber
    [Arguments]    ${ctag}
    [Documentation]    Returns the subscriber id based on the subscriber's C-Tag
    ${json_result}=    restApi.ApiGet    VOLT_SUBSCRIBER
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    c_tag    ${ctag}
    ${id}=    Get From Dictionary    ${getJsonDict}   id
    [Return]    ${id}

Delete Subscriber
    [Arguments]    ${ctag}
    [Documentation]    Deletes a given subscriber based on its c_tag
    ${id}=    Retrieve Subscriber    ${ctag}
    ${api_result}=    restApi.ApiChameleonDelete    VOLT_SUBSCRIBER    ${id}
    Should Be True    ${api_result}

Validate Subscriber Status
    [Arguments]    ${exepected_status}    ${onu_device}
    ${status}    Subscriber Status Check    ${onu_device}
    Should Be Equal    ${status}    ${exepected_status}

Send EAPOL Message
    [Arguments]    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    [Documentation]    Executes a particular auth request on the RG via wpa_supplicant client. Requested packet should exist on src.
    Login And Run Command On Remote System    rm -f /tmp/wpa.log; wpa_supplicant -B -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file} -f /tmp/wpa.log    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Validate Authentication
    [Arguments]    ${auth_pass}    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    [Documentation]    Executes a particular auth request on the RG and verifies if it succeeds. auth_pass determines if authentication should pass
    Send EAPOL Message    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Run Keyword If    '${auth_pass}' == 'True'    Wait Until Keyword Succeeds    120s    2s    Check Remote File Contents    True    /tmp/wpa.log    authentication completed successfully    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Run Keyword If    '${auth_pass}' == 'False'    Sleep    10s
    Run Keyword If    '${auth_pass}' == 'False'    Check Remote File Contents    False    /tmp/wpa.log    authentication completed successfully    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Start DHCP Server on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System    dhcpd -cf /etc/dhcp/dhcpd.conf ${interface}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Should Contain    ${result}    Listening on LPF/${interface}

Delete IP Addresses from Interface on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    ip addr flush dev ${interface}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Add Double Vlan Interface on Host
    [Arguments]    ${interface}    ${stag}    ${ctag}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    ip link add link ${interface} name ${interface}.${stag} type vlan id ${stag}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System    ip link set ${interface}.${stag} up    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System    ip link add link ${interface}.${stag} name ${interface}.${stag}.${ctag} type vlan id ${ctag}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System    ip link set ${interface}.${stag}.${ctag} up    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System    ifconfig ${interface}.${stag}.${ctag}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Delete Interface on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    ip link del ${interface}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Add Ip Address on Interface on Host
    [Arguments]    ${ip_address}    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    ip addr add ${ip_address} dev ${interface}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Add Route to Remote Host
    [Arguments]    ${subnet}    ${gateway}    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    ip route add ${subnet} via ${gateway} dev ${interface}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Validate DHCP and Ping
    [Arguments]    ${dhcp_should_pass}    ${ping_should_pass}    ${src_iface}    ${s_tag}    ${c_tag}    ${dst_dp_ip}    ${src_ip}    ${src_user}    ${src_pass}=${None}    ${src_container_type}=${None}    ${src_container_name}=${None}    ${dst_dp_iface}=${None}    ${dst_ip}=${None}    ${dst_user}=${None}    ${dst_pass}=${None}    ${dst_container_type}=${None}    ${dst_container_name}=${None}
    Run Keyword If    '${dst_ip}' != '${None}'    Run Keywords
    ...    Add Double Vlan Interface on Host    ${dst_dp_iface}    ${s_tag}    ${c_tag}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}    AND
    ...    Add IP Address on Interface on Host    ${dst_dp_ip}/24    ${dst_dp_iface}.${s_tag}.${c_tag}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}    AND
    ...    Start DHCP Server on Remote Host    ${dst_dp_iface}.${s_tag}.${c_tag}    ${dst_ip}    ${dst_user}    ${dst_pass}    ${dst_container_type}    ${dst_container_name}
    Run Keyword If    '${src_container_type}' != 'K8S'    Send Dhclient Request    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    ...                                          ELSE    Send Dhclient Request K8S
    Run Keyword If    '${dhcp_should_pass}' == 'True'    Wait Until Keyword Succeeds    90s   5s    Check IPv4 Address on DHCP Client    True    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${dhcp_should_pass}' == 'False'    Sleep    15s
    Run Keyword If    '${dhcp_should_pass}' == 'False'   Check IPv4 Address on DHCP Client    False    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    Run Keyword If    '${ping_should_pass}' == 'True'    Wait Until Keyword Succeeds    60s    2s    Check Ping    True    ${dst_dp_ip}    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}
    ...                                          ELSE    Wait Until Keyword Succeeds    60s    2s    Check Ping    False    ${dst_dp_ip}    ${src_iface}    ${src_ip}    ${src_user}    ${src_pass}    ${src_container_type}    ${src_container_name}

Send Dhclient Request K8S
    ${RG_CONTAINER}=    Wait Until Keyword Succeeds    60s    1s    Run    kubectl -n voltha get pod|grep "^rg-"|cut -d' ' -f1
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw -r
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient -nw

Validate Subscriber Service Chain
    [Arguments]    ${serial_no}    ${expected}=True
    ${resp}=    CORD Get    ${VOLT_SUBSCRIBER}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${sl}=    Get From Dictionary    ${value}    subscribed_links_ids
    \    ${result}    ${slinks}=    Run Keyword And Ignore Error    Get From List    ${sl}    0
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Run Keyword If    '${expected}' == 'True'    Should Be Equal As Integers    ${slinks}    1    ELSE    Should Be Empty    ${sl}

Validate Fabric CrossConnect SI
    [Arguments]    ${stag}    ${expected}=True
    ${resp}=    CORD Get    ${FABRIC_CROSSCONNECT_SERVICEINSTANCES}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    @{tags}=    Create List
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${tag}=    Get From Dictionary    ${value}    s_tag
    \    Append To List    ${tags}    ${tag}
    Run Keyword If    '${expected}' == 'True'    List Should Contain Value    ${tags}    ${stag}    ELSE    List Should Not Contain Value    ${tags}    ${stag}
