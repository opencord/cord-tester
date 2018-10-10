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

Send EAPOL Message
    [Arguments]    ${iface}    ${conf_file}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    [Documentation]    Executes a particular auth request on the RG via wpa_supplicant client. Requested packet should exist on src.
    Login And Run Command On Remote System    sudo rm -f /tmp/wpa.log; sudo wpa_supplicant -B -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file} -f /tmp/wpa.log    ${ip}    ${user}    ${pass}    ${container_name}

Start DHCP Server on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System    sudo dhcpd -cf /etc/dhcp/dhcpd.conf ${interface}    ${ip}    ${user}    ${pass}    ${container_name}
    Should Contain    ${result}    Listening on LPF/${interface}

Delete IP Addresses from Interface on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    sudo ip addr flush dev ${interface}    ${ip}    ${user}    ${pass}    ${container_name}

Add Double Vlan Interface on Host
    [Arguments]    ${interface}    ${stag}    ${ctag}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    sudo ip link add link ${interface} name ${interface}.${stag} type vlan id ${stag}    ${ip}    ${user}    ${pass}    ${container_name}
    Login And Run Command On Remote System    sudo ip link set ${interface}.${stag} up    ${ip}    ${user}    ${pass}    ${container_name}
    Login And Run Command On Remote System    sudo ip link add link ${interface}.${stag} name ${interface}.${stag}.${ctag} type vlan id ${ctag}    ${ip}    ${user}    ${pass}    ${container_name}
    Login And Run Command On Remote System    sudo ip link set ${interface}.${stag}.${ctag} up    ${ip}    ${user}    ${pass}    ${container_name}
    Login And Run Command On Remote System    ifconfig ${interface}.${stag}.${ctag}    ${ip}    ${user}    ${pass}    ${container_name}

Delete Interface on Remote Host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    sudo ip link del ${interface}    ${ip}    ${user}    ${pass}    ${container_name}

Add Ip Address on Interface on Host
    [Arguments]    ${ip_address}    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    sudo ip addr add ${ip_address} dev ${interface}    ${ip}    ${user}    ${pass}    ${container_name}

Add Route to Remote Host
    [Arguments]    ${subnet}    ${gateway}    ${interface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System    sudo ip route add ${subnet} via ${gateway} dev ${interface}    ${ip}    ${user}    ${pass}    ${container_name}
