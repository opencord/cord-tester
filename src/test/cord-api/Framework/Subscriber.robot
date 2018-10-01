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
Send EAPOL Message
    [Arguments]    ${auth_pass}    ${ip}    ${user}    ${pass}    ${iface}    ${conf_file}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into the RG (src) and executes a particular auth request via wpa_supplicant client. Requested packet should exist on src.
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo rm -f /tmp/wpa.log; sudo wpa_supplicant -B -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file} -f /tmp/wpa.log
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    Run Keyword If    '${auth_pass}' == 'True'    Wait Until Keyword Succeeds    30s    2s    Check Remote File Contents    True    ${conn_id}    /tmp/    wpa.log    authentication completed successfully
    Run Keyword If    '${auth_pass}' == 'False'    Sleep    10s
    Run Keyword If    '${auth_pass}' == 'False'    Check Remote File Contents    False    ${conn_id}    /tmp/    wpa.log    authentication completed successfully
    SSHLibrary.Close Connection

Delete IP Addresses from Interface on Remote Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip addr flush dev ${interface}; echo $?
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection

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

Add Double Vlan Interface on Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${interface}    ${stag}    ${ctag}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip link add link ${interface} name ${interface}.${stag} type vlan id ${stag}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    SSHLibrary.Write    sudo ip link set ${interface}.${stag} up
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Write    sudo ip link add link ${interface}.${stag} name ${interface}.${stag}.${ctag} type vlan id ${ctag}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Write    sudo ip link set ${interface}.${stag}.${ctag} up
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Write    ifconfig ${interface}.${stag}.${ctag}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection

Delete Interface on Remote Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip link del ${interface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    Read Until    ${prompt}
    SSHLibrary.Close Connection

Add Ip Address on Interface on Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${ip_address}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip addr add ${ip_address} dev ${interface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    Read Until    ${prompt}
    SSHLibrary.Close Connection

Start DHCP Server on Remote Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo dhcpd -cf /etc/dhcp/dhcpd.conf ${interface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    Should Contain    ${result}    Listening on LPF/${interface}
    SSHLibrary.Close Connection

Add Route to Remote Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${subnet}    ${gateway}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip route add ${subnet} via ${gateway} dev ${interface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
