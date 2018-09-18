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

*** Keywords ***
Send EAPOL Message
    [Arguments]    ${ip}    ${user}    ${pass}    ${iface}    ${conf_file}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into the RG (src) and executes a particular auth request via wpa_supplicant client. Requested packet should exist on src.
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo wpa_supplicant -B -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
    Should Contain    ${result}    Successfully initialized wpa_supplicant
    [Return]    ${result}

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

Delete IP Addresses from Interface on Remote Host
    [Arguments]    ${ip}    ${user}    ${pass}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    Deletes all ip addresses assigned to a particular interface on a remote host
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip addr flush dev ${interface}; echo $?
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
