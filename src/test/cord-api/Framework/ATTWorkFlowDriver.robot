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
Documentation     Library to retrieve status fields from ATT WorkFlow Driver Service Instance List
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           ../Framework/utils/utils.py
Library           ../Framework/restApi.py

*** Keywords ***
Service Instance Status Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns Status and authentication_state field values from att work flow driver for a particular ONU device
    ${json_result}=    restApi.ApiGet    ATT_SERVICEINSTANCES
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${onu_device}
    ${onu_state}=  Get From Dictionary    ${getJsonDict}   onu_state
    ${authentication_state}=  Get From Dictionary    ${getJsonDict}   authentication_state
    [Return]    ${onu_state}    ${authentication_state}

Service Instance DHCP State Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns dhcp state value from att work flow driver for a particular ONU device
    ${json_result}=    restApi.ApiGet    ATT_SERVICEINSTANCES
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${onu_device}
    ${state}=  Get From Dictionary    ${getJsonDict}   dhcp_state
    [Return]    ${state}

Create Whitelist Entry
    [Arguments]    ${entry_list}    ${list_index}
    [Documentation]    Sends a POST to create an att whitelist in XOS
    ${elist} =    Get Variable Value    ${entry_list}
    ${entry_dictionary}=    utils.listToDict    ${elist}    ${list_index}
    ${api_result}=    restApi.ApiPost    ATT_WHITELIST    ${entry_dictionary}
    Should Be True    ${api_result}
    ${AttWhiteList_Id}=    Get From Dictionary    ${api_result}    id
    Set Global Variable    ${AttWhiteList_Id}
    [Return]    ${AttWhiteList_Id}

Retrieve Whitelist Entry
    [Arguments]    ${serial_number}
    [Documentation]    Returns the whitelist entry per the onu's serial number
    ${json_result}=    restApi.ApiGet    ATT_WHITELIST
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${serial_number}
    ${id}=    Get From Dictionary    ${getJsonDict}   id
    [Return]    ${id}

Retrieve ATT Service Instance ID
    [Arguments]    ${serial_number}
    [Documentation]    Returns the whitelist entry per the onu's serial number
    ${json_result}=    restApi.ApiGet    ATT_SERVICEINSTANCES
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${serial_number}
    ${id}=    Get From Dictionary    ${getJsonDict}   id
    [Return]    ${id}

Delete Whitelist Entry
    [Arguments]    ${id}
    [Documentation]    Sends a DELETE to delete an att whitelist in XOS
    ${api_result}=    restApi.ApiChameleonDelete    ATT_WHITELIST    ${id}
    Should Be True    ${api_result}

Validate ATT Workflow Driver SI
    [Arguments]    ${expected_status}    ${expected_auth_status}    ${onu_device}
    ${onu_state}   ${authentication_status}   Service Instance Status Check    ${onu_device}
    Should Be Equal    ${onu_state}    ${expected_status}
    Should Be Equal    ${authentication_status}    ${expected_auth_status}

Validate ATT Workflow Driver SI DHCP State
    [Arguments]    ${expected_status}    ${onu_device}
    ${dhcp_state}=   Service Instance DHCP State Check    ${onu_device}
    Should Be Equal    ${dhcp_state}    ${expected_status}
