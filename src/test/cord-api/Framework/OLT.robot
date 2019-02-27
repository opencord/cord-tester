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
Documentation     Library of functions related to OLT
Library           SSHLibrary
Library           Collections
Library           String
Library           OperatingSystem
Library           RequestsLibrary
Library           utils/utils.py
Library           restApi.py

*** Keywords ***
Openolt is Up
    [Arguments]    ${ip}    ${user}    ${pass}    ${prompt}=~#
    [Documentation]    Verify that openolt process is started and ready to connect to voltha
    Check Remote File Contents    True    /var/log/openolt.log    oper_state: up    ${ip}    ${user}    ${pass}    prompt=${prompt}

OLT Status Check
    [Arguments]    ${olt_device}
    [Documentation]    Returns "operational_status" and "admin_status" of a particular OLT device from "olt device list"
    ${json_result}=    restApi.ApiGet    VOLT_DEVICE
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    host    ${olt_device}
    ${operational_status}=  Get From Dictionary    ${getJsonDict}   oper_status
    ${admin_status}=  Get From Dictionary    ${getJsonDict}   admin_state
    [Return]    ${operational_status}    ${admin_status}

Validate OLT States
    [Arguments]    ${expected_op_status}    ${expected_admin_status}    ${olt_device}
    ${operational_status}    ${admin_status}    OLT Status Check    ${olt_device}
    Should Be Equal    ${operational_status}    ${expected_op_status}
    Should Be Equal    ${admin_status}    ${expected_admin_status}
