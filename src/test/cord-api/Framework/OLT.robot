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

Get VOLTHA Status
    ${resp}=    CORD Get    ${VOLT_DEVICE}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${olt_device_id}=    Get From Dictionary    ${value}    device_id
    \    ${logical_device_id}=    Get From Dictionary    ${value}    of_id
    Set Suite Variable    ${olt_device_id}
    Set Suite Variable    ${logical_device_id}
    testCaseUtils.send_command_to_voltha_cli    /tmp    voltha_devices.log    devices    host=${server_ip}
    testCaseUtils.send_command_to_voltha_cli    /tmp    logical_devices.log    logical_device ${logical_device_id}    voltha_logical_ports.log    ports    voltha_logical_flows.log    flow    host=${server_ip}
    testCaseUtils.send_command_to_voltha_cli    /tmp    devices.log    device ${olt_device_id}    voltha_olt_ports.log    ports    voltha_olt_flows.log    flows    host=${server_ip}
    ${voltha_devices_log}=    Get Binary File    /tmp/voltha_devices.log
    ${devices_flows}=    Get Binary File    /tmp/voltha_olt_flows.log
    ${device_ports}=    Get Binary File    /tmp/voltha_olt_ports.log
    ${logical_devices}=    Get Binary File    /tmp/voltha_logical_flows.log
    ${l_device_ports}=    Get Binary File    /tmp/voltha_logical_ports.log
    Log    ${voltha_devices_log}
    Log    ${devices_flows}
    Log    ${device_ports}
    Log    ${logical_devices}
    Log    ${l_device_ports}

Get ONOS Status
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_apps.log    apps -a -s    host=${server_ip}
    ${onos_apps}    Get Binary File    /tmp/onos_apps.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_devices.log    devices    host=${server_ip}
    ${onos_devices}    Get Binary File    /tmp/onos_devices.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_ports.log    ports   host=${server_ip}
    ${onos_ports}    Get Binary File    /tmp/onos_ports.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_flows.log    flows -s    host=${server_ip}
    ${onos_flows}    Get Binary File    /tmp/onos_flows.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_meters.log    meters    host=${server_ip}
    ${onos_meters}    Get Binary File    /tmp/onos_meters.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_volt_prog_subscribers.log    volt-programmed-subscribers    host=${server_ip}
    ${onos_volt_prog_subscribers}    Get Binary File    /tmp/onos_volt_prog_subscribers.log
    testCaseUtils.send_command_to_onos_cli    /tmp    onos_volt_prog_meters.log    volt-programmed-meters    host=${server_ip}
    ${onos_volt_prog_meters}    Get Binary File    /tmp/onos_volt_prog_meters.log
    Log    ${onos_apps}
    Log    ${onos_devices}
    Log    ${onos_ports}
    Log    ${onos_flows}
    Log    ${onos_meters}
    Log    ${onos_volt_prog_subscribers}
    Log    ${onos_volt_prog_meters}
