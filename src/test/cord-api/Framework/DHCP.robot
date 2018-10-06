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
Documentation     Library to DHCP Requests from an RG (source host)
Library           OperatingSystem
Library           SSHLibrary
Resource          utils/utils.robot

*** Keywords ***
Send Dhclient Request
    [Arguments]    ${iface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    [Documentation]    Executes a dhclient against a particular interface on the RG (src)
    ${result}=    Login And Run Command On Remote System    sudo dhclient -nw ${iface}    ${ip}    ${user}    ${pass}    ${container_name}
    [Return]    ${result}

Add Default Route to Dst Gateway
    [Arguments]    ${src_gateway}    ${dst_subnet}    ${iface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    [Documentation]    Adds an entry to the routing table on the RG (src)
    ${result}=    Login And Run Command On Remote System    sudo ip route add ${dst_subnet} via ${src_gateway} dev ${iface}    ${ip}    ${user}    ${pass}    ${container_name}
    [Return]    ${result}

Check IPv4 Address on DHCP Client
    [Arguments]    ${ip_should_exist}    ${iface}    ${ip}    ${user}    ${pass}=${None}    ${container_name}=${None}
    [Documentation]    Check if the sepcified interface has an IPv4 address assigned
    ${output}=    Login And Run Command On Remote System    ifconfig ${iface}    ${ip}    ${user}    ${pass}    ${container_name}
    Run Keyword If    '${ip_should_exist}' == 'True'    Should Match Regexp    ${output}    \\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b
    Run Keyword If    '${ip_should_exist}' == 'False'    Should Not Match Regexp    ${output}    \\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b
