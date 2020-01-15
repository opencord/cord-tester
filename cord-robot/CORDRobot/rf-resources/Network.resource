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
Documentation     Library for interacting with network config, such as
...               interfaces, VLANs, routes on a host
Resource          utils.resource

*** Keywords ***
Add Ip Address on Interface on Host
    [Documentation]    Add IP addresss on interface on remote host
    [Arguments]    ${ip_address}    ${interface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    ip addr add ${ip_address} dev ${interface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Delete IP Addresses from Interface on Remote Host
    [Documentation]    Remove specified IP address on an interface on remote host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    ip addr flush dev ${interface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Add Double Vlan Interface on Host
    [Documentation]    Add double S/C-VLAN tagging on an interface on remote host
    [Arguments]    ${interface}    ${stag}    ${ctag}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    ip link add link ${interface} name ${interface}.${stag} type vlan id ${stag}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System
    ...    ip link set ${interface}.${stag} up
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System
    ...    ip link add link ${interface}.${stag} name ${interface}.${stag}.${ctag} type vlan id ${ctag}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System
    ...    ip link set ${interface}.${stag}.${ctag} up
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Login And Run Command On Remote System
    ...    ifconfig ${interface}.${stag}.${ctag}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Delete Interface on Remote Host
    [Documentation]    Deleted interface (link) on remote host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    ip link del ${interface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}

Add Route to Remote Host
    [Documentation]    Add route on remote host given subnet and gateway
    [Arguments]    ${subnet}    ${gateway}    ${interface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    Login And Run Command On Remote System
    ...    ip route add ${subnet} via ${gateway} dev ${interface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
