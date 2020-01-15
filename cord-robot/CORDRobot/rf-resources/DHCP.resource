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
Documentation     Library for DHCP server and client functions
Library           OperatingSystem
Resource          utils.resource

*** Keywords ***
Send Dhclient Request
    [Documentation]    Executes a dhclient against a particular interface on the RG (src)
    [Arguments]    ${iface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System
    ...    dhclient -nw ${iface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    [Return]    ${result}

Send Dhclient Request K8S
    [Documentation]    Run dhclient inside rg container in K8s
    ${RG_CONTAINER}=    Wait Until Keyword Succeeds    60s    1s
    ...    Run    kubectl -n voltha get pod|grep "^rg[0-]"|cut -d' ' -f1
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- sed -i 's/timeout 300;/timeout 30;/' /etc/dhcp/dhclient.conf
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- ifconfig eth0 0.0.0.0
    Run    kubectl -n voltha exec ${RG_CONTAINER} -- dhclient

Add Default Route to Dst Gateway
    [Documentation]    Adds an entry to the routing table on the RG (src)
    # FIXME - Argument order of iface/ip/user/pass should match other functions
    [Arguments]    ${src_gateway}    ${dst_subnet}    ${iface}    ${ip}
    ...    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System
    ...    ip route add ${dst_subnet} via ${src_gateway} dev ${iface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    [Return]    ${result}

Check IPv4 Address on DHCP Client
    [Documentation]    Check if the sepcified interface has an IPv4 address assigned
    # FIXME - should ip_should_exist have a default value?
    [Arguments]    ${ip_should_exist}    ${iface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ${output}=    Login And Run Command On Remote System
    ...    ip address show ${iface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    # FIXME - ipv4_regex not set if container_type != K8S?
    ${ipv4_regex}=    Set Variable If    '${container_type}' != 'K8S'
    ...    \\b([0-9]{1,3}\\.){3}[0-9]{1,3}\\b    \\b(172)\\.(18)(\\.([0-9]{1,3})){2}\\b
    # FIXME - use a boolean rather than string comparison against truthy value
    Run Keyword If    '${ip_should_exist}' == 'True'    Should Match Regexp
    ...    ${output}    ${ipv4_regex}
    Run Keyword If    '${ip_should_exist}' == 'False'    Should Not Match Regexp
    ...    ${output}    ${ipv4_regex}

Start DHCP Server on Remote Host
    [Documentation]    Start the 'dhcpd' process on specified network interface
    ...    on a remote host
    [Arguments]    ${interface}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System
    ...    dhcpd -cf /etc/dhcp/dhcpd.conf ${interface}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
