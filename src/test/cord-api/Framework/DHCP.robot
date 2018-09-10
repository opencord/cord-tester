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

*** Keywords ***
Send Dhclient Request
    [Arguments]    ${ip}    ${user}    ${pass}    ${iface}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into the RG (src) and executes a dhclient against a particular interface
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo dhclient ${iface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
    [Return]    ${result}

Add Default Route to Dst Gateway
    [Arguments]    ${ip}    ${user}    ${pass}    ${src_gateway}    ${dst_subnet}    ${iface}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into the RG (src) and adds an entry to the routing table
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    SSHLibrary.Write    sudo ip route add ${dst_subnet} via ${src_gateway} dev ${iface}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
    [Return]    ${result}
