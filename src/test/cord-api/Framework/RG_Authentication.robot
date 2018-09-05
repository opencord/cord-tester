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
Documentation     Library to Send EAPOL 802.1x messages from a RG (source host)
Library           OperatingSystem
Library           SSHLibrary

*** Keywords ***
Send EAPOL Message
    [Arguments]    ${ip}    ${user}    ${pass}    ${iface}    ${conf_file}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into the RG (src) and executes a particular auth request via wpa_supplicant client. Requested packet should exist on src.
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pamvss}
    SSHLibrary.Write    sudo sudo wpa_supplicant -i ${iface} -Dwired -c /etc/wpa_supplicant/${conf_file}
    Read Until    [sudo] password for ${user}:
    SSHLibrary.Write    ${pass}
    ${result}=    Read Until    ${prompt}
    SSHLibrary.Close Connection
    [Return]    ${result}
