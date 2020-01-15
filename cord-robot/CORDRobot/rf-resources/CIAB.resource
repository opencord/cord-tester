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
Documentation     Library for CORD-in-a-Box
Library           SSHLibrary
Resource          utils.resource

*** Keywords ***
Execute Command on CIAB Server in Specific VM
    [Documentation]    SSHs into ${HOST} where CIAB is running and executes a
    ...    command in the Prod Vagrant VM where all the containers are running
    [Arguments]    ${system}    ${vm}    ${cmd}
    ...    ${user}=${VM_USER}    ${password}=${VM_PASS}
    ...    ${prompt}=$    ${use_key}=True    ${strip_line}=True
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=${prompt}    timeout=300s
    Run Keyword If    '${use_key}' == 'False'
    ...    SSHLibrary.Login    ${user}    ${pass}
    ...    ELSE
    ...    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/${SSH_KEY}    any
    SSHLibrary.Write    ssh ${vm}
    SSHLibrary.Read Until Prompt
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until Prompt
    SSHLibrary.Close Connection
    ${output_1}=    Run Keyword If    '${strip_line}' == 'True'    Get Line    ${output}    0
    ${output}=    Set Variable If    '${strip_line}' == 'True'    ${output_1}    ${output}
    [Return]    ${output}

Execute Command on Compute Node in CIAB
    [Documentation]    SSHs into ${system} where CIAB is running and executes a
    ...    command in the Prod Vagrant VM where all the containers are running
    [Arguments]    ${system}    ${node}    ${hostname}    ${cmd}
    ...    ${user}=${VM_USER}    ${password}=${VM_PASS}    ${prompt}=$    ${use_key}=True
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=${prompt}    timeout=300s
    # FIXME: Truthy comparison of strings
    Run Keyword If    '${use_key}' == 'False'
    ...    SSHLibrary.Login    ${user}    ${pass}
    ...    ELSE
    ...    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/${SSH_KEY}    any
    SSHLibrary.Write    ssh ${node}
    SSHLibrary.Read Until Prompt
    SSHLibrary.Write    ssh root@${hostname}
    SSHLibrary.Read Until    \#
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until    \#
    SSHLibrary.Close Connection
    [Return]    ${output}

Get Docker Logs
    ##In Ciab, all containers are run in the prod vm so we must log into that
    [Documentation]    Retrieves the logs of a docker container running inside
    ...    given ${system}
    [Arguments]    ${system}    ${container_id}
    ...    ${user}=${USER}    ${password}=${PASSWD}    ${prompt}=prod:~$
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=$    timeout=300s
    SSHLibrary.Login With Public Key    ${USER}    %{HOME}/.ssh/${SSH_KEY}    any
    #SSHLibrary.Login    ${HOST_USER}    ${HOST_PASSWORD}
    SSHLibrary.Write    ssh head1
    SSHLibrary.Read Until    ${prompt}
    SSHLibrary.Write    docker logs -t ${container_id}
    ${container_logs}=    SSHLibrary.Read Until    ${prompt}
    SSHLibrary.Close Connection
    Log    ${container_logs}
    [Return]    ${container_logs}
