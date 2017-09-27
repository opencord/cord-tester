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

# Copyright 2017-present Radisys Corporation
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
Documentation    Library for various utilities
Library           SSHLibrary
Library           HttpLibrary.HTTP
Library           String
Library           DateTime
Library           Process
Library           Collections
Library           RequestsLibrary
#Library           ${CURDIR}/readProperties.py
#Resource          ${CURDIR}/utils.py
*** Variables ***
${SSH_KEY}=   id_rsa

*** Keywords ***
Run Command On Remote System
    [Arguments]    ${system}    ${cmd}    ${user}=${VM_USER}    ${pass}=${VM_PASS}    ${prompt}=$    ${prompt_timeout}=60s    ${use_key}=False
    [Documentation]    SSH's into a remote host, executes command, and logs+returns output
    BuiltIn.Log    Attempting to execute command "${cmd}" on remote system "${system}"
    BuiltIn.Log    ${pass}
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=${prompt}    timeout=${prompt_timeout}
    Run Keyword If    '${use_key}' == 'False'    SSHLibrary.Login    ${user}    ${pass}    ELSE    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/${SSH_KEY}    any
    #SSHLibrary.Login    ${user}    ${pass}
    ${output}=    SSHLibrary.Execute Command    ${cmd}
    SSHLibrary.Close Connection
    Log    ${output}
    [Return]    ${output}

Execute Command on CIAB Server in Specific VM
    [Arguments]    ${system}    ${vm}    ${cmd}    ${user}=${VM_USER}    ${password}=${VM_PASS}    ${prompt}=$    ${use_key}=True    ${strip_line}=True
    [Documentation]    SSHs into ${HOST} where CIAB is running and executes a command in the Prod Vagrant VM where all the containers are running
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=${prompt}    timeout=300s
    Run Keyword If    '${use_key}' == 'False'    SSHLibrary.Login    ${user}    ${pass}    ELSE    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/${SSH_KEY}    any
    SSHLibrary.Write    ssh ${vm}
    SSHLibrary.Read Until Prompt
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until Prompt
    SSHLibrary.Close Connection
    ${output_1}=    Run Keyword If    '${strip_line}' == 'True'    Get Line    ${output}    0
    ${output}=    Set Variable If    '${strip_line}' == 'True'    ${output_1}    ${output}
    [Return]    ${output}

Execute Command on Compute Node in CIAB
    [Arguments]    ${system}    ${node}    ${hostname}    ${cmd}    ${user}=${VM_USER}    ${password}=${VM_PASS}    ${prompt}=$    ${use_key}=True
    [Documentation]    SSHs into ${HOST} where CIAB is running and executes a command in the Prod Vagrant VM where all the containers are running
    ${conn_id}=    SSHLibrary.Open Connection    ${system}    prompt=${prompt}    timeout=300s
    Run Keyword If    '${use_key}' == 'False'    SSHLibrary.Login    ${user}    ${pass}    ELSE    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/${SSH_KEY}    any
    SSHLibrary.Write    ssh ${node}
    SSHLibrary.Read Until Prompt
    SSHLibrary.Write    ssh root@${hostname}
    SSHLibrary.Read Until    \#
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until   \#
    SSHLibrary.Close Connection
    [Return]    ${output}

Execute Command Locally
    [Arguments]    ${cmd}
    ${output}=    Run    ${cmd}
    [Return]    ${output}

Execute ONOS Command
    [Arguments]    ${onos}    ${port}    ${cmd}    ${user}=karaf    ${pass}=karaf
    ${conn_id}=    SSHLibrary.Open Connection    ${onos}    port=${port}    prompt=onos>    timeout=300s
    SSHLibrary.Login    ${user}    ${pass}
    ${output}=    SSHLibrary.Execute Command    ${cmd}
    SSHLibrary.Close Connection
    [Return]    ${output}

Get Docker Container ID
    [Arguments]    ${container_name}
    [Documentation]    Retrieves the id of the requested docker container running inside headnode
    ${container_id}=     Run    docker ps | grep ${container_name} | awk '{print $1}'
    Log    ${container_id}
    [Return]    ${container_id}

Get Docker Logs
    [Arguments]    ${system}    ${container_id}    ${user}=${USER}    ${password}=${PASSWD}    ${prompt}=prod:~$
    [Documentation]    Retrieves the id of the requested docker container running inside given ${HOST}
    ##In Ciab, all containers are run in the prod vm so we must log into that
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

Remove Value From List
    [Arguments]    ${list}    ${val}
    ${length}=    Get Length    ${list}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    Log    ${list[${INDEX}]}
    \    ${value}=    Get Dictionary Values    ${list[${INDEX}]}
    \    Log    ${value[0]}
    \    Run Keyword If    '${value[0]}' == '${val}'    Remove From List    ${list}    ${INDEX}
    \    Run Keyword If    '${value[0]}' == '${val}'    Exit For Loop

Test Ping
    [Arguments]    ${interface}    ${host}
    [Documentation]    Ping hosts to check connectivity
    ${result}=   Run    ping -I ${interface} -c 5 ${host}
    Should Contain    ${result}    64 bytes
    Should Not Contain    ${result}    Destination Host Unreachable