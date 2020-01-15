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
Documentation     Library for various utilities
Library           SSHLibrary
Library           String
Library           DateTime
Library           Process
Library           Collections
Library           RequestsLibrary

*** Keywords ***
Login To Remote System
    [Documentation]    SSH into a remote host (and into a container on that host if container_type
    ...    and container_name are specified) and returns connection ID
    [Arguments]    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ...    ${prompt}=~$    ${prompt_timeout}=15s    ${container_prompt}=#
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    Run Keyword If    '${pass}' != '${None}'
    ...    SSHLibrary.Login    ${user}    ${pass}
    ...    ELSE
    ...    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/id_rsa
    # Login to the lxc container
    Run Keyword If    '${container_type}' == 'LXC'    Run Keywords
    ...    SSHLibrary.Write    lxc exec ${container_name} /bin/bash
    ...    AND
    ...    SSHLibrary.Read Until    ${container_prompt}
    ...    AND
    ...    SSHLibrary.Set Client Configuration    prompt=${container_prompt}
    # Login to the k8s container
    # FIXME: This fails if /bin/bash isn't installed in the container, run on command
    Run Keyword If    '${container_type}' == 'K8S'    Run Keywords
    ...    SSHLibrary.Write    kubectl -n $(kubectl get pods --all-namespaces | grep ${container_name} | awk '{print $1}') exec ${container_name} -it /bin/bash
    ...    AND
    ...    SSHLibrary.Read Until    ${container_prompt}
    ...    AND
    ...    SSHLibrary.Set Client Configuration    prompt=${container_prompt}
    # Try to switch to root user
    # FIXME: Is is useful in the LXC/K8S cases?
    ${conn}=    SSHLibrary.Get Connection    ${conn_id}
    Run Keyword And Ignore Error
    ...    SSHLibrary.Write    sudo -s
    ${output}=    SSHLibrary.Read Until Regexp    \#|${conn.prompt}|password for ${user}:
    Run Keyword If    'password for ${user}:' not in '''${output}'''
    ...    Return From Keyword    ${conn_id}
    SSHLibrary.Set Client Configuration    prompt=\#
    SSHLibrary.Write    ${pass}
    SSHLibrary.Read Until Prompt
    [Return]    ${conn_id}

Logout From Remote System
    [Documentation]    Exit from the SSH session to a remote host
    [Arguments]    ${conn_id}
    SSHLibrary.Switch Connection    ${conn_id}
    SSHLibrary.Close Connection

Run Command On Remote System
    [Documentation]    Executes a command on remote host and returns output
    [Arguments]    ${cmd}    ${conn_id}    ${user}    ${pass}=${None}
    ${conn}=    SSHLibrary.Get Connection    ${conn_id}
    SSHLibrary.Switch Connection    ${conn_id}
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until Regexp    ${conn.prompt}|password for ${user}:
    Run Keyword If    'password for ${user}:' not in '''${output}'''
    ...    Return From Keyword    ${output}
    SSHLibrary.Write    ${pass}
    ${output}=    SSHlibrary.Read Until Prompt
    [Return]    ${output}

Login And Run Command On Remote System
    [Documentation]    SSH into a remote host (and into a container on that host if container_type
    ...    and container_name are specified), switch to root user, executes command, return output
    [Arguments]    ${cmd}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ...    ${prompt}=~$    ${prompt_timeout}=50s    ${container_prompt}=#
    ${conn_id}    Login To Remote System    ${ip}    ${user}    ${pass}
    ...    ${container_type}    ${container_name}
    ...    ${prompt}    ${prompt_timeout}    ${container_prompt}
    ${output}=    Run Command On Remote System    ${cmd}    ${conn_id}    ${user}    ${pass}
    Log    ${output}
    # FIXME: Look into persisting SSH connection rather than tearing it up/down repeatedly
    Logout From Remote System    ${conn_id}
    [Return]    ${output}

Execute Command Locally
    [Documentation]    Superfluous, use the 'Run' keyword instead which this wraps
    [Arguments]    ${cmd}
    ${output}=    Run    ${cmd}
    [Return]    ${output}

Get Docker Container ID
    [Documentation]    Retrieves the id of the requested docker container running locally
    [Arguments]    ${container_name}
    ${container_id}=    Run    docker ps | grep ${container_name} | awk '{print $1}'
    Log    ${container_id}
    [Return]    ${container_id}

Remove Value From List
    [Documentation]    Removes a value from a dictionary
    [Arguments]    ${list}    ${val}
    ${length}=    Get Length    ${list}
    FOR    ${INDEX}    IN RANGE    0    ${length}
        Log    ${list[${INDEX}]}
        ${value}=    Get Dictionary Values    ${list[${INDEX}]}
        Log    ${value[0]}
        Run Keyword If    '${value[0]}' == '${val}'    Remove From List    ${list}    ${INDEX}
        Run Keyword If    '${value[0]}' == '${val}'    Exit For Loop
    END

Test Ping
    [Documentation]    SSH's into src and attempts to ping dest.
    ...    Status determines if ping should pass | fail
    [Arguments]    ${status}    ${src}    ${user}    ${pass}
    ...    ${dest}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    ${conn_id}=    SSHLibrary.Open Connection
    ...    ${src}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    ${result}=    SSHLibrary.Execute Command
    ...    ping -I ${interface} -c 5 ${dest}
    SSHLibrary.Close Connection
    Log    ${result}
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Contain    ${result}    0% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    100% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    80% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    60% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    40% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    20% packet loss
    Run Keyword If    '${status}' == 'PASS'
    ...    Should Not Contain    ${result}    Destination Host Unreachable
    Run Keyword If    '${status}' == 'FAIL'
    ...    Should Not Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'FAIL'
    ...    Should Contain    ${result}    100% packet loss
    Log To Console    \n ${result}

Check Ping Result
    [Documentation]    Check the output of the 'ping' command
    [Arguments]    ${reachable}    ${result}
    Run Keyword If    '${reachable}' == 'True'
    ...    Should Contain    ${result}    64 bytes
    Run Keyword If    '${reachable}' == 'True'
    ...    Should Contain Any    ${result}    0% packet loss    0.0% packet loss
    Run Keyword If    '${reachable}' == 'True'
    ...    Should Not Contain Any    ${result}    100% packet loss    100.0% packet loss
    Run Keyword If    '${reachable}' == 'False'
    ...    Should Not Contain    ${result}    64 bytes
    Run Keyword If    '${reachable}' == 'False'
    ...    Should Contain Any    ${result}    100% packet loss    100.0% packet loss

Check Ping
    [Documentation]    Run 'ping' on remote system and check output
    [Arguments]    ${ping_should_pass}    ${dst_ip}    ${iface}    ${ip}
    ...    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System
    ...    ping -I ${iface} -c 3 ${dst_ip}
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Check Ping Result    ${ping_should_pass}    ${result}

Check Remote System Reachability
    [Documentation]    Check if the specified IP address is reachable or not
    [Arguments]    ${reachable}    ${ip}
    ${result}=    Run    ping -c 3 ${ip}
    Check Ping Result    ${reachable}    ${result}

Kill Linux Process
    [Documentation]    Kill a process on a remote system
    [Arguments]    ${process}    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}
    ${rc}=    Login And Run Command On Remote System
    ...    kill $(ps aux | grep '${process}' | awk '{print $2}'); echo $?
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Should Be Equal As Integers    ${rc}    0

Check Remote File Contents
    [Documentation]    Check if file on remote system matches a `grep` regex
    [Arguments]    ${file_should_exist}    ${file}    ${pattern}
    ...    ${ip}    ${user}    ${pass}=${None}
    ...    ${container_type}=${None}    ${container_name}=${None}    ${prompt}=~$
    ${output}=    Login And Run Command On Remote System
    ...    cat ${file} | grep '${pattern}'
    ...    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}    ${prompt}
    # FIXME: Comparison against truthy value
    Run Keyword If    '${file_should_exist}' == 'True'
    ...    Should Contain    ${output}    ${pattern}
    ...    ELSE
    ...    Should Not Contain    ${output}    ${pattern}

Set Deployment Config Variables
    [Documentation]    Parses through the given deployment config and sets all the "src" and "dst" variables
    ${source}=    Evaluate    ${hosts}.get("src")
    ${length_src}=    Get Length    ${source}
    ${src}=    Set Variable    src
    FOR    ${INDEX}    IN RANGE    0    ${length_src}
        Set Suite Variable    ${${src}${INDEX}}    ${source[${INDEX}]}
    END
    ${destination}=    Evaluate    ${hosts}.get("dst")
    ${length_dst}=    Get Length    ${destination}
    ${dst}=    Set Variable    dst
    FOR    ${INDEX}    IN RANGE    0    ${length_dst}
        Set Suite Variable    ${${dst}${INDEX}}    ${destination[${INDEX}]}
    END
