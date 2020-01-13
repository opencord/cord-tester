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
Documentation    Library for various utilities
Library           SSHLibrary
Library           String
Library           DateTime
Library           Process
Library           Collections
Library           RequestsLibrary

*** Keywords ***
Login And Run Command On Remote System
    [Arguments]    ${cmd}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}    ${prompt}=~$    ${prompt_timeout}=50s    ${container_prompt}=#
    [Documentation]    SSH's into a remote host (and logs into the container if container_type and container_name are specified), tries to switch to root user and executes a command and returns output
    ${conn_id}    Login To Remote System    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}    ${prompt}    ${prompt_timeout}    ${container_prompt}
    ${output}=    Run Command On Remote System    ${cmd}    ${conn_id}    ${user}    ${pass}
    Log    ${output}
    Logout From Remote System    ${conn_id}
    [Return]    ${output}

Login To Remote System
    [Arguments]    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}    ${prompt}=~$    ${prompt_timeout}=15s    ${container_prompt}=#
    [Documentation]    SSH's into a remote host (and logs into the container if container_type and container_name are specified) and returns connection ID
    ${conn_id}=    SSHLibrary.Open Connection    ${ip}    prompt=${prompt}    timeout=${prompt_timeout}
    Run Keyword If    '${pass}' != '${None}'    SSHLibrary.Login    ${user}    ${pass}
    ...                                 ELSE    SSHLibrary.Login With Public Key    ${user}    %{HOME}/.ssh/id_rsa
    # Login to the lxc container
    Run Keyword If    '${container_type}' == 'LXC'    Run Keywords
    ...    SSHLibrary.Write    lxc exec ${container_name} /bin/bash    AND
    ...    SSHLibrary.Read Until    ${container_prompt}    AND
    ...    SSHLibrary.Set Client Configuration    prompt=${container_prompt}
    # Login to the k8s container
    Run Keyword If    '${container_type}' == 'K8S'    Run Keywords
    ...    SSHLibrary.Write    kubectl -n $(kubectl get pods --all-namespaces | grep ${container_name} | awk '{print $1}') exec ${container_name} -it /bin/bash    AND
    ...    SSHLibrary.Read Until    ${container_prompt}    AND
    ...    SSHLibrary.Set Client Configuration    prompt=${container_prompt}
    # Try to switch to root user
    ${conn}=    SSHLibrary.Get Connection    ${conn_id}
    Run Keyword And Ignore Error    SSHLibrary.Write    sudo -s
    ${output}=    SSHLibrary.Read Until Regexp    \#|${conn.prompt}|password for ${user}:
    Run Keyword If    'password for ${user}:' not in '''${output}'''    Return From Keyword    ${conn_id}
    SSHLibrary.Set Client Configuration    prompt=\#
    SSHLibrary.Write    ${pass}
    SSHLibrary.Read Until Prompt
    [Return]    ${conn_id}

Logout From Remote System
    [Arguments]    ${conn_id}
    [Documentation]    Exit from the SSH session to a remote host
    SSHLibrary.Switch Connection    ${conn_id}
    SSHLibrary.Close Connection

Run Command On Remote System
    [Arguments]    ${cmd}    ${conn_id}    ${user}    ${pass}=${None}
    [Documentation]    Executes a command on remote host and returns output
    ${conn}=    SSHLibrary.Get Connection    ${conn_id}
    SSHLibrary.Switch Connection    ${conn_id}
    SSHLibrary.Write    ${cmd}
    ${output}=    SSHLibrary.Read Until Regexp    ${conn.prompt}|password for ${user}:
    Run Keyword If    'password for ${user}:' not in '''${output}'''    Return From Keyword    ${output}
    SSHLibrary.Write    ${pass}
    ${output}=    SSHlibrary.Read Until Prompt
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
    [Arguments]    ${status}    ${src}    ${user}    ${pass}    ${dest}    ${interface}    ${prompt}=$    ${prompt_timeout}=60s
    [Documentation]    SSH's into src and attempts to ping dest. Status determines if ping should pass | fail
    ${conn_id}=    SSHLibrary.Open Connection    ${src}    prompt=${prompt}    timeout=${prompt_timeout}
    SSHLibrary.Login    ${user}    ${pass}
    ${result}=    SSHLibrary.Execute Command    ping -I ${interface} -c 5 ${dest}
    SSHLibrary.Close Connection
    Log    ${result}
    Run Keyword If    '${status}' == 'PASS'    Should Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'PASS'    Should Contain    ${result}    0% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    100% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    80% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    60% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    40% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    20% packet loss
    Run Keyword If    '${status}' == 'PASS'    Should Not Contain    ${result}    Destination Host Unreachable
    Run Keyword If    '${status}' == 'FAIL'    Should Not Contain    ${result}    64 bytes
    Run Keyword If    '${status}' == 'FAIL'    Should Contain    ${result}    100% packet loss
    Log To Console    \n ${result}

Clean Up Objects
    [Arguments]    ${model_api}
    @{ids}=    Create List
    ${resp}=    CORD Get    ${model_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${id}=    Get From Dictionary    ${value}    id
    \    Append To List    ${ids}    ${id}
    : FOR    ${i}    IN    @{ids}
    \    CORD Delete    ${model_api}    ${i}

CORD Get
    [Documentation]    Make a GET call to XOS
    [Arguments]    ${service}
    ${resp}=    Get Request    ${server_ip}    ${service}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Post
    [Documentation]    Make a POST call to XOS
    [Arguments]    ${service}    ${data}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    ${SERVER_IP}    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Put
    [Documentation]    Make a PUT call to XOS
    [Arguments]    ${service}    ${data}    ${data_id}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Put Request    ${SERVER_IP}    uri=${service}/${data_id}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${id}
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to XOS
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    ${SERVER_IP}    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

Get Service Owner Id
    [Arguments]    ${service}
    ${resp}=    CORD Get    ${service}
    ${jsondata}=    To Json    ${resp.content}
    log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : for    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${id}=    Get From Dictionary    ${value}    id
    [Return]    ${id}

Kill Linux Process
    [Arguments]    ${process}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    ${rc}=    Login And Run Command On Remote System    kill $(ps aux | grep '${process}' | awk '{print $2}'); echo $?    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Should Be Equal As Integers    ${rc}    0

Check Remote File Contents
    [Arguments]    ${file_should_exist}    ${file}    ${pattern}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}    ${prompt}=~$
    ${output}=    Login And Run Command On Remote System    cat ${file} | grep '${pattern}'    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}    ${prompt}
    Run Keyword If    '${file_should_exist}' == 'True'    Should Contain    ${output}    ${pattern}
    ...                                           ELSE    Should Not Contain    ${output}    ${pattern}

Check Ping
    [Arguments]    ${ping_should_pass}    ${dst_ip}    ${iface}    ${ip}    ${user}    ${pass}=${None}    ${container_type}=${None}    ${container_name}=${None}
    ${result}=    Login And Run Command On Remote System    ping -I ${iface} -c 3 ${dst_ip}    ${ip}    ${user}    ${pass}    ${container_type}    ${container_name}
    Check Ping Result    ${ping_should_pass}    ${result}

Check Remote System Reachability
    [Arguments]    ${reachable}    ${ip}
    [Documentation]    Check if the specified IP address is reachable or not
    ${result}=    Run    ping -c 3 ${ip}
    Check Ping Result    ${reachable}    ${result}

Check Ping Result
    [Arguments]    ${reachable}    ${result}
    Run Keyword If    '${reachable}' == 'True'    Should Contain    ${result}    64 bytes
    Run Keyword If    '${reachable}' == 'True'    Should Contain Any   ${result}    0% packet loss    0.0% packet loss
    Run Keyword If    '${reachable}' == 'True'    Should Not Contain Any    ${result}    100% packet loss    100.0% packet loss
    Run Keyword If    '${reachable}' == 'False'    Should Not Contain    ${result}    64 bytes
    Run Keyword If    '${reachable}' == 'False'    Should Contain Any    ${result}    100% packet loss    100.0% packet loss

Set Deployment Config Variables
    [Documentation]    Parses through the given deployment config and sets all the "src" and "dst" variables
    ${source}=    Evaluate    ${hosts}.get("src")
    ${length_src}=    Get Length    ${source}
    ${src}=    Set Variable    src
    : FOR    ${INDEX}    IN RANGE    0    ${length_src}
    \    Set Suite Variable    ${${src}${INDEX}}    ${source[${INDEX}]}
    ${destination}=    Evaluate    ${hosts}.get("dst")
    ${length_dst}=    Get Length    ${destination}
    ${dst}=    Set Variable    dst
    : FOR    ${INDEX}    IN RANGE    0    ${length_dst}
    \    Set Suite Variable    ${${dst}${INDEX}}    ${destination[${INDEX}]}

