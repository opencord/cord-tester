# Copyright 2018-present Open Networking Foundation
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
Suite Setup       Suite Setup
Documentation     Test runner suite for executing NG4T Tests inside the venb vm instance
Library           OperatingSystem
Library           SSHLibrary
Library           CORDRobot
Library           ImportResource  resources=CORDRobot

*** Variables ***
${compute_node_user}    ubuntu
${instance_user}        ng4t
${instance_pass}        ng4t
${NG4T_TESTS_FILE}       ${CURDIR}/ng4t-tests.json

*** Test Cases ***
Execute Tests
    [Documentation]    SSHs into venb instance inside the compute node and executes tests
    : FOR    ${test}    IN    @{ng4t_tests}
    \     ${conn_id}=    SSHLibrary.Open Connection    ${compute_hostname}    prompt=~$    timeout=300s
    \    SSHLibrary.Login With Public Key    ubuntu    /home/cord/.ssh/cord_rsa
    \    SSHLibrary.Read
    \    SSHLibrary.Write    ssh -q ng40@${mgmt_ip} "./${test}"
    \    SSHLibrary.Read Until    password:
    \    SSHLibrary.Write    ng40
    \    ${result}=    SSHLibrary.Read Until Prompt
    \    Run Keyword And Continue On Failure    Should Contain    ${result}    VERDICT_PASS
    \    SSHLibrary.Close Connection

*** Keywords ***
Suite Setup
    ${nova_id}=    Run    . /opt/cord_profile/admin-openrc.sh; nova list --all-tenants | grep venb | awk '{print $2}'
    ${mgmt_ip}=    Run    . /opt/cord_profile/admin-openrc.sh; nova show ${nova_id} | grep management | awk '{print $5}'
    ${compute_hostname}=    Run    . /opt/cord_profile/admin-openrc.sh; nova show ${nova_id} | grep :host | awk '{print $4}'
    ${ng4t_tests}    CORDRobot.jsonToList    ${NG4T_TESTS_FILE}    mcord-ng4t-tests
    Set Suite Variable    ${compute_hostname}
    Set Suite Variable    ${ng4t_tests}
    Set Suite Variable    ${mgmt_ip}
