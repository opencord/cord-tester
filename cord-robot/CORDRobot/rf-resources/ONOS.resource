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
# onos common functions

*** Settings ***
Documentation     Library for ONOS Functions
Library           SSHLibrary

*** Keywords ***
Execute ONOS CLI Command
    [Documentation]    *DEPRECATED* Use "Execute ONOS CLI Command on open connection" instead. Establishes an ssh connection to ONOS contoller and executes a command
    [Arguments]    ${host}    ${port}    ${cmd}    ${user}=karaf    ${pass}=karaf
    ${conn_id}=    SSHLibrary.Open Connection    ${host}    port=${port}    timeout=300s
    SSHLibrary.Login    ${user}    ${pass}
    @{result_values}    SSHLibrary.Execute Command    ${cmd}    return_rc=True
    ...    return_stderr=True    return_stdout=True
    ${output}    Set Variable    @{result_values}[0]
    Log    ${output}
    Should Be Empty    @{result_values}[1]
    Should Be Equal As Integers    @{result_values}[2]    0
    SSHLibrary.Close Connection
    [Return]    ${output}

Validate XConnect in ONOS
    [Documentation]    Check if Fabric Crossconnnect matches exists value
    [Arguments]    ${server_ip}    ${stag}    ${exists}=True    ${port}=30120
    # FIXME: use Robot-based JSON manipulation, shorten line
    ${rc}=    Run And Return RC
    ...    http -a karaf:karaf GET http://${server_ip}:${port}/onos/segmentrouting/xconnect|jq -r '.xconnects[].vlanId'|grep ${stag}
    Run Keyword If    '${exists}' == 'True'
    ...    Should Be Equal As Integers    ${rc}    0
    ...    ELSE
    ...    Should Be Equal As Integers    ${rc}    1

Get ONOS Status
    [Documentation]    Obtain and log output of ONOS diagnostic commands
    [Arguments]    ${server_ip}=${None}    ${server_port}=30115
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_apps.log    apps -a -s
    ...    host=${server_ip}    port=${server_port}
    ${onos_apps}    Get Binary File    /tmp/onos_apps.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_devices.log    devices
    ...    host=${server_ip}    port=${server_port}
    ${onos_devices}    Get Binary File    /tmp/onos_devices.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_ports.log    ports
    ...    host=${server_ip}    port=${server_port}
    ${onos_ports}    Get Binary File    /tmp/onos_ports.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_flows.log    flows -s
    ...    host=${server_ip}    port=${server_port}
    ${onos_flows}    Get Binary File    /tmp/onos_flows.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_meters.log    meters
    ...    host=${server_ip}    port=${server_port}
    ${onos_meters}    Get Binary File    /tmp/onos_meters.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_volt_prog_subscribers.log    volt-programmed-subscribers
    ...    host=${server_ip}    port=${server_port}
    ${onos_volt_prog_subscribers}    Get Binary File    /tmp/onos_volt_prog_subscribers.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_volt_prog_meters.log    volt-programmed-meters
    ...    host=${server_ip}    port=${server_port}
    ${onos_volt_prog_meters}    Get Binary File    /tmp/onos_volt_prog_meters.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_volt_bp_meters.log    volt-bpmeter-mappings
    ...    host=${server_ip}    port=${server_port}
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_volt_port_status.log    volt-port-status
    ...    host=${server_ip}    port=${server_port}
    ${onos_volt_port_status}    Get Binary File    /tmp/onos_volt_port_status.log
    ${onos_volt_bp_meters}    Get Binary File    /tmp/onos_volt_bp_meters.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_dhcpl2.log    dhcpl2relay-allocations
    ...    host=${server_ip}    port=${server_port}
    ${onos_dhcpl2}    Get Binary File    /tmp/onos_dhcpl2.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_aaa_users.log    aaa-users
    ...    host=${server_ip}    port=${server_port}
    ${onos_aaa_users}    Get Binary File    /tmp/onos_aaa_users.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_netcfg.log    netcfg
    ...    host=${server_ip}    port=${server_port}
    ${onos_netcfg}    Get Binary File    /tmp/onos_netcfg.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_groups.log    groups
    ...    host=${server_ip}    port=${server_port}
    ${onos_groups}    Get Binary File    /tmp/onos_groups.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_hosts.log    hosts
    ...    host=${server_ip}    port=${server_port}
    ${onos_hosts}    Get Binary File    /tmp/onos_hosts.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_links.log    links
    ...    host=${server_ip}    port=${server_port}
    ${onos_links}    Get Binary File    /tmp/onos_links.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_roles.log    roles
    ...    host=${server_ip}    port=${server_port}
    ${onos_roles}    Get Binary File    /tmp/onos_roles.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_dhcpl2relay_stats.log    dhcpl2relay-stats
    ...    host=${server_ip}    port=${server_port}
    ${onos_dhcpl2relay_stats}    Get Binary File    /tmp/onos_dhcpl2relay_stats.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_aaa_stats.log    aaa-statistics
    ...    host=${server_ip}    port=${server_port}
    ${onos_aaa_stats}    Get Binary File    /tmp/onos_aaa_stats.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_cfg_settings.log    cfg get
    ...    host=${server_ip}    port=${server_port}
    ${onos_cfg_settings}    Get Binary File    /tmp/onos_cfg_settings.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_xc.log    sr-xconnect
    ...    host=${server_ip}    port=${server_port}
    ${onos_xc}    Get Binary File    /tmp/onos_xc.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_instances.log    nodes
    ...    host=${server_ip}    port=${server_port}
    ${onos_instances}    Get Binary File    /tmp/onos_instances.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_masters.log    masters
    ...    host=${server_ip}    port=${server_port}
    ${onos_masters}    Get Binary File    /tmp/onos_masters.log
    CORDRobot.write_log_of_onos_cli_command    /tmp
    ...    onos_mac_learner_mappings.log    mac-learner-get-mapping
    ...    host=${server_ip}    port=${server_port}
    ${onos_mac_learner_mappings}    Get Binary File    /tmp/onos_mac_learner_mappings.log
    Log    ${onos_apps}
    Log    ${onos_devices}
    Log    ${onos_xc}
    Log    ${onos_ports}
    Log    ${onos_flows}
    Log    ${onos_meters}
    Log    ${onos_aaa_users}
    Log    ${onos_volt_prog_subscribers}
    Log    ${onos_volt_port_status}
    Log    ${onos_volt_prog_meters}
    Log    ${onos_volt_bp_meters}
    Log    ${onos_hosts}
    Log    ${onos_dhcpl2}
    Log    ${onos_netcfg}
    Log    ${onos_groups}
    Log    ${onos_links}
    Log    ${onos_roles}
    Log    ${onos_dhcpl2relay_stats}
    Log    ${onos_aaa_stats}
    Log    ${onos_cfg_settings}
    Log    ${onos_instances}
    Log    ${onos_masters}
    Log    ${onos_mac_learner_mappings}
