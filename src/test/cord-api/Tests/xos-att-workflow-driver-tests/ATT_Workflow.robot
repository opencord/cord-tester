*** Settings ***
Library           KafkaLibrary
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Resource          ../../Framework/utils/utils.robot
Suite Setup       Setup
Suite Teardown    Teardown
Test Template     Send Event and Verify

*** Variables ***
${server_ip}              xos-chameleon
${server_port}            30006
${subscriber_api}         /xosapi/v1/rcord/rcordsubscribers
${att_wf_api}             /xosapi/v1/att-workflow-driver/attworkflowdriverservices
${volt_api}               /xosapi/v1/volt/voltservices
${att_si_api}             /xosapi/v1/att-workflow-driver/attworkflowdriverserviceinstances
${att_whitelist_api}      /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
${onu_device_api}         /xosapi/v1/volt/onudevices
${olt_api}                /xosapi/v1/volt/oltdevices
${pon_ports_api}          /xosapi/v1/volt/ponports
${uni_ports_api}          /xosapi/v1/volt/uniports
${onu_serial_no}          onudevice123
${onu_invalid_sn}         invalid_serial_no
${deviceId}               of:robot_test
${ponportno}              10
${uniportno}              100
${mac_address}            00:AA:00:00:00:01
${ip_address}             192.168.3.5

*** Test Cases ***
Activate Non-Whitelisted ONU    onu.events    {'status': 'activated', 'serial_number': '${onu_invalid_sn}','uni_port_id': 100, 'of_dpid': '${deviceId}'}    onu_serial_number=${onu_invalid_sn}    onu_state=DISABLED
    [Documentation]    Validate that activating an ONU not in whitelist sets onu device to DISABLED

Activate Whitelisted ONU in Wrong Location    onu.events    {'status': 'activated', 'serial_number': '${onu_serial_no}','uni_port_id': 52, 'of_dpid': 'wrongofdpid'}    onu_serial_number=${onu_serial_no}    onu_state=DISABLED
    [Documentation]    Validate that activating an ONU in the whitelist but in the wrong location DISABLES the onu device

Activate Whitelisted ONU    onu.events    {'status': 'activated', 'serial_number': '${onu_serial_no}','uni_port_id': ${uniportno}, 'of_dpid': '${deviceId}'}    onu_serial_number=${onu_serial_no}    onu_state=ENABLED
    [Documentation]    Validate that activating an ONU in the whitelist creates a attworkflow-driver-serviceinstance

Send Auth Request    authentication.events    {'authenticationState': 'APPROVED', 'deviceId': '${deviceId}','portNumber': ${uniportno}}    onu_serial_number=${onu_serial_no}    subscriber_state=enabled    service_instance_state=APPROVED    service_instance_count=1    service_instance_dhcp_state=AWAITING
    [Documentation]    Validate that sending an auth request to the onu will enable the subscriber and create a service chain

Send DHCP Request    dhcp.events    {'macAddress': '${mac_address}','ipAddress': '${ip_address}', 'deviceId': '${deviceId}', 'portNumber': ${uniportno}, 'messageType': 'DHCPACK'}    onu_serial_number=${onu_serial_no}    service_instance_state=APPROVED    service_instance_dhcp_state=DHCPACK
    [Documentation]    Validate that sending an dhcp request to update the subscriber's mac+ip address

Send Denied Auth Request    authentication.events    {'authenticationState': 'DENIED', 'deviceId': '${deviceId}','portNumber': ${uniportno}}    onu_serial_number=${onu_serial_no}    subscriber_state=auth-failed    service_instance_state=DENIED    service_instance_dhcp_state=DHCPACK
    [Documentation]    Validate that denied auth request to the onu will disable the subscriber and remove a service chain

Create New Whitelist Entry
    [Documentation]    Validate that creating a new whitelist entry for the "invalid" onu device will enable the onu
    [Template]    None
    ${resp}=    CORD Post    ${att_whitelist_api}    {"serial_number": "${onu_invalid_sn}", "device_id": "${deviceId}", "pon_port_id": ${ponportno}, "owner_id": ${attworkflowservice_id}}
    ${whitelist_entry2_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${whitelist_entry2_id}
    Wait Until Keyword Succeeds    30s    5s    Validate ONU Device Status    ${onu_invalid_sn}    ENABLED

Remove Whitelist Entry
    [Documentation]    Validate that removing a whitelist entry for an onu device will disable the subscriber and remove it's service chain
    [Template]    None
    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry_id}
    Wait Until Keyword Succeeds    120s    5s    Validate Subscriber Status    ${onu_serial_no}    auth-failed
    Wait Until Keyword Succeeds    120s    5s    Validate Subscriber Service Chain    ${onu_serial_no}

*** Keywords ***
Setup
    ${cord_kafka}=    Get Environment Variable    CORD_KAFKA_IP    cord-kafka
    Connect Producer    ${cord_kafka}:9092    onu.events
    Connect Producer    ${cord_kafka}:9092    authentication.events
    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    Create OLT, ONU, Subscribers, and Whitelists

Teardown
    [Documentation]    Delete all models created
    CORD Get    /xosapi/v1/rcord/rcordsubscribers
    Clean Up Objects    ${subscriber_api}
    Clean Up Objects    ${att_si_api}
    Clean Up Objects    ${subscriber_api}
    Wait Until Keyword Succeeds    60s    1s    Clean Up Objects    ${olt_api}
    Clean Up Objects    ${att_whitelist_api}

Create OLT, ONU, Subscribers, and Whitelists
    [Documentation]    Create two onu devices to be tested for valid/invalid paths
    ${resp}=    CORD Get    ${volt_api}
    ${jsondata}=    To Json    ${resp.content}
    ${voltservice}=    Get From List    ${jsondata['items']}    0
    ${voltservice_id}=    Get From Dictionary    ${voltservice}    id
    ${resp}=    CORD Get    ${att_wf_api}
    ${jsondata}=    To Json    ${resp.content}
    ${attworkflowservice}=    Get From List    ${jsondata['items']}    0
    ${attworkflowservice_id}=    Get From Dictionary    ${attworkflowservice}    id
    Set Suite Variable    ${attworkflowservice_id}
    ${resp}=    CORD Post    ${subscriber_api}    {"onu_device": "${onu_serial_no}", "status": "pre-provisioned"}
    ${subscriber_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${subscriber_id}
    ${resp}=    CORD Post    ${olt_api}    {"volt_service_id": ${voltservice_id}, "name": "testoltdevice1", "device_type": "ponism", "host": "172.17.0.1", "port": 50060, "switch_port": "1", "dp_id": "${deviceId}", "outer_tpid": "0x8100", "uplink": "128"}
    ${oltdevice_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${oltdevice_id}
    ${resp}=    CORD Post    ${pon_ports_api}    {"olt_device_id": ${oltdevice_id}, "port_no": "${ponportno}", "name": "testponport1"}
    ${ponport_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${ponport_id}
    ${resp}=    CORD Post    ${onu_device_api}    {"serial_number": "${onu_serial_no}", "pon_port_id": ${ponport_id}, "vendor": "abcdefg"}
    ${onu_device1_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${onu_device1_id}
    ${resp}=    CORD Post    ${uni_ports_api}    {"onu_device_id": "${onu_device1_id}", "port_no": ${uniportno}, "name": "testuniport"}
    ${uni_port_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${uni_port_id}
    ${resp}=    CORD Post    ${onu_device_api}    {"serial_number": "${onu_invalid_sn}", "pon_port_id": ${ponport_id}, "vendor": "abcdefg"}
    ${onu_device2_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${onu_device2_id}
    ${resp}=    CORD Post    ${att_whitelist_api}    {"serial_number": "${onu_serial_no}", "device_id": "${deviceId}", "pon_port_id": ${ponportno}, "owner_id": ${attworkflowservice_id}}
    ${whitelist_entry_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${whitelist_entry_id}

Send Event and Verify
    [Arguments]    ${topic}    ${event}    ${onu_serial_number}=${EMPTY}    ${onu_state}=${EMPTY}    ${subscriber_state}=${EMPTY}    ${service_instance_state}=${EMPTY}    ${service_instance_count}=${EMPTY}    ${service_instance_dhcp_state}=${EMPTY}
    Send Kafka Event    ${topic}    ${event}
    Run Keyword If    '${topic}' == 'onu.events'    Wait Until Keyword Succeeds    30s    5s    Validate ONU Device Status    ${onu_serial_number}    ${onu_state}
    Run Keyword If    '${topic}' == 'authentication.events'    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Status    ${onu_serial_number}    ${subscriber_state}
    Run Keyword If    '${topic}' == 'authentication.events'    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Service Chain    ${onu_serial_number}    ${service_instance_count}
    Run Keyword If    '${topic}' == 'authentication.events'    Wait Until Keyword Succeeds    30s    5s    Validate ATT Service Instance    ${onu_serial_number}    ${service_instance_state}    ${service_instance_dhcp_state}
    Run Keyword If    '${topic}' == 'dhcp.events'    Wait Until Keyword Succeeds    30s    5s    Validate ATT Service Instance    ${onu_serial_number}    ${service_instance_state}    ${service_instance_dhcp_state}
    Run Keyword If    '${topic}' == 'dhcp.events'    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Settings    ${onu_serial_number}

Send Kafka Event
    [Documentation]    Send event
    [Arguments]    ${topic}    ${message}
    Log    Sending event
    ${event}=    evaluate    json.dumps(${message})    json
    Send    ${topic}    ${event}
    Flush

Validate ATT Service Instance
    [Documentation]    Validates the states in the ATT-WF-SI per onu
    [Arguments]    ${serial_no}    ${auth_state}    ${dhcp_state}
    ${resp}=    CORD Get    ${att_si_api}
    Should Be Equal As Strings    ${resp.status_code}    200
    ## validate sn exists
    Should Contain    ${resp.content}    ${serial_no}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${id}=    Get From Dictionary    ${value}    id
    \    ${sn}=    Get From Dictionary    ${value}    serial_number
    \    ${as}=    Get From Dictionary    ${value}    authentication_state
    \    ${dp}=    Get From Dictionary    ${value}    dhcp_state
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${dp}    ${dhcp_state}
    Should Be Equal    ${as}    ${auth_state}

Validate Subscriber Status
    [Arguments]    ${serial_no}    ${expected_status}
    ${resp}=    CORD Get    ${subscriber_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${status}=    Get From Dictionary    ${value}    status
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${status}    ${expected_status}

Validate Subscriber Service Chain
    [Arguments]    ${serial_no}    ${expected_no_sc}=${EMPTY}
    ${resp}=    CORD Get    ${subscriber_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${sl}=    Get From Dictionary    ${value}    subscribed_links_ids
    \    ${result}    ${slinks}=    Run Keyword And Ignore Error    Get From List    ${sl}    0
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Run Keyword If    '${expected_no_sc}' != '${EMPTY}'    Should Not Be Equal As Strings    ${result}    FAIL
    Run Keyword If    '${expected_no_sc}' != '${EMPTY}'    Should Not Be Empty    ${result}    ELSE    Should Be Empty    ${sl}

Validate ONU Device Status
    [Arguments]    ${serial_no}    ${expected_status}
    ${resp}=    CORD Get    ${onu_device_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${status}=    Get From Dictionary    ${value}    admin_state
    \    ${sn}=    Get From Dictionary    ${value}    serial_number
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${status}    ${expected_status}

Validate Subscriber Settings
    [Arguments]    ${serial_no}
    ${resp}=    CORD Get    ${subscriber_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${macAddress}=    Get From Dictionary    ${value}    mac_address
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${macAddress}    ${mac_address}