*** Settings ***
Library           KafkaLibrary
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Suite Setup       Setup
Suite Teardown    Teardown

*** Variables ***
${cord_kafka}         cord-kafka
${server_ip}          xos-chameleon
${server_port}        9101
${subscriber_api}     /xosapi/v1/rcord/rcordsubscribers
${att_si_api}         /xosapi/v1/att-workflow-driver/attworkflowdriverserviceinstances
${onu_device_api}     /xosapi/v1/volt/onudevices
${onu_serial_no}      onudevice123
${onu_invalid_sn}     invalid_serial_no
${mac_address}        00:AA:00:00:00:01
${ip_address}         192.168.3.5
${deviceId}           of:robot_test
${ponportno}          10
${uniportno}          100

*** Test Cases ***
Create Two ONU Devices
    [Documentation]    Create two onu devices to be tested for valid + invalid paths
    [Tags]    play
    ${resp}=    CORD Get    /xosapi/v1/volt/voltservices
    ${jsondata}=    To Json    ${resp.content}
    ${voltservice}=    Get From List    ${jsondata['items']}    0
    ${voltservice_id}=    Get From Dictionary    ${voltservice}    id
    ${resp}=    CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverservices
    ${jsondata}=    To Json    ${resp.content}
    ${attworkflowservice}=    Get From List    ${jsondata['items']}    0
    ${attworkflowservice_id}=    Get From Dictionary    ${attworkflowservice}    id
    Set Suite Variable    ${attworkflowservice_id}
    ${resp}=    CORD Post    /xosapi/v1/rcord/rcordsubscribers    {"onu_device": "${onu_serial_no}", "status": "pre-provisioned"}
    ${subscriber_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${subscriber_id}
    ${resp}=    CORD Post    /xosapi/v1/volt/oltdevices    {"volt_service_id": ${voltservice_id}, "name": "testoltdevice1", "device_type": "ponism", "host": "172.17.0.1", "port": 50060, "switch_port": "1", "dp_id": "${deviceId}", "outer_tpid": "0x8100"}
    ${oltdevice_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${oltdevice_id}
    ${resp}=    CORD Post    /xosapi/v1/volt/ponports    {"olt_device_id": ${oltdevice_id}, "port_no": "${ponportno}", "name": "testponport1"}
    ${ponport_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${ponport_id}
    ${resp}=    CORD Post    /xosapi/v1/volt/onudevices    {"serial_number": "${onu_serial_no}", "pon_port_id": ${ponport_id}, "vendor": "abcdefg"}
    ${onu_device1_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${onu_device1_id}
    ${resp}=    CORD Post    /xosapi/v1/volt/uniports    {"onu_device_id": "${onu_device1_id}", "port_no": ${uniportno}, "name": "testuniport"}
    ${uni_port_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${uni_port_id}
    ${resp}=    CORD Post    /xosapi/v1/volt/onudevices    {"serial_number": "${onu_invalid_sn}", "pon_port_id": ${ponport_id}, "vendor": "abcdefg"}
    ${onu_device2_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${onu_device2_id}
    ${resp}=    CORD Post    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    {"serial_number": "${onu_serial_no}", "device_id": "${deviceId}", "pon_port_id": ${ponportno}, "owner_id": ${attworkflowservice_id}}
    ${whitelist_entry_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${whitelist_entry_id}

Activate Non-Whitelisted ONU
    [Documentation]    Validate that activating an ONU not in whitelist sets onu device to DISABLED
    Send Kafka Event    onu.events    {'status': 'activated','serial_number': '${onu_invalid_sn}','uni_port_id': ${uniportno}, 'of_dpid': '${deviceId}'}
    Wait Until Keyword Succeeds    30s    5s    Validate ONU Device Status    ${onu_invalid_sn}    DISABLED

Activate Whitelisted ONU in Wrong Location
    [Documentation]    Validate that activating an ONU in the whitelist but in the wrong location DISABLES the onu device
    Send Kafka Event    onu.events    {'status': 'activated','serial_number': '${onu_serial_no}','uni_port_id': 52, 'of_dpid': '${deviceId}'}
    ${att_wf_driver_si_id}=    Wait Until Keyword Succeeds    30s    5s    Get ATT Service Instance ID    ${onu_serial_no}    DISABLED

Activate Whitelisted ONU
    [Documentation]    Validate that activating an ONU in the whitelist creates a attworkflow-driver-serviceinstance
    Send Kafka Event    onu.events    {'status': 'activated','serial_number': '${onu_serial_no}','uni_port_id': ${uniportno}, 'of_dpid': '${deviceId}'}
    ${att_wf_driver_si_id}=    Wait Until Keyword Succeeds    30s    5s    Get ATT Service Instance ID    ${onu_serial_no}    AWAITING

Send Denied Auth Request
    [Documentation]    Validate that denied auth request to the onu will disabled the subscriber and remove a service chain
    Send Kafka Event    authentication.events    {'authenticationState': 'DENIED', 'deviceId': '${deviceId}','portNumber': ${uniportno}}
    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Status    ${onu_serial_no}    disabled
    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Service Chain    ${onu_serial_no}    0
    ${att_wf_driver_si_id}=    Wait Until Keyword Succeeds    30s    5s    Get ATT Service Instance ID    ${onu_serial_no}    AWAITING

Send Auth Request
    [Documentation]    Validate that sending an auth request to the onu will enable the subscriber and create a service chain
    Send Kafka Event    authentication.events    {'authenticationState': 'APPROVED', 'deviceId': '${deviceId}','portNumber': ${uniportno}}
    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Status    ${onu_serial_no}    enabled
    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Service Chain    ${onu_serial_no}    1
    ${att_wf_driver_si_id}=    Wait Until Keyword Succeeds    30s    5s    Get ATT Service Instance ID    ${onu_serial_no}    APPROVED

Send DHCP Request
    [Documentation]    Validate that sending an dhcp request to update the subscriber's mac+ip address
    Send Kafka Event    dhcp.events    {'macAddress': '${mac_address}','ipAddress': '${ip_address}', 'deviceId': '${deviceId}', 'portNumber': ${uniportno}}
    Wait Until Keyword Succeeds    30s    5s    Validate Subscriber Settings    ${onu_serial_no}

Create New Whitelist Entry
    [Documentation]    Validate that creating a new whitelist entry for the "invalid" onu device will enable the onu
    [Tags]    notready
    ${resp}=    CORD Post    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    {"serial_number": "${onu_invalid_sn}", "device_id": "${deviceId}", "pon_port_id": ${ponportno}, "owner_id": ${attworkflowservice_id}}
    ${whitelist_entry2_id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${whitelist_entry2_id}
    Wait Until Keyword Succeeds    30s    5s    Validate ONU Device Status    ${onu_invalid_sn}    ENABLED

*** Keywords ***
Setup
    Connect Producer    ${cord_kafka}:9092    onu.events
    Connect Producer    ${cord_kafka}:9092    authentication.events
    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}

Teardown
    [Documentation]    Delete all models create
    CORD Get    /xosapi/v1/rcord/rcordsubscribers
    CORD Delete    /xosapi/v1/rcord/rcordsubscribers    ${subscriber_id}
    # sleeping to allow onu devices to be deleted
    Sleep    60
    CORD Get    /xosapi/v1/volt/onudevices
    CORD Delete    /xosapi/v1/volt/oltdevices    ${oltdevice_id}
    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry_id}
    CORD Delete    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry2_id}

Send Kafka Event
    [Documentation]    Send event
    [Arguments]    ${topic}    ${message}
    Log    Sending event
    ${event}=    evaluate    json.dumps(${message})    json
    Send    ${topic}    ${event}
    Flush

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
    ${resp}=    Post Request    ${server_ip}    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    ${id}=    Get Json Value    ${resp.content}    /id
    Set Suite Variable    ${id}
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to the CORD controller
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    ${SERVER_IP}    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

Get ATT Service Instance ID
    [Documentation]    Returns the id of the newly created onu's att workflow service instance
    [Arguments]    ${serial_no}    ${auth_state}
    ${resp}=    Get Request    ${server_ip}    ${att_si_api}
    Log    ${resp.content}
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
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${as}    ${auth_state}
    [Return]    ${id}

Validate Service Chain Links
    [Arguments]    ${serial_no}    ${expected_links}
    ${resp}=    CORD Get    ${subscriber_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${subscribed_links}=    Get From Dictionary    ${value}    subscribed_links_ids
    \    ${id}=    Get From Dictionary    ${value}    id
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${expected_links}    ${subscribed_links}

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
    [Arguments]    ${serial_no}    ${expected_no_sc}
    ${resp}=    CORD Get    ${subscriber_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    : FOR    ${INDEX}    IN RANGE    0    ${length}
    \    ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
    \    ${sl}=    Get From Dictionary    ${value}    subscribed_links_ids
    \    ${sl}=    Get From List    ${sl}    0
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal As Integers    ${sl}    ${expected_no_sc}

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
    \    ${ipAddress}=    Get From Dictionary    ${value}    ip_address
    \    ${sn}=    Get From Dictionary    ${value}    onu_device
    \    Run Keyword If    '${sn}' == '${serial_no}'    Exit For Loop
    Should Be Equal    ${macAddress}    ${mac_address}
    Should Be Equal    ${ipAddress}    ${ip_address}
