*** Settings ***
Documentation    Scale up models in a SEBA deployment with no backends
Library           KafkaLibrary
Library           RequestsLibrary
Library           HttpLibrary.HTTP
Library           Collections
Library           String
Library           OperatingSystem
Library           ./utils/devices.py
Suite Setup       Setup
Suite Teardown    Teardown

*** Variables ***
${xos_chameleon_url}    localhost
${xos_chameleon_port}   30006
${cord_kafka}           10.152.183.238


${num_olts}             1
${num_pon_ports}        1
${num_onus}             1

${scale_size}           5

${WHITELIST_PATHFILE}      ${CURDIR}/data/whitelist.json

*** Test Cases ***
Check Whitelist
    [Documentation]     Verify that we created the correct number of whitelist entries
    ${res} =   CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
    ${jsondata} =    To Json    ${res.content}
    ${length} =    Get Length    ${jsondata['items']}
    ${total} =      Convert To Integer   ${scale_size}
#    Should Be Equal    ${length}    ${total}

#Activate ONUs
#    [Documentation]     For each fake ONU send an activation event
#    :FOR    ${ELEMENT}    IN    @{onu_list}
#    \   Log   ${ELEMENT}


*** Keywords ***
Setup
    Connect Producer    ${cord_kafka}:9092    onu.events
    Connect Producer    ${cord_kafka}:9092    authentication.events
    Connect Producer    ${cord_kafka}:9092    dhcp.events
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    XOS    http://${xos_chameleon_url}:${xos_chameleon_port}    auth=${AUTH}    headers=${HEADERS}
    Store Data
    Create Olts     ${num_olts}
#    Setup Whitelist

Teardown
    [Documentation]    Delete all models created
    Log     Teardown
    Clean Whitelist
    Delete OLTs
    Delete All Sessions

Create Olts
    [Documentation]     Stub OLT for the test
    [Arguments]    ${num_olts}
    ${olts} =   Create Olts Data    ${num_olts}     ${voltservice_id}
    : FOR   ${OLT}  IN  @{olts}
    \   Log     ${OLT}
    \   ${res} =    CORD Post   /xosapi/v1/volt/oltdevices    ${OLT}
    \   ${jsondata} =    To Json    ${res.content}
    \   ${pon_ports} =      Create Pon Ports Data   ${num_pon_ports}    ${jsondata['id']}
    \   Create Pon Ports    ${pon_ports}

Delete Olts
    # FIXME can we simplify the loop? see "Activate ONUs"
    [Documentation]     Clean the whitelist
    ${res} =    CORD Get    /xosapi/v1/volt/oltdevices
    ${jsondata} =    To Json    ${res.content}
    :FOR    ${ELEMENT}    IN  @{jsondata['items']}
    \   Log     ${ELEMENT}
    \   ${id}=    Get From Dictionary    ${ELEMENT}    id
    \   Log     ${id}
    \   CORD Delete     /xosapi/v1/volt/oltdevices    ${id}

Create Pon Ports
    [Arguments]    ${pon_ports}
    : FOR   ${port}  IN  @{pon_ports}
    \   Log     ${port}
    \   CORD Post   /xosapi/v1/volt/ponports    ${port}

#Setup Whitelist
#    [Documentation]     Create a whitelist for the tests
#    ${onu_list} =       Create List
#    : FOR    ${INDEX}    IN RANGE    0    ${scale_size}
#    \   ${serial_number} =      Catenate    SEPARATOR=    MOCK0000000     ${INDEX}
#    \   Append To List    ${onu_list}    ${serial_number}
#    \   ${whitelist_entry} =    Create Dictionary   serial_number=${serial_number}  device_id=${olt_device_ofid}   pon_port_id=${pon_port_no}  owner_id=${attworkflowservice_id}
#    \   Log     ${whitelist_entry}
#    \   CORD Post   /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${whitelist_entry}
#    Log     ${onu_list}
#    Set Suite Variable  ${onu_list}

Clean Whitelist
    # FIXME can we simplify the loop? see "Activate ONUs"
    [Documentation]     Clean the whitelist
    ${res} =    CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries
    ${jsondata} =    To Json    ${res.content}
    ${length} =    Get Length    ${jsondata['items']}
    :FOR    ${INDEX}    IN RANGE    0    ${length}
    \   ${ELEMENT} =    Get From List    ${jsondata['items']}    ${INDEX}
    \   ${id}=    Get From Dictionary    ${ELEMENT}    id
    \   CORD Delete     /xosapi/v1/att-workflow-driver/attworkflowdriverwhitelistentries    ${id}

Store Data
    [Documentation]     Store all the ids needed for the test to work
    # Get AttWorkflowDriverService id
    ${resp}=    CORD Get    /xosapi/v1/att-workflow-driver/attworkflowdriverservices
    ${jsondata}=    To Json    ${resp.content}
    ${attworkflowservice}=    Get From List    ${jsondata['items']}    0
    ${attworkflowservice_id}=    Get From Dictionary    ${attworkflowservice}    id
    Set Suite Variable    ${attworkflowservice_id}

    # Get VoltService id
    ${resp}=    CORD Get    /xosapi/v1/volt/voltservices
    ${jsondata}=    To Json    ${resp.content}
    ${voltservice}=    Get From List    ${jsondata['items']}    0
    ${voltservice_id}=    Get From Dictionary    ${voltservice}    id
    Set Suite Variable    ${voltservice_id}

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
    ${resp}=    Get Request    XOS    ${service}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Post
    [Documentation]    Make a POST call to XOS
    [Arguments]    ${service}    ${data}
    ${data}=    Evaluate    json.dumps(${data})    json
    ${resp}=    Post Request    XOS    uri=${service}    data=${data}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to the CORD controller
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    XOS    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}