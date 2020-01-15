*** Settings ***
Library           KafkaLibrary
Library           RequestsLibrary
Library           Collections
Library           String
Library           OperatingSystem
Suite Setup       Setup
Suite Teardown    Teardown

*** Variables ***
${cord_kafka}         cord-kafka
${xos_tosca}          xos-tosca
${xos_tosca_port}     9102
${server_ip}          xos-chameleon
${server_port}        9101

*** Test Cases ***
Validate Kubernetes Service Instance
    [Documentation]    Modify the demo-simpleexampleservice instance and validate webserver
    Wait Until Keyword Succeeds    120s    2s    Obtain SimpleExampleService SI
    Wait Until Keyword Succeeds    300s    2s    Get Kubernetes SI Pod IP
    Send Kafka Event    SimpleExampleEvent    {"service_instance": "My Simple Example Service Instance", "tenant_message": "world"}
    Wait Until Keyword Succeeds    60s    2s    Validate SI Message    world
    Wait Until Keyword Succeeds    120s    2s    Validate WebService Message    world
    Send Kafka Event    SimpleExampleEvent    {"service_instance": "My Simple Example Service Instance", "tenant_message": "Earth"}
    Wait Until Keyword Succeeds    60s    2s    Validate SI Message    Earth
    Wait Until Keyword Succeeds    120s    2s    Validate WebService Message    Earth
    #Delete Simpleexamplesi and verify webserver goes down
    CORD Delete    /xosapi/v1/simpleexampleservice/simpleexampleserviceinstances    ${demo_si_id}
    Wait Until Keyword Succeeds    300s    2s    Validate Webserver Gone

*** Keywords ***
Setup
    Connect Producer    ${cord_kafka}:9092    SimpleExampleEvent
    ${auth} =    Create List    admin@opencord.org    letmein
    ${HEADERS}    Create Dictionary    Content-Type=application/json
    Create Session    ${server_ip}    http://${server_ip}:${server_port}    auth=${AUTH}    headers=${HEADERS}
    #Create SimpleExampleServiceInstance from provided tosca recipes
    Run    git clone https://github.com/opencord/simpleexampleservice
    ${output}=    Run    curl -H "xos-username:admin@opencord.org" -H "xos-password:letmein" -X POST --data-binary @simpleexampleservice/xos/examples/SimpleExampleServiceInstance.yaml http://${xos_tosca}:${xos_tosca_port}/run
    Should Contain    ${output}    Created models

Teardown
    [Documentation]    Delete all models created
    Log    Tearing down
    Delete All Sessions

Validate Webserver Gone
    ${output}=    Run    http ${k8_pod_ip}
    Should Contain    ${output}    Request timed out

Obtain SimpleExampleService SI
    ${resp}=    CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleserviceinstances
    ${jsondata}=    To Json    ${resp.content}
    ${simpleexampleserviceinstance}=    Get From List    ${jsondata['items']}    0
    ${k8_si_id}=    Get From Dictionary    ${simpleexampleserviceinstance}    compute_instance_id
    ${demo_si_id}=    Get From Dictionary    ${simpleexampleserviceinstance}    id
    Set Suite Variable    ${k8_si_id}
    Set Suite Variable    ${demo_si_id}

Get Kubernetes SI Pod IP
    ${resp}=    CORD Get    /xosapi/v1/kubernetes/kubernetesserviceinstances/${k8_si_id}
    ${k8_pod_ip}=    Get From Dictionary    ${resp.json()}    pod_ip
    Set Suite Variable    ${k8_pod_ip}

Validate SI Message
    [Arguments]    ${message}
    ${resp}=    CORD Get    /xosapi/v1/simpleexampleservice/simpleexampleserviceinstances
    ${jsondata}=    To Json    ${resp.content}
    ${simpleexampleserviceinstance}=    Get From List    ${jsondata['items']}    0
    ${si_message}=    Get From Dictionary    ${simpleexampleserviceinstance}    tenant_message
    Should Be Equal As Strings    ${si_message}    ${message}

Validate WebService Message
    [Arguments]    ${message}
    ${output}=    Run    http ${k8_pod_ip} | grep ${message}
    Should Contain    ${output}   Tenant Message: "${message}"

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
    ${id}=    Get From Dictionary    ${resp.json()}    id
    Set Suite Variable    ${id}
    [Return]    ${resp}

CORD Delete
    [Documentation]    Make a DELETE call to the CORD controller
    [Arguments]    ${service}    ${data_id}
    ${resp}=    Delete Request    ${SERVER_IP}    uri=${service}/${data_id}
    Log    ${resp.content}
    Should Be Equal As Strings    ${resp.status_code}    200
    [Return]    ${resp}
