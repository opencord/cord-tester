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
Documentation     Library for interacting with XOS
Library           String
Library           RequestsLibrary

*** Keywords ***
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
    ${id}=    Get From Dictionary    ${resp.json()}    id
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
    [Documentation]    Find the id of owner of an XOS service
    [Arguments]    ${service}
    ${resp}=    CORD Get    ${service}
    ${jsondata}=    To Json    ${resp.content}
    log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    # FIXME: should this break after finding the first item?
    FOR    ${INDEX}    IN RANGE    0    ${length}
        ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
        ${id}=    Get From Dictionary    ${value}    id
    END
    [Return]    ${id}

Clean Up Objects
    [Documentation]    Delete all objects in XOS data model
    [Arguments]    ${model_api}
    @{ids}=    Create List
    ${resp}=    CORD Get    ${model_api}
    ${jsondata}=    To Json    ${resp.content}
    Log    ${jsondata}
    ${length}=    Get Length    ${jsondata['items']}
    FOR    ${INDEX}    IN RANGE    0    ${length}
        ${value}=    Get From List    ${jsondata['items']}    ${INDEX}
        ${id}=    Get From Dictionary    ${value}    id
        Append To List    ${ids}    ${id}
    END
    FOR    ${i}    IN    @{ids}
        CORD Delete    ${model_api}    ${i}
    END
