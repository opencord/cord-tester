*** Settings ***
Documentation     Library to check the status in ONU List
Library           Collections
Library           String
Library           OperatingSystem
Library           XML
Library           RequestsLibrary
Library           ../Framework/utils/utils.py
Library           ../Framework/restApi.py

*** Keywords ***
ONU Status Check
    [Arguments]    ${onu_device}
    [Documentation]    Returns "operational_status" and "admin_status" of a particular ONU device from "onu device list"
    ${json_result}=    restApi.ApiGet    ONU_DEVICE
    Log    ${json_result}
    ${json_result_list}=    Get From dictionary    ${json_result}    items
    ${getJsonDict}=    utils.getDictFromListOfDict    ${json_result_list}    serial_number    ${onu_device}
    ${operational_status}=  Get From Dictionary    ${getJsonDict}   oper_status
    ${admin_status}=  Get From Dictionary    ${getJsonDict}   admin_state
    [Return]    ${operational_status}    ${admin_status} 
