*** Settings ***
Documentation     Integration tests for the Kaspersky Security Center 15.2 Open API surface exposed by the backend.
...               Live Administration Server calls are tolerant of upstream failures because the configured
...               console may not expose the KSC Open API endpoint (port 13299) to this client.
Library           Process
Library           Collections
Library           String
Suite Setup       Backend Must Be Available
Force Tags        integration    ksc    kaspersky-security-center

*** Variables ***
${BACKEND_URL}    %{BACKEND_URL=http://127.0.0.1:8080}

*** Test Cases ***
KSC Status Reports Configuration And Catalog
    ${response}=    Curl JSON    GET    /api/ksc/status
    Should Contain    ${response}[product]    Open API
    Dictionary Should Contain Key    ${response}    configured
    Dictionary Should Contain Key    ${response}    baseUrl
    Should Not Be Empty    ${response}[operations]

KSC Method Catalog Lists Documented Operations
    ${response}=    Curl JSON    GET    /api/ksc/methods
    ${methods}=    Evaluate    [op["method"] for op in $response["operations"]]
    Should Contain    ${methods}    StartSession
    Should Contain    ${methods}    FindHosts
    Should Contain    ${methods}    GetStaticInfo

KSC Call Proxy Rejects Methods Outside The Allow List
    ${status}    ${response}=    Curl With Status    POST    /api/ksc/call    {"class":"HostGroup","method":"RemoveHost"}
    Should Be Equal    ${status}    403
    Dictionary Should Contain Key    ${response}    error

KSC Session Start Returns Session Or Graceful Error
    Assert KSC Endpoint    POST    /api/ksc/session    sessionId

KSC Server Info Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/server-info    serverInfo

KSC Hosts Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/hosts    hosts

KSC Groups Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/groups    groups

KSC Licenses Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/licenses    licenses

KSC Software Inventory Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/software    software

KSC Reports Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/reports    reports

KSC Events Returns Data Or Graceful Error
    Assert KSC Endpoint    GET    /api/ksc/events    events

KSC Catalog Includes Cloud Read-Only Operations
    ${response}=    Curl JSON    GET    /api/ksc/methods
    ${methods}=    Evaluate    [op["method"] for op in $response["operations"]]
    Should Contain    ${methods}    GetInvProductsList
    Should Contain    ${methods}    EnumReports
    Should Contain    ${methods}    CreateEventProcessing2

*** Keywords ***
Backend Must Be Available
    ${result}=    Run Process    curl    -fsS    ${BACKEND_URL}/healthz
    Should Be Equal As Integers    ${result.rc}    0    Backend is not available at ${BACKEND_URL}: ${result.stderr}
    ${health}=    Evaluate    json.loads($result.stdout)    modules=json
    Should Be True    ${health}[ok]
    Dictionary Should Contain Key    ${health}    kscConfigured

Curl JSON
    [Arguments]    ${method}    ${path}    ${payload}=${EMPTY}
    IF    '${payload}' == '${EMPTY}'
        ${result}=    Run Process    curl    -fsS    -X    ${method}    ${BACKEND_URL}${path}
    ELSE
        ${result}=    Run Process    curl    -fsS    -X    ${method}    ${BACKEND_URL}${path}    -H    Content-Type: application/json    -d    ${payload}
    END
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    ${response}=    Evaluate    json.loads($result.stdout)    modules=json
    RETURN    ${response}

Curl With Status
    [Arguments]    ${method}    ${path}    ${payload}=${EMPTY}
    IF    '${payload}' == '${EMPTY}'
        ${result}=    Run Process    curl    -sS    -w    \n\%{http_code}    -X    ${method}    ${BACKEND_URL}${path}
    ELSE
        ${result}=    Run Process    curl    -sS    -w    \n\%{http_code}    -X    ${method}    ${BACKEND_URL}${path}    -H    Content-Type: application/json    -d    ${payload}
    END
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    ${lines}=    Split To Lines    ${result.stdout}
    ${status}=    Get From List    ${lines}    -1
    ${body_lines}=    Get Slice From List    ${lines}    0    -1
    ${body}=    Catenate    SEPARATOR=\n    @{body_lines}
    ${response}=    Evaluate    json.loads($body)    modules=json
    RETURN    ${status}    ${response}

Assert KSC Endpoint
    [Documentation]    Passes when the endpoint returns 200 with ${success_key}, or a graceful error response.
    [Arguments]    ${method}    ${path}    ${success_key}
    ${status}    ${response}=    Curl With Status    ${method}    ${path}
    IF    '${status}' == '200'
        Dictionary Should Contain Key    ${response}    ${success_key}
    ELSE
        Dictionary Should Contain Key    ${response}    error
        Log    ${path} returned HTTP ${status}: ${response}[error]    WARN
    END
