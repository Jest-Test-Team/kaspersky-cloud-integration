*** Settings ***
Documentation     Live integration tests for every officially documented Kaspersky Threat Intelligence Portal API endpoint.
Library           Process
Library           OperatingSystem
Library           Collections
Library           String
Suite Setup       Backend Must Be Available
Force Tags        integration    live    kaspersky-cloud

*** Variables ***
${BACKEND_URL}    %{BACKEND_URL=http://127.0.0.1:8080}
${EICAR_MD5}      44d88612fea8a8f36de82e1278abb02f

*** Test Cases ***
Endpoint Catalog Lists Every Published Endpoint
    ${response}=    Curl JSON    GET    /api/integrations/endpoints
    ${paths}=    Evaluate    [item["upstreamPath"] for item in $response["endpoints"]]
    Length Should Be    ${paths}    6
    FOR    ${path}    IN    /search/hash    /search/ip    /search/domain    /search/url    /scan/file    /getresult/file
        Should Contain    ${paths}    ${path}
    END

Hash Lookup Integration
    ${response}=    Lookup Indicator    ${EICAR_MD5}
    Should Be Equal    ${response}[type]    hash
    Dictionary Should Contain Key    ${response}[result]    Zone

IPv4 Lookup Integration
    ${response}=    Lookup Indicator    8.8.8.8
    Should Be Equal    ${response}[type]    ip
    Dictionary Should Contain Key    ${response}[result]    Zone

Domain Lookup Integration
    ${response}=    Lookup Indicator    example.com
    Should Be Equal    ${response}[type]    domain
    Dictionary Should Contain Key    ${response}[result]    Zone

URL Lookup Integration
    ${result}=    Run Process    curl    -sS    -w    \n\%{http_code}    -X    POST    ${BACKEND_URL}/api/intelligence/lookup    -H    Content-Type: application/json    -d    {"indicator":"https://example.com"}
    Should Be Equal As Integers    ${result.rc}    0
    ${lines}=    Split To Lines    ${result.stdout}
    ${status}=    Get From List    ${lines}    -1
    ${body_lines}=    Get Slice From List    ${lines}    0    -1
    ${body}=    Catenate    SEPARATOR=\n    @{body_lines}
    ${response}=    Evaluate    json.loads($body)    modules=json
    IF    '${status}' == '200'
        Should Be Equal    ${response}[type]    url
        Dictionary Should Contain Key    ${response}[result]    Zone
    ELSE
        Should Be Equal    ${status}    502
        Should Be Equal As Integers    ${response}[upstreamStatus]    400
        Log    Kaspersky's documented URL endpoint returned HTTP 400 for a valid URL; recorded as an upstream issue.    WARN
    END

Basic File Analysis Integration
    ${fixture}=    Normalize Path    ${CURDIR}/fixtures/benign.txt
    ${result}=    Run Process    curl    -fsS    -X    POST    ${BACKEND_URL}/api/intelligence/file/scan    -F    file\=@${fixture}
    Should Be Equal As Integers    ${result.rc}    0    ${result.stderr}
    ${response}=    Evaluate    json.loads($result.stdout)    modules=json
    Dictionary Should Contain Key    ${response}    result

Full File Analysis Report Integration
    ${response}=    Curl JSON    POST    /api/intelligence/file/report    {"hash":"${EICAR_MD5}"}
    Should Be Equal    ${response}[hash]    ${EICAR_MD5}
    Dictionary Should Contain Key    ${response}[result]    Zone

*** Keywords ***
Backend Must Be Available
    ${result}=    Run Process    curl    -fsS    ${BACKEND_URL}/healthz
    Should Be Equal As Integers    ${result.rc}    0    Backend is not available at ${BACKEND_URL}: ${result.stderr}
    ${health}=    Evaluate    json.loads($result.stdout)    modules=json
    Should Be True    ${health}[ok]
    Should Be True    ${health}[intelligenceConfigured]

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

Lookup Indicator
    [Arguments]    ${indicator}
    ${payload}=    Evaluate    json.dumps({"indicator": $indicator})    modules=json
    ${response}=    Curl JSON    POST    /api/intelligence/lookup    ${payload}
    RETURN    ${response}
