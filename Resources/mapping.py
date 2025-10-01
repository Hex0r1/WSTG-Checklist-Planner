# Regenerate the WSTG -> ASVS mapping, this time correctly assigning WSTG categories (4.1-4.12)
# and producing CSV and Excel files ready to download.
import pandas as pd
from io import StringIO

# Small ASVS excerpt to provide ASVS IDs/descriptions for mapping (best-effort).
asvs_csv = r"""chapter_id,chapter_name,section_id,section_name,req_id,req_description,L
V1,Encoding and Sanitization,V1.1,Encoding and Sanitization Architecture,V1.1.1,"Verify that input is decoded or unescaped into a canonical form only once, and before processing.",2
V1,Encoding and Sanitization,V1.2,Injection Prevention,V1.2.1,"Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required.",1
V1,Encoding and Sanitization,V1.2,Injection Prevention,V1.2.4,"Verify that data selection or database queries use parameterized queries, ORMs, or are otherwise protected from SQL Injection.",1
V3,Web Frontend Security,V3.3,Cookie Setup,V3.3.1,"Verify that cookies have the 'Secure' attribute set.",1
V3,Web Frontend Security,V3.4,Browser Security Mechanism Headers,V3.4.1,"Verify that a Strict-Transport-Security header field is included on all responses.",1
V5,Logging and Error Handling,V5.1,Error Handling,V5.1.1,"Verify that error handling does not leak stack traces or sensitive debug information to end users.",1
V6,Cryptography,V6.1,Transport Security,V6.1.1,"Verify TLS configuration and ensure weak ciphers/protocols are disabled.",1
V2,Validation and Business Logic,V2.2,Input Validation,V2.2.1,"Verify that input is validated to enforce business or functional expectations for that input.",1
V7,Authentication and Session Management,V7.1,Authentication,V7.1.1,"Verify password policy and secure password storage (hashing).",1
V7,Authentication and Session Management,V7.2,Session Management,V7.2.1,"Verify that session tokens are securely generated, stored, and have appropriate attributes.",1
V8,Authorization,V8.1,Access Control,V8.1.1,"Verify that authorization checks are enforced on the server side for protected resources.",1
V9,API Security,V9.1,API Security,V9.1.1,"Verify REST/GraphQL endpoints enforce authentication, authorization and input validation.",1
"""

asvs_df = pd.read_csv(StringIO(asvs_csv))

# WSTG tests list aligned to categories 4.1-4.12
wstg_tests = [
("WSTG-INFO-01","Conduct Search Engine Discovery","4.1 Information Gathering"),
("WSTG-INFO-02","Fingerprint Web Server","4.1 Information Gathering"),
("WSTG-INFO-03","Review Webserver Metafiles for Information Leakage","4.1 Information Gathering"),
("WSTG-INFO-04","Enumerate Applications on Webserver","4.1 Information Gathering"),
("WSTG-INFO-05","Fingerprint Web Application Framework","4.1 Information Gathering"),
("WSTG-INFO-06","Fingerprint Web Application","4.1 Information Gathering"),
("WSTG-INFO-07","Map Application Architecture","4.1 Information Gathering"),
("WSTG-CONF-01","Test Network/Infrastructure Configuration","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-02","Test Application Platform Configuration","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-03","Test File Extensions Handling","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-04","Review Old, Backup, and Unreferenced Files","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-05","Enumerate Infrastructure and Application Admin Interfaces","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-06","Test HTTP Methods","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-07","Test HTTP Strict Transport Security","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-08","Test RIA Cross Domain Policy","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-09","Test File Permissions","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-10","Test for Subdomain Takeover","4.2 Configuration and Deployment Management Testing"),
("WSTG-CONF-11","Test Cloud Storage","4.2 Configuration and Deployment Management Testing"),
("WSTG-IDNT-01","Test Role Definitions","4.3 Identity Management Testing"),
("WSTG-IDNT-02","Test User Registration Process","4.3 Identity Management Testing"),
("WSTG-IDNT-03","Test Account Provisioning Process","4.3 Identity Management Testing"),
("WSTG-IDNT-04","Testing for Account Enumeration and Guessable User Account","4.3 Identity Management Testing"),
("WSTG-ATHN-01","Test Password Policy","4.4 Authentication Testing"),
("WSTG-ATHN-02","Test for Bypassing Authentication Schema","4.4 Authentication Testing"),
("WSTG-ATHN-03","Test Remember Me Functionality","4.4 Authentication Testing"),
("WSTG-ATHN-04","Test for Browser Cache Weaknesses","4.4 Authentication Testing"),
("WSTG-ATHN-05","Test Weak Password Change or Reset Functionalities","4.4 Authentication Testing"),
("WSTG-ATHN-06","Test for Weaker Authentication in Alternative Channel","4.4 Authentication Testing"),
("WSTG-ATHZ-01","Test Directory Traversal","4.5 Authorization Testing"),
("WSTG-ATHZ-02","Test for Bypassing Authorization Schema","4.5 Authorization Testing"),
("WSTG-ATHZ-03","Test for Privilege Escalation","4.5 Authorization Testing"),
("WSTG-ATHZ-04","Test for Insecure Direct Object References","4.5 Authorization Testing"),
("WSTG-SESS-01","Test for Session Management Schema","4.6 Session Management Testing"),
("WSTG-SESS-02","Test for Cookies Attributes","4.6 Session Management Testing"),
("WSTG-SESS-03","Test for Session Fixation","4.6 Session Management Testing"),
("WSTG-SESS-04","Test for Exposed Session Variables","4.6 Session Management Testing"),
("WSTG-SESS-05","Test for Cross Site Request Forgery (CSRF)","4.6 Session Management Testing"),
("WSTG-SESS-06","Test for Logout Functionality","4.6 Session Management Testing"),
("WSTG-SESS-07","Test Session Timeout","4.6 Session Management Testing"),
("WSTG-SESS-08","Test for Session Puzzling","4.6 Session Management Testing"),
("WSTG-INPV-01","Test for Reflected Cross Site Scripting","4.7 Input Validation Testing"),
("WSTG-INPV-02","Test for Stored Cross Site Scripting","4.7 Input Validation Testing"),
("WSTG-INPV-03","Test for HTTP Response Splitting","4.7 Input Validation Testing"),
("WSTG-INPV-04","Test for SQL Injection","4.7 Input Validation Testing"),
("WSTG-INPV-05","Test for LDAP Injection","4.7 Input Validation Testing"),
("WSTG-INPV-06","Test for XML Injection","4.7 Input Validation Testing"),
("WSTG-INPV-07","Test for SSI Injection","4.7 Input Validation Testing"),
("WSTG-INPV-08","Test for XPath Injection","4.7 Input Validation Testing"),
("WSTG-INPV-09","Test for IMAP/SMTP Injection","4.7 Input Validation Testing"),
("WSTG-INPV-10","Test for Code Injection","4.7 Input Validation Testing"),
("WSTG-INPV-11","Test for Command Injection","4.7 Input Validation Testing"),
("WSTG-INPV-12","Test for Buffer Overflow","4.7 Input Validation Testing"),
("WSTG-INPV-13","Test for Format String Injection","4.7 Input Validation Testing"),
("WSTG-INPV-14","Test for Incubated Vulnerabilities","4.7 Input Validation Testing"),
("WSTG-INPV-15","Test for HTTP Splitting/Smuggling","4.7 Input Validation Testing"),
# Error handling
("WSTG-ERRH-01","Test for Improper Error Handling","4.8 Testing for Error Handling"),
("WSTG-ERRH-02","Test for Stack Traces or Debug Information Exposure","4.8 Testing for Error Handling"),
# Cryptography
("WSTG-CRYP-01","Test for Weak SSL/TLS Ciphers, Protocols, and Keys","4.9 Testing for Weak Cryptography"),
("WSTG-CRYP-02","Test for Padding Oracle","4.9 Testing for Weak Cryptography"),
("WSTG-CRYP-03","Test for Sensitive Information Sent via Unencrypted Channels","4.9 Testing for Weak Cryptography"),
("WSTG-CRYP-04","Test for Weak Password Hashing","4.9 Testing for Weak Cryptography"),
# Business logic
("WSTG-BUSL-01","Test Business Logic Data Validation","4.10 Business Logic Testing"),
("WSTG-BUSL-02","Test Ability to Forge Requests","4.10 Business Logic Testing"),
("WSTG-BUSL-03","Test Integrity Checks","4.10 Business Logic Testing"),
("WSTG-BUSL-04","Test for Process Timing","4.10 Business Logic Testing"),
("WSTG-BUSL-05","Test Number of Times a Function Can Be Used Limits","4.10 Business Logic Testing"),
("WSTG-BUSL-06","Testing for Circumvention of Workflows","4.10 Business Logic Testing"),
("WSTG-BUSL-07","Test for Defenses Against Application Misuse","4.10 Business Logic Testing"),
("WSTG-BUSL-08","Test Upload of Unexpected File Types","4.10 Business Logic Testing"),
("WSTG-BUSL-09","Test Upload of Malicious Files","4.10 Business Logic Testing"),
# Client-side
("WSTG-CLNT-01","Test DOM-Based Cross Site Scripting","4.11 Client-side Testing"),
("WSTG-CLNT-02","Test JavaScript Execution","4.11 Client-side Testing"),
("WSTG-CLNT-03","Test HTML Injection","4.11 Client-side Testing"),
("WSTG-CLNT-04","Test CSS Injection","4.11 Client-side Testing"),
("WSTG-CLNT-05","Test for Client-Side URL Redirect","4.11 Client-side Testing"),
("WSTG-CLNT-06","Test for Client-Side Resource Manipulation","4.11 Client-side Testing"),
("WSTG-CLNT-07","Test Cross-Origin Resource Sharing","4.11 Client-side Testing"),
("WSTG-CLNT-08","Test for Cross Site Flashing","4.11 Client-side Testing"),
("WSTG-CLNT-09","Test Clickjacking","4.11 Client-side Testing"),
("WSTG-CLNT-10","Test WebSockets","4.11 Client-side Testing"),
("WSTG-CLNT-11","Test Web Messaging","4.11 Client-side Testing"),
("WSTG-CLNT-12","Test Browser Storage","4.11 Client-side Testing"),
# API
("WSTG-API-01","Test GraphQL","4.12 API Testing"),
("WSTG-API-02","Test REST","4.12 API Testing"),
("WSTG-API-03","Test SOAP","4.12 API Testing"),
]

# Keyword mapping to ASVS excerpt
keyword_map = {
    "xss":["cross site scripting","xss","csp"],
    "sql":["sql","database","sql injection"],
    "ldap":["ldap"],
    "xpath":["xpath"],
    "csrf":["csrf","cross site request forgery"],
    "cookie":["cookie","samesite","httponly"],
    "session":["session","session fixation","session timeout"],
    "password":["password","hashing","reset"],
    "tls":["tls","ssl","cipher","hsts","strict-transport-security"],
    "cors":["cross-origin","cors","access-control"],
    "ssrf":["server-side request forgery","ssrf"],
    "deserial":["deserial","xxe","xml external"],
    "auth":["authentication","login","remember me","bypass"],
    "authz":["authorization","privilege","insecure direct object references","idor"],
    "file":["file","upload","backup"],
    "headers":["content-security-policy","x-content-type-options","headers"],
    "api":["graphql","rest","soap","api"],
    "error":["error","stack trace","debug"],
    "input":["input validation","validation"]
}

def find_best_asvs_match(test_name, asvs_df):
    text = test_name.lower()
    for key, terms in keyword_map.items():
        for term in terms:
            if term in text:
                matches = asvs_df[asvs_df['req_description'].str.lower().str.contains(term, na=False)]
                if not matches.empty:
                    row = matches.iloc[0]
                    return row['req_id'], row['req_description']
    # fallback mapping by high-level terms
    if "password" in text or "hash" in text:
        row = asvs_df[asvs_df['req_id'].str.startswith("V7")].iloc[0]
        return row['req_id'], row['req_description']
    if "tls" in text or "ssl" in text or "cipher" in text:
        row = asvs_df[asvs_df['req_id'].str.startswith("V6")].iloc[0]
        return row['req_id'], row['req_description']
    if "error" in text or "stack" in text:
        row = asvs_df[asvs_df['req_id'].str.startswith("V5")].iloc[0]
        return row['req_id'], row['req_description']
    # default to input validation
    row = asvs_df[asvs_df['req_id'].str.startswith("V1")].iloc[0]
    return row['req_id'], row['req_description']

rows = []
for wid,wname,cat in wstg_tests:
    asvs_id, asvs_desc = find_best_asvs_match(wname, asvs_df)
    rationale = f"Automated heuristic mapping based on keywords in WSTG test name."
    rows.append({
        "WSTG_Category": cat,
        "WSTG_ID": wid,
        "WSTG_Name": wname,
        "ASVS_Req_ID": asvs_id,
        "ASVS_Req_Description": asvs_desc,
        "Mapping_Rationale": rationale
    })

mapping_df = pd.DataFrame(rows)

# Save to CSV and Excel
csv_out = "/mnt/data/wstg_to_asvs_mapping_4.1-4.12.csv"
xlsx_out = "/mnt/data/wstg_to_asvs_mapping_4.1-4.12.xlsx"
mapping_df.to_csv(csv_out, index=False)
mapping_df.to_excel(xlsx_out, index=False)

# Display preview and provide file paths
import caas_jupyter_tools as tools; tools.display_dataframe_to_user("WSTG -> ASVS Mapping (4.1-4.12) - preview", mapping_df.head(80))
csv_out, xlsx_out, mapping_df.shape[0]
