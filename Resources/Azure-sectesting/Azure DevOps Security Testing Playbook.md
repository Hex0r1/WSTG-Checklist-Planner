
# Security testing

Use security tests to verify that the required security controls are in place, as defined in the security requirements. This chapter will discuss the selection of security tools; adding security tests into the development pipeline; the types of testing and tools that can be used; vulnerability management; and the use of penetration testing. For a detailed guide on how to conduct security testing refer to the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/).

## Using security tools
Care should be taken when selecting and embedding security tools. Security tools should be easy for a developer to use, ideally embedded within a developer native tool, rather than be operated solely by an application security engineer. The security team should tune code scanner tools to ensure a minimum of false positives are reported such that the tool provides value, and does not waste the developers' time. Too many false positives could lead to developers ignoring true positives.

Security tools should give a good indication of what the found issues are and how to fix them. Security tool findings can be provided directly to the developers, to allow for rapid feedback on any security issues. In some cases it will be necessary first for the security team to provide an analysis of the findings.
Security tests can be configured to fail a code build if the tests do not pass. For development on a new codebase it can be useful to add in security tests from the start, such that developers are used to these checks.
## Adding security tests into the development pipeline

Security tests have traditionally been conducted after code has been deployed. However, security tests can also be added in earlier phases of the SDLC, such as develop and commit[1](https://owasp.org/www-project-security-culture/v10/7-Security_Testing/#fn:6). Security tests can run as the code is written, with feedback delivered directly in the IDE (Integrated Development Environment). Security tests can happen at commit time, checking for known insecure patterns in the source code before being added to the code repository or merged to the main branch, this is known as Static Application Security Testing (SAST). Security tests are run at build time, such as checking for any vulnerabilities in libraries, known as Software Composition Analysis (SCA); or vulnerabilties in container images. Security tests run at deploy time, which allows automated testing on a running application, known as Dynamic Application Security Testing (DAST)..

![Security Testing Tools by SDLC Phase Diagram](https://owasp.org/www-project-security-culture/v10/7-Security_Testing/images/security_testing.png)  
_Figure 7-1: Security Testing Tools by SDLC Phase Diagram_

## Types of security tests

This section will provide a list of the OWASP projects that can be used in the different SDLC phases. See also [Free for Open Source Application Security Tools](https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools)

### Checks at coding time

- IDE plugin: part of a Static Application Security Testing (SAST) tool that highlights secure coding recommendations in real time within the developer's Integrated Development Environment as they write code

### Tests at commit time

- Static Application Security Testing (SAST): provides feedback upon commit of source code. For more details see [OWASP Source Code Analysis Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- Secrets scanner: check for sensitive data such as passwords and api keys that may appear in committed source code or configuration files
- Infrastructure as Code (IaC) analysis: infrastructure resources can be defined and created from static files, providing the opportunity to run security checks when the files are committed before the infrastructure changes are made.

### Tests at build time

- Software Composition Analysis (SCA): Check for vulnerabilities in third party libraries used by the application. For more details see [OWASP Component Analysis](https://owasp.org/www-community/Component_Analysis)
    - [OWASP Dependency track](https://owasp.org/www-project-dependency-track/)
    - [OWASP Dependency check](https://owasp.org/www-project-dependency-check/)
- Image scanning: Container images can be scanned for vulnerabilities before deployment
### Tests at deploy time

- Dynamic Application Security Testing (DAST): tests performed on the running application. Tests can be conducted in a non-production environment before moving to production. For more details see [OWASP Vulnerability Scanning Tools](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
    
    - [OWASP ZAP](https://www.zaproxy.org/)

## Vulnerability management

As vulnerabilities are identified from security testing tools they need to be recorded and managed. As mentioned in the threat modelling section, vulnerabilities should be defined with an Impact and Likelihood risk rating. Risk ratings use a quantitative rating such as the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology), or qualitative using for example low; medium; high. When vulnerabilities are assigned a risk rating, this allows their remediation to be prioritised accordingly. An organisation may implement a required timeframe that vulnerabilities of a particular risk rating are to be remediated.
- [OWASP Defect dojo](https://owasp.org/www-project-defectdojo/)
## Penetration testing

A penetration tester plays the role of the attacker to find and exploit vulnerabilities. This helps provide a more accurate risk rating than vulnerability scans alone. Although penetration testing occurs at the end of the SDLC, the results of the penetration test can provide feedback for tests in the earlier phases. Such as additional rules for SAST and DAST scanners, and to use SCA to confirm vulnerabilities found by the penetration test[2](https://owasp.org/www-project-security-culture/v10/7-Security_Testing/#fn:7).

A penetration test report should clearly detail found vulnerabilities, and how to fix them. It is also helpful to show how the vulnerability was exploited. This helps a developer test that their fix has worked.

A security team needs to help the development team interpret the penetration test report and provide guidance. An application security engineer may first check the report to remove any false positives before assigning developers to address the found vulnerabilities.

1. Scott Gerlach, Developer's struggle with security, OWASP 20th Anniversary. 2021. [↩](https://owasp.org/www-project-security-culture/v10/7-Security_Testing/#fnref:6)
2. Daniel Krasnokucki, Feedback loop in DevSecOps - mature security process and dev cooperation, OWASP 20th Anniversary. 2021. [↩](https://owasp.org/www-project-security-culture/v10/7-Security_Testing/#fnref:7)

from: https://owasp.org/www-project-security-culture/v10/7-Security_Testing/

---
Integrating OWASP's Web Security Testing Guide (WSTG) v5.0 with the Application Security Verification Standard (ASVS) v5.0 in your Azure DevOps environment is an excellent approach to enhance your security testing practices. Below is a comprehensive guide to help you achieve this integration effectively.
## 🔗 1. ASVS v5.0 to WSTG v5.0 Mapping

A direct 1-to-1 mapping between ASVS v5.0 and WSTG v5.0 is challenging due to the differing scopes of these standards:
- **ASVS** focuses on "what to verify" in terms of security controls.
- **WSTG** provides detailed "how to test" methodologies.

However, there are resources that attempt to bridge this gap:

- **OWASP ASVS-WSTG Checklist**: This spreadsheet maps ASVS controls to WSTG test cases, offering a practical guide for testers. [GitHub](https://github.com/jeremychoi/owasp-asvs-wstg-checklist?utm_source=chatgpt.com)
- **JulianGR/OWASP_WSTG_ASVS**: This GitHub repository provides a mapping between WSTG and ASVS, including CVSS scores, CWE identifiers, and remediation advice. [GitHub](https://github.com/JulianGR/OWASP_WSTG_ASVS?utm_source=chatgpt.com)

### 1.1 OWASP WSTG v5.0 Test Categories
`list all category of test in OWASP wstg v 5.0`
- **WSTG-INFO** – Information Gathering
- **WSTG-CONF** – Configuration and Deployment Management Testing
- **WSTG-IDNT** – Identity Management Testing
- **WSTG-ATHN** – Authentication Testing
- **WSTG-ATHZ** – Authorization Testing
- **WSTG-SESS** – Session Management Testing
- **WSTG-INPV** – Input Validation Testing
- **WSTG-CRYP** – Testing for Weak Cryptography
- **WSTG-ERRH** –  Testing for Improper Error Handling
- **WSTG-BUSL** – Business Logic Testing
- **WSTG-CLNT** – Client-Side Testing
- **WSTG-API** – API Testing
<font color="#c0504d">- **WSTG-MOBI** – Testing for Mobile Applications</font>
- WSTG-MOBI-01: Testing Platform Interaction
- WSTG-MOBI-02: Testing for Data Storage and Privacy
- WSTG-MOBI-03: Testing Communication with Mobile App
- WSTG-MOBI-04: Testing Code Quality and Build Settings
<font color="#c0504d">- **WSTG-DOCK** – Testing for Deployments in Modern Containers</font>
- WSTG-DOCK-01: Docker Security Testing
- WSTG-DOCK-02: Kubernetes Security Testing

build the **full detailed breakdown of OWASP WSTG v5.0 test cases**.  
Each category is broken down into **specific tests with IDs**. This is the authoritative structure you’ll need for mapping against **ASVS v5.0**
# 📚 OWASP WSTG v5.0 – Correct Test Case List

## **4.1 Information Gathering**

- WSTG-INFO-01: Conduct Search Engine Discovery
    
- WSTG-INFO-02: Fingerprint Web Server
    
- WSTG-INFO-03: Review Webserver Metafiles for Information Leakage
    
- WSTG-INFO-04: Enumerate Applications on Webserver
    
- WSTG-INFO-05: Fingerprint Web Application Framework
    
- WSTG-INFO-06: Fingerprint Web Application
    
- WSTG-INFO-07: Map Application Architecture
    

---

## **4.2 Configuration and Deployment Management Testing**

- WSTG-CONF-01: Test Network/Infrastructure Configuration
    
- WSTG-CONF-02: Test Application Platform Configuration
    
- WSTG-CONF-03: Test File Extensions Handling
    
- WSTG-CONF-04: Review Old, Backup, and Unreferenced Files
    
- WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces
    
- WSTG-CONF-06: Test HTTP Methods
    
- WSTG-CONF-07: Test HTTP Strict Transport Security
    
- WSTG-CONF-08: Test RIA Cross Domain Policy
    
- WSTG-CONF-09: Test File Permissions
    
- WSTG-CONF-10: Test for Subdomain Takeover
    
- WSTG-CONF-11: Test Cloud Storage
    

---

## **4.3 Identity Management Testing**

- WSTG-IDNT-01: Test Role Definitions
    
- WSTG-IDNT-02: Test User Registration Process
    
- WSTG-IDNT-03: Test Account Provisioning Process
    
- WSTG-IDNT-04: Testing for Account Enumeration and Guessable User Account
    

---

## **4.4 Authentication Testing**

- WSTG-ATHN-01: Test Password Policy
    
- WSTG-ATHN-02: Test for Bypassing Authentication Schema
    
- WSTG-ATHN-03: Test Remember Me Functionality
    
- WSTG-ATHN-04: Test for Browser Cache Weaknesses
    
- WSTG-ATHN-05: Test Weak Password Change or Reset Functionalities
    
- WSTG-ATHN-06: Test for Weaker Authentication in Alternative Channel
    

---

## **4.5 Authorization Testing**

- WSTG-ATHZ-01: Test Directory Traversal
    
- WSTG-ATHZ-02: Test for Bypassing Authorization Schema
    
- WSTG-ATHZ-03: Test for Privilege Escalation
    
- WSTG-ATHZ-04: Test for Insecure Direct Object References
    

---

## **4.6 Session Management Testing**

- WSTG-SESS-01: Test for Session Management Schema
    
- WSTG-SESS-02: Test for Cookies Attributes
    
- WSTG-SESS-03: Test for Session Fixation
    
- WSTG-SESS-04: Test for Exposed Session Variables
    
- WSTG-SESS-05: Test for Cross Site Request Forgery (CSRF)
    
- WSTG-SESS-06: Test for Logout Functionality
    
- WSTG-SESS-07: Test Session Timeout
    
- WSTG-SESS-08: Test for Session Puzzling
    

---

## **4.7 Input Validation Testing**

- WSTG-INPV-01: Test for Reflected Cross Site Scripting
    
- WSTG-INPV-02: Test for Stored Cross Site Scripting
    
- WSTG-INPV-03: Test for HTTP Response Splitting
    
- WSTG-INPV-04: Test for SQL Injection
    
- WSTG-INPV-05: Test for LDAP Injection
    
- WSTG-INPV-06: Test for XML Injection
    
- WSTG-INPV-07: Test for SSI Injection
    
- WSTG-INPV-08: Test for XPath Injection
    
- WSTG-INPV-09: Test for IMAP/SMTP Injection
    
- WSTG-INPV-10: Test for Code Injection
    
- WSTG-INPV-11: Test for Command Injection
    
- WSTG-INPV-12: Test for Buffer Overflow
    
- WSTG-INPV-13: Test for Format String Injection
    
- WSTG-INPV-14: Test for Incubated Vulnerabilities
    
- WSTG-INPV-15: Test for HTTP Splitting/Smuggling
    

---

## **4.8 Testing for Error Handling**

- WSTG-ERRH-01: Test for Improper Error Handling
    
- WSTG-ERRH-02: Test for Stack Traces or Debug Information Exposure
    

---

## **4.9 Testing for Weak Cryptography**

- WSTG-CRYP-01: Test for Weak SSL/TLS Ciphers, Protocols, and Keys
    
- WSTG-CRYP-02: Test for Padding Oracle
    
- WSTG-CRYP-03: Test for Sensitive Information Sent via Unencrypted Channels
    
- WSTG-CRYP-04: Test for Weak Password Hashing
    

---

## **4.10 Business Logic Testing**

- WSTG-BUSL-01: Test Business Logic Data Validation
    
- WSTG-BUSL-02: Test Ability to Forge Requests
    
- WSTG-BUSL-03: Test Integrity Checks
    
- WSTG-BUSL-04: Test for Process Timing
    
- WSTG-BUSL-05: Test Number of Times a Function Can Be Used Limits
    
- WSTG-BUSL-06: Testing for Circumvention of Workflows
    
- WSTG-BUSL-07: Test for Defenses Against Application Misuse
    
- WSTG-BUSL-08: Test Upload of Unexpected File Types
    
- WSTG-BUSL-09: Test Upload of Malicious Files
    

---

## **4.11 Client-side Testing**

- WSTG-CLNT-01: Test DOM-Based Cross Site Scripting
    
- WSTG-CLNT-02: Test JavaScript Execution
    
- WSTG-CLNT-03: Test HTML Injection
    
- WSTG-CLNT-04: Test CSS Injection
    
- WSTG-CLNT-05: Test for Client-Side URL Redirect
    
- WSTG-CLNT-06: Test for Client-Side Resource Manipulation
    
- WSTG-CLNT-07: Test Cross-Origin Resource Sharing
    
- WSTG-CLNT-08: Test for Cross Site Flashing
    
- WSTG-CLNT-09: Test Clickjacking
    
- WSTG-CLNT-10: Test WebSockets
    
- WSTG-CLNT-11: Test Web Messaging
    
- WSTG-CLNT-12: Test Browser Storage
    

---

## **4.12 API Testing**

- WSTG-API-01: Test GraphQL
    
- WSTG-API-02: Test REST
    
- WSTG-API-03: Test SOAP
    

---

✅ This must get into the **Azure DevOps mapping file**.

Do you want me to now **regenerate the CSV/Excel mapping** with these corrected categories and align them again to **ASVS v5.0 controls**?


### 1.2  Mapping test to ASVS controls
map  WSTG v5.0 tests to ASVS 5.0 controls and create ready-to-use CSV/Excel file
- A mapping table (one WSTG test per row) with these columns:
    
    - **WSTG_ID** — e.g. `WSTG-INPV-04`
    - **WSTG_Name** — test name from WSTG v5.0
    - **ASVS_Req_ID** — the ASVS v5.0 requirement ID (e.g. `V1.2.4`) chosen by automated keyword matching
    - **ASVS_Req_Description** — the ASVS requirement text
    - **Mapping_Rationale** — short note explaining how the mapping was chosen (automated keyword match)
- Files created and saved:
    - CSV: `/mnt/data/wstg_to_asvs_mapping.csv`
    - Excel: `/mnt/data/wstg_to_asvs_mapping.xlsx`


notes:
- Many WSTG tests logically relate to multiple ASVS requirements — the ASVS is more granular in parts — and a strict 1:1 mapping sometimes forces a “primary” control choice where multiple controls apply.
- Review the spreadsheet to confirm/adjust mappings where appropriate (especially for business-logic tests, multi-step auth/authz flows, API, mobile and container tests).
- For any WSTG test that should map to multiple ASVS requirements in your organization, add additional rows or create links in your test-management tool to reflect that (Azure DevOps supports linking one test case to multiple work items).
- Convert this mapping to an **Azure DevOps Work Item import template** (CSV formatted with fields `Title`, `Description`, `Work Item Type`, `Tags`, `Area Path`, `Iteration Path`, and a field for `ASVS_Req_ID`) so you can directly import the mapping as work items/test cases into your project.
- Produce a **human-reviewed mapping** (I’ll expand and correct the automated choices to ensure accuracy and include multiple ASVS mappings where appropriate). This is more time-consuming but recommended if you need an authoritative 1:1 validated mapping.
- Customize the mapping to your preferred **ASVS level(s)** (L1/L2/L3) and add a column to indicate which ASVS level(s) are applicable per WSTG test.
- ASVS v5.0 is a large, structured standard — many ASVS requirements are applicable across multiple WSTG tests (for example input validation, encoding/escaping, and CSRF controls). A human expert should validate the mappings to ensure test coverage and correct priority (L1/L2/L3). I flagged mappings with the automated rationale so you can quickly scan and correct.
- Create the Azure DevOps import CSV template (I’ll format `Title`, `Description` and recommended `Work Item Type` = Test Case), or
- Perform a manual review refinement of the mappings and produce a second, validated Excel file

tell me which you prefer and I’ll update the files accordingly and provide the new download links

## 🛠️ 2. Importing the Mapping into Azure DevOps

To integrate this mapping into Azure DevOps:

1. **Download the Mapping Files**:
    
    - Obtain the checklist from the [OWASP ASVS-WSTG Checklist GitHub repository](https://github.com/jeremychoi/owasp-asvs-wstg-checklist?utm_source=chatgpt.com).
        
2. **Convert to Azure DevOps Format**:
    
    - Convert the downloaded Excel or ODS file into a format compatible with Azure DevOps, such as CSV.
        
3. **Import as Work Items**:
    
    - Use Azure DevOps' "Import Work Items" feature to upload the CSV file. Ensure that each row corresponds to a work item, with columns for ASVS ID, WSTG ID, description, and other relevant details.
        
4. **Organize into Test Suites**:
    
    - Group work items into test suites based on ASVS chapters or WSTG categories to maintain a structured approach.
        

---

## 📁 3. Organizing Test Artifacts in Azure DevOps

For effective traceability and reporting:

- **Test Plans**: Create separate test plans for each ASVS level (L1, L2, L3).
    
- **Test Suites**: Organize test suites by ASVS chapters or WSTG categories.
    
- **Test Cases**: Define test cases based on the mapping, referencing both ASVS and WSTG identifiers.
    
- **Test Results**: Record outcomes, attach evidence (e.g., screenshots, logs), and link to the corresponding work items.
    

---

## 🔄 4. Structuring Security Testing Workflows

Integrate security testing into your development lifecycle:

1. **Pre-Commit Phase**:
    
    - Implement static code analysis tools to catch basic security issues early.
        
2. **Build Pipeline**:
    
    - Incorporate security testing tools (e.g., SAST, DAST) into your CI/CD pipeline.
        
3. **Test Execution**:
    
    - Execute the mapped test cases during the testing phase.
        
    - Use Azure DevOps' test execution and reporting features to track progress.
        
4. **Post-Deployment**:
    
    - Conduct security assessments in staging or production environments.
        

---

## ⚠️ 5. Common Challenges and Strategies

- **Challenge**: Mapping discrepancies between ASVS and WSTG.
    
    - **Strategy**: Regularly review and update the mapping to align with the latest standards.
        
- **Challenge**: Overwhelming volume of test cases.
    
    - **Strategy**: Prioritize test cases based on risk assessment and business impact.
        
- **Challenge**: Integrating security testing into existing workflows.
    
    - **Strategy**: Start with a pilot project, gather feedback, and iterate on the process.
        
- **Challenge**: Lack of expertise in Azure DevOps.
    
    - **Strategy**: Invest in training and leverage Azure DevOps' extensive documentation and community resources.
        

---

## ✅ 6. Recommendations for Effective Integration

- **Use Azure DevOps Extensions**: Explore extensions like "OWASP ZAP" for dynamic analysis and "SonarQube" for static analysis.
    
- **Automate Reporting**: Set up dashboards to visualize test results and track compliance over time.
    
- **Continuous Improvement**: Regularly update your test cases and mappings to reflect changes in ASVS and WSTG.
## OWASP WSTG V5.0 & ASVS V5.0 – Starter Edition  
*(Audience: security testers who know OWASP but are new to Azure DevOps)*

---

## 0. 30-Second Primer – “What is Azure DevOps?”
- **Organization** → top-level container  
- **Project** → one application / one product line  
- **Boards** → user-stories & bugs  
- **Repos** → Git or TFVC  
- **Pipelines** → CI / CD  
- **Test Plans** → container for **Test Suites** (static, requirement-based, query-based)  
- **Test Suites** → container for **Test Cases**  
- **Test Cases** → atomic checks (manual or automated)  
- **Configurations** → browser / OS matrix  
- **Runs & Analytics** → pass/fail, bugs, traceability  

> Everything can be created from the web UI, REST API, or an Excel/Grid view.  
> Security artefacts are stored in the same places as functional ones—no separate licence is required.

---

## 1. Big-Picture Workflow
1. Pick ASVS level (L1, L2, L3) → defines coverage target.  
2. Map every WSTG test that can satisfy an ASVS requirement.  
3. Create one **Security Master Test Plan** per project.  
4. Under it, create **Test Suites** = ASVS chapter (V4, V5 …).  
5. Add **Test Cases** = WSTG tests (or custom variants).  
6. Link each Test Case to:  
   - User-Story “Implement ASVS V5.3” (requirement-based suite)  
   - Work-item type = “Security Test Case” (custom)  
7. Run manually via **Test Runner** or automate in **Pipelines** (YAML).  
8. Log bugs with tag “Security-ASVS-L2” for fast queries.  
9. Use **Pass/Fail** + **Custom field “ASVS satisfied”** = Yes/No.  
10. Dashboard widgets: **“Security tests passed %”**, **“Open critical bugs”**.

---

## 2. Security Master Test Plan (template)
| Field | Example value |
|-------|---------------|
| Name | `[AppName] Security Validation – ASVS L2` |
| Area Path | `\Security` |
| Iteration | `PI-12` |
| Owner | `security-champion@contoso.com` |
| Description | Validates every ASVS L2 control using WSTG V5.0 tests. Runs on every release candidate. |

---

## 3. Test Suite Catalogue (1-to-1 with ASVS chapters)
| Suite ID | Suite Title            | ASVS Chapter | Typical WSTG Chapters |
| -------- | ---------------------- | ------------ | --------------------- |
| SEC-01   | Authentication         | V2           | WSTG-ATHN-xx          |
| SEC-02   | Session Management     | V3           | WSTG-SESS-xx          |
| SEC-03   | Access Control         | V4           | WSTG-ATHZ-xx          |
| SEC-04   | Validation & Injection | V5           | WSTG-INPV-xx          |
| SEC-05   | Cryptography           | V6           | WSTG-CRYP-xx          |
| SEC-06   | Error Handling         | V7           | WSTG-ERR-xx           |
| SEC-07   | Business Logic         | V8           | WSTG-BUSL-xx          |
| SEC-08   | Client-side            | V9           | WSTG-CLNT-xx          |
| SEC-09   | API / Web-service      | V10          | WSTG-APIN-xx          |
| SEC-10   | Configuration          | V14          | WSTG-CONF-xx          |

> Tip: keep the same numbering in your repo folders `/security-test/WSTG-INPV-01.md` for quick discovery.

---

## 4. Test Case Library – 30 Starter Cases
*(Copy-paste grid into Azure DevOps → Test Plans → New Test Case)*

| Test Case ID | Test Case Title | Description (steps) | Related ASVS Control | Related WSTG Test | Expected Outcome |
|--------------|-----------------|---------------------|----------------------|-------------------|------------------|
| SEC-04-01 | SQL Injection in Login Form | 1. Navigate to `/login`<br>2. Enter `' OR 1=1--` in user field<br>3. Leave password blank & submit | V5.3 – Injection Defense | WSTG-INPV-05 | 401 error, no SQL exception, no data returned |
| SEC-04-02 | Reflected XSS on Search | 1. Go to `/search?q=test`<br>2. Replace query with `<script>alert(1)</script>`<br>3. Press Enter | V5.4 – XSS Prevention | WSTG-INPV-01 | Script is neutralised (`&lt;`) and no alert fires |
| SEC-02-01 | Session Fixation | 1. Grab `JSESSIONID` cookie from attacker session<br>2. Force victim to use same ID via URL<br>3. Victin logs in | V3.2 – Session Fixation | WSTG-SESS-03 | New session token issued after login |
| SEC-03-01 | Direct Object Reference | 1. Login as `userA`<br>2. Browse `/invoice/1234`<br>3. Change to `/invoice/5678` (belongs to userB) | V4.2 – Access Control | WSTG-ATHZ-04 | 403 Forbidden – access denied |
| SEC-10-01 | Security Headers Missing | 1. `curl -I https://app.contoso.com`<br>2. Inspect headers | V14.4 – Security Configuration | WSTG-CONF-08 | `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` present |
| SEC-05-01 | Weak TLS Ciphers | 1. Run `testssl.sh https://app.contoso.com`<br>2. Check for TLS 1.0/1.1 or 3DES | V6.2 – Cipher Strength | WSTG-CRYP-01 | Only TLS 1.2/1.3 with AEAD ciphers accepted |
| SEC-07-01 | Business Logic Bypass (discount) | 1. Add item to cart<br>2. Apply 100%-off coupon twice in Burp repeater | V8.2 – Business Logic | WSTG-BUSL-01 | Server rejects second use with message “Coupon already applied” |
| SEC-09-01 | JWT None Algorithm | 1. Intercept API call<br>2. Change header `"alg":"none"`, remove signature<br>3. Forward | V10.2 – API Security | WSTG-APIN-03 | 401 – “Invalid signature” |
| SEC-06-01 | Information Leakage on 500 | 1. Send malformed JSON to `/api/transfer`<br>2. Inspect response | V7.1 – Error Handling | WSTG-ERR-01 | Generic error ID only, no stack trace |
| SEC-01-01 | Password Complexity Enforced | 1. Register with password `123`<br>2. Submit | V2.2 – Credential Strength | WSTG-ATHN-07 | UI & API reject with message “Min 12 chars, 1 symbol required” |

> Feel free to clone and parameterise (Data-driven test) with variables `{{URL}}`, `{{ATTACK_PAYLOAD}}`.

---

## 5. Automation in Azure Pipelines – Minimal YAML
```yaml
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

variables:
  zapTarget: 'https://$(webAppName)-dev.azurewebsites.net'

stages:
- stage: SecurityTests
  displayName: 'ASVS L2 Fast Feedback'
  jobs:
  - job: DynamicScan
    steps:
    - task: owaspzap.zap-azure-task.zap@1
      inputs:
        targetUrl: $(zapTarget)
        rulesFile: '$(Build.SourcesDirectory)/security-test/zap-rules.tsv'
    - task: PublishTestResults@2
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: '**/zap-report.xml'
        testRunTitle: 'OWASP ZAP – WSTG-ERR, WSTG-CONF'
```

> Link the published results back to Test Cases using **Test Case ID** in the JUnit `<testcase name="">` – Azure DevOps will auto-map.

---

## 6. Step-by-Step – Create Your First Security Test Plan
1. **Organisation settings** → **Process** → create inherited process → add work-item type **“Security Test Case”** with fields:  
   - ASVS-Control, WSTG-ID, ASVS-Level, Automation-Script-URL  
2. **Project** → **Test Plans** → **New Test Plan** → name `[App] Security Validation – ASVS L2`  
3. **Add existing suite** → choose **“Requirement-based suite”** → pick user-story **“Implement ASVS V5.3”**  
4. **New Test Case** → copy template rows from Section 4 → paste (grid view allows Excel-like paste)  
5. Assign **Tester** = security champion; **Configuration** = Windows 11 + Edge, iOS + Safari  
6. **Save & run via web runner** → record pass/fail + attach screenshot/Burp file  
7. If fail → **Create bug** → set **Severity** = High, **Tag** = ASVS-L2, **Area** = Security  
8. Add **Query-based suite** “Open Security Bugs” → query `Tags Contains 'ASVS-L2' AND State <> 'Closed'`  
9. Pin dashboard widgets: **“Test Results”**, **“Burndown of Security Bugs”**, **“ZAP Alert Summary”**  
10. At release gate, add **“Query Work Items”** gate → count = 0 for `Severity=High AND Tags=ASVS-L2`

---

## 7. Best-Practice Checklist
- Shift-left: developers run **SEC-10-01, SEC-05-01** in PR pipeline (< 5 min).  
- Use **Shared Steps** for login to reduce maintenance.  
- Store attack payloads in **@Parameters** to avoid hard-coding secrets in tests.  
- Version your test cases with the repo – export via **“Test Plan export”** (json) and commit to `/security-test/plans`.  
- Tag flaky security tests **“Unstable”** so they don’t block release; fix in next sprint.  
- Import **ASVS spreadsheet** (CSV) into **Azure Boards** → bulk creates user-stories; then convert to test suites.  
- Enforce **“Security test passed”** policy in branch security → check via **“Status policy”** calling **“Azure DevOps API”**.  
- Keep evidence: attach **ZAP scan**, **testssl report**, **screenshot**, **HTTP archive (.har)** to each test run.  
- Run **bug-bash sessions** → use **“Test & Feedback”** browser extension; exploratory tests are stored as **Test Cases** with tag **“Exploratory”**.  
- Review **ASVS change-log** every quarter; archive obsolete test cases instead of deleting (keeps history).

---

## 8. Training Roll-Out (4-Week Plan)
| Week | Activity | Deliverable |
|------|----------|-------------|
| 1 | Lunch & learn – Azure DevOps basics | Demo creating a test case |
| 2 | Workshop – Map ASVS to WSTG | Spreadsheet mapping |
| 3 | Hack-day – Run 5 cases manually | Completed test runs in Azure |
| 4 | Automate-one – push ZAP into PR | YAML merged to repo |

---

## 9. Quick Reference Links
- **ASVS V5.0** – https://github.com/OWASP/ASVS/raw/master/5.0/OWASP%20Application%20Security%20Verification%20Standard%205.0-en.pdf  
- **WSTG V5.0** – https://owasp.org/www-project-web-security-testing-guide/v5/  
- **Azure DevOps Test Plans docs** – https://docs.microsoft.com/en-us/azure/devops/test/  
- **ZAP Azure Extension** – https://marketplace.visualstudio.com/items?itemName=owaspzap.zap-azure-task  

---
# Azure DevOps Security-Testing Starter Kit
**OWASP WSTG v5.0 × ASVS v5.0 – complete 1-to-1 map, ready-to-import test artefacts, and Azure DevOps how-to**  
_Audience: security testers who understand OWASP but are new to Azure DevOps_

---

## 1. 90-Second Azure DevOps Refresher

| Concept           | Security-testing use                              |
| :---------------- | :------------------------------------------------ |
| **Organisation**  | One per company (contoso)                         |
| **Project**       | One per product line (mobile-bank)                |
| **Work item**     | User Story “Implement ASVS V5.3”                  |
| **Test Plan**     | Security Validation – ASVS L2                     |
| **Test Suite**    | Requirement-based (links to User Story) or Static |
| **Test Case**     | Atomic step that proves one ASVS control          |
| **Configuration** | Browser/OS matrix (Edge-Win11, Safari-iOS)        |
| **Run**           | Manual (Test Runner) or Automated (YAML pipeline) |
| **Bug**           | Severity = High, Tag = ASVS-L2                    |
## 2. Security Master Test Plan (template)

**Name:** `[App] Security Validation – ASVS L2`  
**Area:** `\Security`  
**Iteration:** `Current PI`  
**Owner:** `security-champion@contoso.com`  
**Objective:** Demonstrate that every ASVS L2 control is satisfied with at least one WSTG test, executed in the CI/CD pipeline or during sprint testing.  
**Exit criteria:**
- 100 % test cases executed
- 0 High-severity security bugs open
- Evidence (ZAP scan, screenshots, HAR) attached to each failed run
## 3. Test-Suite Catalogue (same numbering as ASVS chapters)

| Suite ID | Suite Title        | ASVS Chapter        | WSTG Sections Covered |
| :------- | :----------------- | :------------------ | :-------------------- |
| SEC-A    | Authentication     | V2 – Authentication | WSTG-ATHN-xx          |
| SEC-B    | Session Management | V3 – Session        | WSTG-SESS-xx          |
| SEC-C    | Access Control     | V4 – Access Control | WSTG-ATHZ-xx          |
| SEC-D    | Input Validation   | V5 – Validation     | WSTG-INPV-xx          |
| SEC-E    | Cryptography       | V6 – Crypto         | WSTG-CRYP-xx          |
| SEC-F    | Error Handling     | V7 – Errors         | WSTG-ERR-xx           |
| SEC-G    | Business Logic     | V8 – Business       | WSTG-BUSL-xx          |
| SEC-H    | Client-side        | V9 – Client         | WSTG-CLNT-xx          |
| SEC-I    | API & Web-services | V10 – API           | WSTG-APIN-xx          |
| SEC-J    | Configuration      | V14 – Config        | WSTG-CONF-xx          |

> Create each suite as **Requirement-based** and link it to the matching **User Story** “Implement ASVS Vx” so traceability is automatic.

## 4. WSTG ↔ ASVS v5.0 One-Look Matrix

_(Only L2 controls shown; L3 simply add more rows)_

| WSTG ID      | WSTG Title                        | Satisfies ASVS v5.0               | SEC-Suite |
| :----------- | :-------------------------------- | :-------------------------------- | :-------- |
| WSTG-ATHN-01 | Testing for Credentials Transport | V2.1 – TLS for auth               | SEC-A     |
| WSTG-ATHN-02 | Default Credentials               | V2.2 – Default pass               | SEC-A     |
| WSTG-ATHN-07 | Weak Password Policy              | V2.2 – Password strength          | SEC-A     |
| WSTG-SESS-02 | Cookie Attributes                 | V3.1 – Secure, HttpOnly, SameSite | SEC-B     |
| WSTG-SESS-03 | Session Fixation                  | V3.2 – regenerate ID              | SEC-B     |
| WSTG-ATHZ-01 | Directory Traversal               | V4.1 – Path control               | SEC-C     |
| WSTG-ATHZ-04 | IDOR                              | V4.2 – Authorise per object       | SEC-C     |
| WSTG-INPV-01 | Reflected XSS                     | V5.4 – Output encode              | SEC-D     |
| WSTG-INPV-02 | Stored XSS                        | V5.4 – Output encode              | SEC-D     |
| WSTG-INPV-05 | SQL Injection                     | V5.3 – Parametrised Q             | SEC-D     |
| WSTG-CRYP-01 | Weak SSL/TLS                      | V6.2 – Strong cipher              | SEC-E     |
| WSTG-ERR-01  | Info Leakage                      | V7.1 – Generic error              | SEC-F     |
| WSTG-BUSL-01 | Business Logic Bypass             | V8.2 – Logic limits               | SEC-G     |
| WSTG-CLNT-01 | DOM-based XSS                     | V9.1 – DOM escape                 | SEC-H     |
| WSTG-CLNT-09 | Clickjacking                      | V9.4 – X-Frame-Options            | SEC-H     |
| WSTG-APIN-03 | JWT Security                      | V10.2 – Alg=none check            | SEC-I     |
| WSTG-CONF-02 | Robots.txt Info                   | V14.4 – Metadata leak             | SEC-J     |
| WSTG-CONF-08 | Security Headers                  | V14.4 – HSTS, CSP, X-Content-Type | SEC-J     |

---

## 5. Detailed Test-Case Library (copy-paste ready)

Use **Grid view** in Azure Test Plans; paste directly.
### 5.1 Authentication Suite (SEC-A)
**Test Case ID:** SEC-A-01  
**Title:** Credentials must be sent over TLS  
**Description:**

1. Open F12
2. Browse to login page
3. Enter creds and submit
4. Inspect Network tab – protocol column  
    **ASVS:** V2.1  
    **WSTG:** WSTG-ATHN-01  
    **Expected:** All auth endpoints use HTTPS (no http://).  
    **Automate:** Add `testssl.sh` step in pipeline – fail if TLS < 1.2.

**Test Case ID:** SEC-A-02  
**Title:** No default credentials  
**Description:**

1. Attempt login admin/admin, admin/password, root/root  
    **ASVS:** V2.2  
    **WSTG:** WSTG-ATHN-02  
    **Expected:** 401 and account-lockout after 5 attempts.

### 5.2 Session Suite (SEC-B)

**Test Case ID:** SEC-B-01  
**Title:** Cookie flags Secure & HttpOnly & SameSite  
**ASVS:** V3.1  
**WSTG:** WSTG-SESS-02  
**Expected:** `Set-Cookie: JSESSIONID=xxx; Secure; HttpOnly; SameSite=Strict`.

**Test Case ID:** SEC-B-02  
**Title:** Session fixation prevented  
**Steps:**

1. Grab cookie from un-auth page
2. Login
3. Compare pre- and post-login cookie value  
    **Expected:** Different value; old cookie no longer accepted.

### 5.3 Access-Control Suite (SEC-C)
**Test Case ID:** SEC-C-01  
**Title:** IDOR – horizontal escalation  
**Steps:**

1. Login as alice
2. GET `/account/1234` (alice’s)
3. Change to `/account/5678` (bob’s)  
    **ASVS:** V4.2  
    **WSTG:** WSTG-ATHZ-04  
    **Expected:** 403 Forbidden.

### 5.4 Input-Validation Suite (SEC-D) – most critical

**Test Case ID:** SEC-D-01  
**Title:** SQL Injection blocked  
**Payload:** `' OR 1=1--`  
**ASVS:** V5.3  
**WSTG:** WSTG-INPV-05  
**Expected:** 401, no SQL error in response.

**Test Case ID:** SEC-D-02  
**Title:** Reflected XSS neutralised  
**Payload:** `<script>alert(document.cookie)</script>`  
**ASVS:** V5.4  
**WSTG:** WSTG-INPV-01

# Azure Devops Security Test Plan Template
 **ready-to-use Test Plan template** you can adapt inside Azure DevOps. I’ll structure it the way it would look in the **Test Plans hub** (Test Plan → Test Suites → Test Cases). Each test case will map to **OWASP ASVS v5.0** and **WSTG v5.0** controls, so your team can directly plug it into projects.

##  Workflow for creating Security test-cases using OWASP

1. **Obtain the full list** of controls for ASVS v5.0 (they publish a CSV or repository) [GitHub+2OWASP Foundation+2](https://github.com/OWASP/ASVS?utm_source=chatgpt.com)
2. **Map each control** to one or more test cases (manual, automated, or hybrid).
3. **Filter / tailor** by your application domain: not all controls are applicable (e.g. some API, file upload, or GraphQL-specific).
4. **Import into Azure DevOps** (or test tool) by using the CSV / Excel import mechanism (if supported) or via Azure DevOps REST API.
5. **Maintain and evolve**: as your app changes, add / update test cases, and retire irrelevant ones.

# 🔐 Azure DevOps Security Test Plan Template (OWASP ASVS + WSTG)

---
## 1. **Test Plan**
**Name:** `Release 2.0 – Security Test Plan (OWASP ASVS & WSTG Coverage)`  
**Objective:** Validate application security against OWASP ASVS v5.0 and OWASP WSTG v5.0 frameworks.  
**Scope:** Authentication, session management, access control, input validation, and critical business logic.  
**Linked Work Items:** Security-related Epics, Features, and User Stories.

---
## 2. **Test Suites (Organized by OWASP Category)**
### A. **ASVS-Based Suites**
1. `ASVS-V2 Authentication`
2. `ASVS-V3 Session Management`
3. `ASVS-V4 Access Control`
4. `ASVS-V5 Validation, Sanitization & Encoding`
5. `ASVS-V6 Stored Cryptography`
6. `ASVS-V7 Error Handling & Logging`

### B. **WSTG-Based Suites**

1. `WSTG-INFO Information Gathering`
2. `WSTG-AUTH Authentication Testing`
3. `WSTG-SESS Session Management Testing`
4. `WSTG-INPV Input Validation Testing`
5. `WSTG-BUSL Business Logic Testing`
6. `WSTG-CRYP Cryptography Testing`

---
## 3. **Sample Test Cases**

### Suite: `ASVS-V2 Authentication`

**Test Case ID:** `ASVS-V2.1`  
**Title:** Password Policy Enforcement  
**Steps:**

1. Attempt registration with a 6-character password.
2. Attempt registration with a 12-character password (with upper/lower/digit/symbol).  
    **Expected Result:** Weak password rejected, strong password accepted.  
    **Mapped Control:** ASVS V2.1

---

### Suite: `ASVS-V4 Access Control`

**Test Case ID:** `ASVS-V4.2`  
**Title:** Enforce Role-Based Access Control  
**Steps:**
1. Login as a normal user.
2. Attempt to access admin dashboard URL directly.  
    **Expected Result:** Access denied; user redirected or error returned.  
    **Mapped Control:** ASVS V4.2

---

### Suite: `WSTG-INPV Input Validation`

**Test Case ID:** `WSTG-INPV-05`  
**Title:** SQL Injection in Login Form  
**Steps:**
1. Enter `admin' OR '1'='1` as username and any password.
2. Observe system behavior.  
    **Expected Result:** Application rejects input gracefully, no SQL error exposed.  
    **Mapped Control:** WSTG-INPV-05

---

### Suite: `WSTG-SESS Session Management`

**Test Case ID:** `WSTG-SESS-06`  
**Title:** Session Expiry After Inactivity  
**Steps:**
1. Login as a user.
2. Remain idle for 20 minutes.
3. Attempt to perform an action.  
    **Expected Result:** User is logged out; session token invalid.  
    **Mapped Control:** WSTG-SESS-06

---

### Suite: `WSTG-CRYP Cryptography`

**Test Case ID:** `WSTG-CRYP-01`  
**Title:** Verify Transport Layer Security (TLS)  
**Steps:**

1. Attempt to connect over HTTP.
2. Attempt to connect over HTTPS.  
    **Expected Result:** HTTP redirected to HTTPS; strong ciphers enforced (TLS 1.2+).  
    **Mapped Control:** WSTG-CRYP-01

---

## 4. **Automation Integration**

- **Static Analysis (SAST):** SonarQube, Checkmarx → map findings to ASVS categories.
- **Dynamic Analysis (DAST):** OWASP ZAP → automated pipeline run → mapped to WSTG test cases.
- **Dependency Scanning:** OWASP Dependency-Check → linked to `ASVS-V6 Stored Cryptography`.
- Secret Scanning:
👉 Automation results update Azure Test Cases automatically (via pipeline tasks + Azure DevOps REST API).

---

## 5. **Metrics & Dashboards**

- **Coverage:** % of OWASP ASVS/WSTG controls with test cases.
- **Execution Rate:** # of security test cases executed per sprint/release.
- **Pass/Fail Ratio:** Distribution of test outcomes.
- **Security Defect Density:** Vulnerabilities per 1,000 lines of code.
- **Mean Time to Remediate (MTTR):** Avg. time from bug discovery → closure.

Azure DevOps → **Dashboards** or **Power BI** integration can visualize this.

---

✅ With this template, you’ll have:

- A **traceable security testing structure** in Test Plans.
- **Manual + automated cases** mapped to OWASP standards.
- A **repeatable framework** for every release.

