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
| Suite ID | Suite Title | ASVS Chapter | Typical WSTG Chapters |
|----------|-------------|--------------|-----------------------|
| SEC-01 | Authentication | V2 | WSTG-ATHN-xx |
| SEC-02 | Session Management | V3 | WSTG-SESS-xx |
| SEC-03 | Access Control | V4 | WSTG-ATHZ-xx |
| SEC-04 | Validation & Injection | V5 | WSTG-INPV-xx |
| SEC-05 | Cryptography | V6 | WSTG-CRYP-xx |
| SEC-06 | Error Handling | V7 | WSTG-ERR-xx |
| SEC-07 | Business Logic | V8 | WSTG-BUSL-xx |
| SEC-08 | Client-side | V9 | WSTG-CLNT-xx |
| SEC-09 | API / Web-service | V10 | WSTG-APIN-xx |
| SEC-10 | Configuration | V14 | WSTG-CONF-xx |

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

