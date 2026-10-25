# TrustVault — Threat Model

## 1. Purpose

TrustVault is a document-sharing application designed to let authenticated users upload, organize, access, and share documents with specific users. This threat model describes the assets, trust boundaries, potential attacks, and security controls relevant to the application.

This document describes intended protections. A control should be considered verified only after its implementation and relevant tests have been inspected.

## 2. Assets to Protect

- Document contents and downloaded files.
- User credentials, authentication tokens, and account information.
- Document ownership and sharing permissions.
- Access requests and approval decisions.
- Audit records, including denied access attempts.
- Database integrity and document metadata.
- Application secrets and deployment configuration.

## 3. Trust Boundaries

1. **Unauthenticated user → application:** A user must authenticate before accessing protected resources.
2. **Authenticated user → document:** Being logged in must not automatically grant access to every document.
3. **Viewer → editor operations:** Read access must not imply permission to modify, share, or delete a document.
4. **Document owner → shared user:** Access must be restricted to the permissions granted for the particular document.
5. **Application → database and file storage:** Database queries and storage operations must enforce the same document-level authorization decisions.
6. **Application → audit records:** Users must not be able to rewrite or delete audit history through ordinary application endpoints.

## 4. Threats and Mitigations

### T1. Cross-user document access (IDOR/BOLA)

**Threat:** A user changes a document ID in a URL or request body to access another user's private document.

**Impact:** Confidential documents may be exposed, modified, or deleted.

**Mitigation:** Authenticate the caller and check document ownership or an explicit document-level grant on every protected operation. Do not rely on hiding document IDs in the interface.

**Verification needed:** Automated tests using two separate users must attempt to list, read, download, edit, share, and delete each other's documents without permission.

### T2. Privilege escalation

**Threat:** A viewer or ordinary user submits an edit, delete, permission-grant, or administrative request directly to the API.

**Impact:** Unauthorized modification, deletion, or disclosure of documents.

**Mitigation:** Enforce role and resource-level permissions on the server for every operation. Frontend visibility and disabled buttons are not security controls.

**Verification needed:** Test each restricted endpoint with a low-privilege account, including requests made outside the browser interface.

### T3. Revoked access remains usable

**Threat:** A user continues accessing a document after the owner revokes their grant.

**Impact:** Continued unauthorized access.

**Mitigation:** Recheck current permissions on every document operation. Avoid relying on stale frontend state or indefinitely cached authorization decisions.

**Verification needed:** Grant access, confirm the permitted operation, revoke access, then retry reading, downloading, editing, and deleting.

### T4. Insecure access-request approval

**Threat:** A requester approves their own request, approves a request belonging to another document, or reviews a request without the required authority.

**Impact:** Unauthorized permissions may be granted.

**Mitigation:** Validate the request's document, requester, status, and reviewing user's authority on the server. Approval should grant only the requested and permitted access level.

**Verification needed:** Test self-approval, review by an unrelated user, duplicate approval, rejected requests, and attempts to change a reviewed request.

### T5. Authentication and session compromise

**Threat:** Weak credentials, leaked tokens, or improperly handled sessions allow an attacker to impersonate a user.

**Impact:** Account takeover and unauthorized document access.

**Mitigation:** Use appropriate password hashing, secure token handling, secret management, and HTTPS in deployment. Do not commit credentials or production secrets.

**Verification needed:** Inspect authentication code and configuration; test invalid credentials, expired or invalid tokens where supported, and access after logout.

### T6. Unauthorized uploads and malicious files

**Threat:** An attacker uploads oversized, unexpected, or malicious files, or uses filenames to attempt path traversal.

**Impact:** Resource exhaustion, unsafe file handling, or unauthorized file access.

**Mitigation:** Validate file size and type, generate safe server-side storage names, prevent user-controlled paths from escaping the storage directory, and apply suitable storage isolation.

**Verification needed:** Inspect upload validation and storage code and test oversized files, unusual filenames, and unauthorized downloads.

### T7. Audit trail tampering or incomplete records

**Threat:** Users alter audit records, or important events—including denied access attempts—are not recorded.

**Impact:** Investigations become unreliable, and suspicious activity may go undetected.

**Mitigation:** Restrict audit-write operations to trusted server code, record relevant successful and denied actions, and protect audit records against unauthorized modification. If hash chaining or signed checkpoints are used, verify the integrity checks and signing-key protection.

**Limitation:** A hash chain alone does not prevent an attacker who controls the database and signing key from rewriting history. Independent protection of keys and copies of audit evidence may be required.

**Verification needed:** Test event coverage, denied-action logging, integrity verification, and attempts to modify audit records.

### T8. Permission-check bypass through alternate endpoints

**Threat:** A protected document is inaccessible through one endpoint but can be retrieved through search, metadata, download, sharing, or another API route.

**Impact:** Confidentiality or integrity failure despite apparently correct primary access checks.

**Mitigation:** Centralize or consistently apply authorization checks across all document-related endpoints. Avoid returning sensitive document metadata to unauthorized users.

**Verification needed:** Run negative authorization tests against every endpoint that returns or changes document-related information.

### T9. Injection and unsafe input handling

**Threat:** Malicious input in search terms, metadata, filenames, or request bodies causes injection or unsafe processing.

**Impact:** Data disclosure, data corruption, or application errors.

**Mitigation:** Use parameterized database operations, validate input types and lengths, and safely render user-provided content in the frontend.

**Verification needed:** Inspect database access and frontend rendering code; test malformed and unexpected input.

### T10. Deployment and configuration exposure

**Threat:** Debug endpoints, secrets, development databases, permissive CORS settings, or insecure storage are exposed in production.

**Impact:** Account compromise, data loss, or disclosure of private documents.

**Mitigation:** Keep secrets in deployment environment variables, disable unnecessary debug access, configure HTTPS and CORS appropriately, and use persistent, access-controlled storage and backups.

**Verification needed:** Inspect the live deployment configuration and verify that the database and uploaded files persist across restarts.

## 5. Security Test Plan

The following tests should be run before claiming the application is secure:

- User A cannot read or download User B's private documents.
- User A cannot edit or delete User B's documents without explicit permission.
- A viewer cannot perform editor-only operations.
- Revoking a grant immediately removes the affected access.
- Users cannot grant themselves access through access-request endpoints.
- Users cannot approve or reject requests outside their authority.
- Search and metadata endpoints do not disclose inaccessible documents.
- Failed authorization attempts are recorded in the audit trail where required.
- Audit integrity verification detects unauthorized changes within its stated threat model.
- Invalid or unauthenticated requests cannot access protected endpoints.

Record actual test results separately. Do not describe a test as passing until it has been executed.

## 6. Known Limitations and Residual Risks

The presence of an authorization function or audit mechanism does not prove that every endpoint uses it correctly. Security depends on complete endpoint coverage, correct database scoping, safe file storage, and deployment configuration.

This document is a threat model, not an independent security audit. Any untested mitigation, deployment control, or automated test must remain explicitly unverified.

## 7. Review

Update this file when new endpoints, roles, storage mechanisms, or permission workflows are introduced. Revisit the threat model after security tests reveal new attack paths.
