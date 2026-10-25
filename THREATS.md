# TrustVault — Threat Model and Security Testing

## 1. Overview

TrustVault is a secure document-sharing application built with FastAPI and PostgreSQL. It uses authentication, role-based access control, document-level permissions, and audit logging to protect sensitive documents.

This document identifies potential threats, their impact, security controls, and tests used to evaluate the application's behavior.

## 2. Assets to Protect

- User credentials and account information
- Uploaded documents and document metadata
- Document permissions and access requests
- Authentication tokens and application secrets
- Audit logs and security-related records
- Database contents and application configuration

## 3. Threat Actors

- Unauthenticated users attempting to access protected resources
- Authenticated viewers attempting unauthorized operations
- Users attempting to access documents belonging to other users
- Malicious users attempting to bypass API authorization
- Attackers attempting to manipulate requests or exploit application errors

## 4. Threat Analysis

### T1. Unauthorized Document Access

**Threat:** A user attempts to read or download a document without permission.

**Impact:** Confidential documents may be exposed.

**Mitigation:** Enforce server-side authentication and document-level authorization on every relevant endpoint.

**Validation test:** Log in as a viewer without permission and attempt to access the document through the API directly.

**Expected result:** Access is denied and the document contents are not disclosed.

### T2. Unauthorized Document Modification or Deletion

**Threat:** A viewer attempts to edit or delete a document they do not own or manage.

**Impact:** Documents may be altered or destroyed.

**Mitigation:** Verify ownership and required permissions before modifying or deleting documents.

**Validation test:** Send direct API requests to edit and delete a protected document using an account without the required permission.

**Expected result:** The operation is denied and the document remains unchanged.

### T3. Permission Escalation

**Threat:** A viewer attempts to grant themselves additional permissions or perform owner-only actions.

**Impact:** Unauthorized access to documents or management functions.

**Mitigation:** Enforce role and permission checks on the backend. Never trust role values supplied by clients.

**Validation test:** Attempt owner-only operations as a viewer and try to modify role or permission fields in requests.

