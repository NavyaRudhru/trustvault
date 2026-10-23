# TrustVault Threat Model

## 1. Purpose

TrustVault is a security-focused document-sharing application. This document identifies important security threats, existing protections, and remaining risks.

The threat model should be updated whenever authentication, authorization, file storage, or audit functionality changes.

## 2. Assets to Protect

- User accounts and password hashes.
- Authentication tokens and application secrets.
- Uploaded documents and their contents.
- Document ownership and access permissions.
- Audit events and audit checkpoints.
- Database records and application configuration.
- Administrator capabilities.

## 3. Trust Boundaries

1. **Unauthenticated users:** Must not access protected account or document operations.
2. **Authenticated users:** Must only access resources permitted by their role and document permissions.
3. **Document owners:** May manage sharing permissions for documents they own, subject to server-side checks.
4. **Administrators:** May access administrator-only audit and permission review endpoints.
5. **Application and storage:** The server must enforce access rules independently of the user interface.
6. **External environment:** Uploaded files, client requests, environment variables, and database files must not automatically be trusted.

## 4. Threats and Mitigations

### Threat 1: Unauthorized account access

**Risk:** An attacker guesses, steals, or obtains a user's password or authentication token.

**Existing protections:**
- Password hashing using Argon2.
- Minimum password length enforced by the application.
- Authentication tokens used for protected operations.
- Login rate limiting and audit events for relevant login outcomes.

**Remaining risks and actions:**
- Use HTTPS in deployed environments.
- Store secrets outside source control.
- Review token expiration, invalidation, and signing-key rotation.
- Test brute-force resistance and account lifecycle behavior.

### Threat 2: Privilege escalation

**Risk:** A viewer registers as an administrator or accesses administrator-only functionality.

**Existing protections:**
- Public registration assigns the viewer role.
- Administrator endpoints check the authenticated user's role and active status.

**Remaining risks and actions:**
- Verify how the first administrator is provisioned.
- Test attempts to change roles through registration, profile updates, and direct API requests.
- Ensure administrative privileges cannot be granted through client-controlled fields.

### Threat 3: Unauthorized document access

**Risk:** A user guesses or obtains a document ID and reads or downloads a document without permission.

**Existing protections:**
- Document-level authorization helpers.
- Ownership and sharing permission checks.
- Denied access audit events in relevant authorization paths.

**Remaining risks and actions:**
- Test every document read, download, update, and delete route.
- Test direct requests using another user's document IDs.
- Verify that file contents and storage paths cannot be retrieved through alternate routes.
- Ensure failed authorization cannot be bypassed through search, previews, or metadata endpoints.

### Threat 4: Unauthorized permission changes

**Risk:** A viewer or unrelated user grants access to a document, changes another user's permissions, or revokes a legitimate user's access.

**Existing protections:**
- Permission-management operations check document ownership.
- Permission grants validate the target account and requested access.
- Permission grant and revoke operations generate audit events in the relevant code paths.

**Remaining risks and actions:**
- Test unauthorized grants and revocations.
- Verify that edit access always includes read access.
- Verify that revoked access stops working on the next protected request.
- Test simultaneous permission changes and document operations.

### Threat 5: Malicious or invalid uploads

**Risk:** An attacker uploads an oversized, malformed, or dangerous file.

**Existing protections:**
- File extension allowlist.
- Maximum upload size of 10 MB in the current implementation.
- Basic file-signature validation.
- UUID-based stored filenames.

**Remaining risks and actions:**
- File signatures and extensions do not prove a file is harmless.
- Consider malware scanning and stricter content validation.
- Prevent path traversal and executable-file exposure.
- Apply upload limits at the application and hosting layers.
- Test malformed files, mismatched extensions, and oversized uploads.

### Threat 6: Audit log tampering

**Risk:** An attacker modifies or removes audit records to hide unauthorized activity.

**Existing protections:**
- Hash-chain audit integrity verification.
- Signed audit checkpoints.
- A verification endpoint restricted to administrators.

**Remaining risks and actions:**
- Protect checkpoint signing secrets.
- Restrict database and checkpoint-file access.
- Keep protected, independent backups of audit records.
- Test modified records, deleted records, invalid checkpoints, and rollback scenarios.
- A hash chain does not by itself prevent a sufficiently privileged attacker from rewriting the database and recomputing hashes.
- Verify that security-sensitive operations fail safely if required audit persistence fails.

### Threat 7: Sensitive information leakage

**Risk:** API responses, logs, error messages, or public repository files expose passwords, tokens, file contents, or secrets.

**Existing protections:**
- Password hashing.
- Administrator permission listings are intended to expose permission metadata rather than file contents.
- Git ignore rules are intended to exclude private environment files, databases, and uploaded files.

**Remaining risks and actions:**
- Never return password hashes or authentication secrets in API responses.
- Avoid logging tokens, passwords, and document contents.
- Check repository history for accidentally committed secrets.
- Restrict audit-log access and review the information returned by administrator endpoints.

### Threat 8: Database or storage compromise

**Risk:** An attacker obtains direct access to the database, uploaded files, or audit checkpoint files.

**Existing protections:**
- UUID-based stored filenames.
- Application-level authorization for protected operations.

**Remaining risks and actions:**
- Application authorization does not protect files from an attacker who already has direct filesystem access.
- Apply least-privilege filesystem and database permissions.
- Protect backups and production storage.
- Use appropriate encryption and recovery procedures for sensitive deployments.

### Threat 9: Denial of service

**Risk:** Repeated login attempts, large uploads, expensive searches, or excessive requests consume application resources.

**Existing protections:**
- Login rate limiting.
- Upload size restrictions.
- Bounded pagination on the documented administrator list endpoints.

**Remaining risks and actions:**
- Apply request limits to other expensive endpoints.
- Configure server-level timeouts and resource limits.
- Consider reverse-proxy rate limiting and monitoring.
- Test behavior under repeated requests and concurrent uploads.

## 5. Security Testing Strategy

The project should test both allowed and denied operations.

Important test cases include:

- Unauthenticated requests to protected endpoints are rejected.
- A viewer cannot access an unshared document.
- One user cannot read, download, edit, or delete another user's private document.
- A non-owner cannot grant or revoke document permissions.
- Revoked permissions stop allowing access.
- Inactive accounts cannot access protected functionality.
- Non-admin users cannot access administrator endpoints.
- Invalid and oversized uploads are rejected.
- Denied security-sensitive operations are audited.
- Audit-chain verification detects altered audit records.
- Invalid or outdated checkpoints are rejected where required.
- Tests fail when an authorization check is deliberately weakened.

Run the automated test suite with:

```powershell
python -m pytest -q
```

Passing tests provide evidence for the tested cases only; they do not prove the absence of all vulnerabilities.

## 6. Security Assumptions

- The application host and Python runtime are trusted.
- Application secrets are configured securely.
- The database and file storage are not publicly exposed.
- Administrators are authorized and protect their credentials.
- Production traffic uses an appropriately secured network connection.

If these assumptions fail, application-level checks may not be sufficient.

## 7. Known Limitations

- SQLite is suitable for local development but may not be the preferred database for a multi-user production deployment.
- Basic file-signature validation is not a substitute for malware scanning.
- Hash-chain verification and signed checkpoints provide tamper-evidence, not absolute protection against a compromised host or stolen signing secret.
- Production deployment, backup recovery, monitoring, and operational security must be independently configured and verified.
- Features and mitigations listed as existing protections must be checked against the current code and tests before making a security assurance.

## 8. Responsible Security Review

Security testing should be performed only against systems and data that the tester is authorized to access. Use test accounts and non-sensitive sample documents during demonstrations.
