# TrustVault — Secure Document Sharing Platform

TrustVault is a security-focused document-sharing platform built with FastAPI and PostgreSQL. It enables users to upload and manage documents, control document-level access permissions, and track important activities through audit logs.

## Key Features

- **Authentication:** Secure user authentication.
- **Role-Based Access Control:** Supports Admin, Owner, and Viewer roles.
- **Document Management:** Upload, organize, search, and manage documents.
- **Granular Permissions:** Grant or revoke document access for specific users.
- **Read and Edit Access:** Control what authorized users can do with shared documents.
- **Access Enforcement:** Prevent unauthorized users from accessing documents or performing restricted actions.
- **Audit Logging:** Record important activities, including document uploads, downloads, changes, deletions, permission changes, and denied access attempts.
- **Document Access Requests:** Support a workflow for requesting access to documents.
- **API Documentation:** Explore and test API endpoints using FastAPI's Swagger UI.
- **Cloud Deployment:** Deployed using Render with a PostgreSQL database.

## Technology Stack

| Component         | Technology                 |
| ----------------- | -------------------------- |
| Backend           | Python, FastAPI            |
| Database          | PostgreSQL                 |
| ORM               | SQLAlchemy                 |
| Authentication    | Token-based authentication |
| Password Security | Argon2 password hashing    |
| API Documentation | Swagger UI / OpenAPI       |
| Deployment        | Render                     |
| Version Control   | Git and GitHub             |

## Architecture Overview

1. The client sends requests to the FastAPI application.
2. The application authenticates the user and checks their permissions.
3. SQLAlchemy communicates with PostgreSQL to manage application data.
4. Document operations are restricted according to user roles and document-level permissions.
5. Audit logs record relevant security and document activities.

## Getting Started

### Prerequisites

- Python 3.10 or a compatible supported version
- PostgreSQL
- Git

### 1. Clone the repository

```bash
git clone https://github.com/NavyaRudhru/trustvault.git
cd trustvault
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Configure the required environment variables in your local environment:

- `DATABASE_URL` — PostgreSQL connection URL
- `SESSION_SECRET` — Secret used for session/token security
- `AUDIT_CHECKPOINT_SECRET` — Secret used for audit checkpoint operations
- `APP_ENV` — Set to `production` for production deployment

Use strong, unique secrets. Never commit credentials, database URLs, or secret keys to GitHub.

### 5. Run the application

```bash
uvicorn app.main:app --reload
```

Open the local API documentation:

`http://127.0.0.1:8000/docs`

## Demo Accounts

The application supports different roles for testing access control.

- **Owner:** Manages documents and grants or revokes document permissions.
- **Viewer:** Accesses documents according to the permissions granted to them.
- **Admin:** Performs administrative actions allowed by the application's role policies.

Create demo accounts through the registration endpoint or the project's authorized account-provisioning procedure. Public registration creates Viewer accounts.

**Security note:** Do not publish demo passwords or production credentials in this repository.

## Security Considerations

- Enforce authorization checks on every protected document operation.
- Do not rely only on frontend restrictions; validate permissions on the backend.
- Store passwords as secure hashes rather than plaintext.
- Keep secrets and database credentials outside source control.
- Record security-sensitive actions in audit logs.
- Test both authorized and unauthorized access scenarios.
- Review database backups, audit-log integrity, and persistent storage before production use.

## Deployment

TrustVault is deployed on Render.

- **Live Application:** [https://trustvault-n4za.onrender.com](https://trustvault-n4za.onrender.com)
- **API Documentation:** [https://trustvault-n4za.onrender.com/docs](https://trustvault-n4za.onrender.com/docs)
- **Health Endpoint:** [https://trustvault-n4za.onrender.com/health](https://trustvault-n4za.onrender.com/health)

The deployed application uses a PostgreSQL database configured through the `DATABASE_URL` environment variable.

## Testing and Validation

TrustVault was tested to validate its core functionality, access control, and security behavior.

### 1. Authentication Testing
- Verified user registration and login.
- Confirmed that public registration creates Viewer accounts.
- Tested access to protected endpoints without valid authentication.

### 2. Document Management Testing
- Tested document upload and listing.
- Verified document access based on assigned permissions.
- Tested document management operations for authorized users.

### 3. Access Control Testing
- Verified document access for users with granted permissions.
- Tested access denial for users without permission.
- Checked permission granting and revocation.
- Verified that Viewer accounts cannot perform unauthorized owner-level operations.

### 4. Audit Logging Testing
- Checked audit records for document-related activities.
- Tested logging of permission changes and denied access attempts.
- Verified that relevant events are recorded for security review.

### 5. Document Access Request Testing
- Tested the document access request workflow.
- Verified that requests follow the application's configured authorization rules.

### 6. Deployment Testing
- Verified that the application is accessible on Render.
- Checked the API documentation through Swagger UI.
- Confirmed database connectivity in the deployed environment.

### Testing Outcome

The main application workflows were tested in the deployed environment. Security-related tests should be repeated after significant code changes to ensure that authorization and document access restrictions continue to work correctly.

## Demo Accounts

Use the following demo accounts to explore TrustVault's role-based access control and document-sharing functionality.

Demo Accounts

- Owner: 
username:`demo_owner`
password:owner@123456
 — Upload documents and manage document permissions.

- Viewer 1: 
username:`demo_viewer1` 
password:ViewerDemo1@2026Pass
— Test access to documents shared with an authorized viewer.

- Viewer 2: 
username:`demo_viewer2`
password:ViewerDemo2@2026Pass
 — Test access restrictions for a viewer without permission.

### How to Test

1. Sign in using an authorized demo account.
2. Upload a sample document using the Owner account.
3. Grant read access to `demo_viewer1`.
4. Sign in as `demo_viewer1` and verify access to the shared document.
5. Sign in as `demo_viewer2` and verify that access is denied when no permission has been granted.
6. Revoke an existing permission and verify that subsequent access is denied.

**Security note:** These are demonstration accounts, not production accounts. Never use real personal documents or reuse personal passwords during testing.

## Project Objective

The objective of TrustVault is to demonstrate secure document sharing through authentication, role-based authorization, fine-grained access control, and activity auditing.

GitHub: [https://github.com/NavyaRudhru](https://github.com/NavyaRudhru)

---

*TrustVault — Share documents securely. Control access precisely. Track activity transparently.*
