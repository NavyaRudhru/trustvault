# TrustVault

**Security-first document management with fine-grained access control and tamper-evident auditing.**

TrustVault is a document-sharing platform designed to protect files through authentication, document-level permissions, server-side authorization, upload validation, and audit logging.

## Features

- User registration and authentication.
- Role-based administrator access.
- Document ownership and per-document read/edit permissions.
- Granting and revoking document access.
- Document upload, organization, and search capabilities.
- Upload validation, allowed file types, and file-size restrictions.
- Audit logging for security-sensitive actions and denied operations.
- Hash-chain audit integrity verification and signed audit checkpoints.
- Administrator endpoints for reviewing audit events and document permissions.
- Automated tests for authentication, authorization, and document isolation.

## Technology Stack

- Python
- FastAPI
- SQLAlchemy
- SQLite for local development
- Argon2 password hashing
- Signed bearer tokens
- Pytest

Check `requirements.txt` for the exact dependency versions.

## User Roles and Access Model

| Role or relationship | Description |
|---|---|
| Administrator | Can access administrator-only audit and permission review endpoints. |
| Document owner | The user who owns a document and can manage its sharing permissions, subject to server-side authorization. |
| Viewer | The default role assigned through public registration. Access to shared documents depends on the permissions granted. |
| Authorized editor | A user with edit permission for a particular document. Edit access also requires read access. |

Document ownership and sharing permissions are checked on the server. Hiding a button in the user interface is not a substitute for authorization.

Public registration assigns the viewer role. Administrator accounts must be provisioned securely; public registration must not allow users to promote themselves to administrator.

## Requirements

- Python installed.
- Git installed.
- A terminal such as PowerShell.
- A local copy of this repository.

## Installation and Local Setup

Open PowerShell in the project directory.

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt or configure your local PowerShell execution policy appropriately.

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure environment variables

Review `.env.example` before configuring the application.

Configure the secrets and database settings required by your local application. In particular, use a strong, private `SESSION_SECRET` and configure `AUDIT_CHECKPOINT_SECRET` with at least 32 characters of secret material when using audit checkpoints.

Do not commit real secrets, production credentials, or private environment files to GitHub. Use separate secrets for development and production.

The application uses SQLite by default for local development. Confirm the database configuration in `app/database.py` before changing it.

### 4. Start the application

```powershell
python -m uvicorn app.main:app --reload
```

The local server normally starts at:

http://127.0.0.1:8000

Interactive API documentation:

http://127.0.0.1:8000/docs

OpenAPI schema:

http://127.0.0.1:8000/openapi.json

Do not expose the development server directly to the public internet.

## Important API Endpoints

The following endpoints are defined in the application:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Root endpoint |
| GET | `/health` | Health check |
| POST | `/auth/register` | Register a viewer account |
| POST | `/auth/login` | Authenticate a user |
| GET | `/me` | Get the authenticated user's information |
| GET | `/admin/audit` | List audit events; administrator access required |
| GET | `/admin/permissions` | Review document permissions; administrator access required |
| GET | `/admin/audit/verify` | Verify audit-chain integrity; administrator access required |

Document-management and permission-management routes are also provided by the application. Use `/docs` to inspect the exact paths, request formats, and response schemas exposed by the running version.

### Authentication and authorization

- Authenticate through the login endpoint and use the returned authentication token as required by the API.
- Protected endpoints must verify the authenticated user on the server.
- Document access must be checked for every applicable read, download, edit, and delete request.
- Owners can grant or revoke document permissions according to the application's authorization rules.
- Denied access attempts should be audited.
- Never assume that knowing a document ID grants access to that document.

## File Upload Security

The application validates uploaded files before accepting them.

The current implementation is intended to restrict uploads to PDF, TXT, PNG, JPG, and JPEG files, with a maximum file size of 10 MB. It also uses UUID-based stored filenames and basic file-signature checks.

File extensions and signatures alone cannot guarantee that a file is safe. Production deployments should add appropriate malware scanning, resource limits, and isolated storage.

## Audit Logging and Integrity

TrustVault uses audit events to record security-relevant operations.

The audit system includes hash-chain verification and signed checkpoints intended to help detect unauthorized modification of audit history.

Audit integrity checks do not independently guarantee that every event was recorded, that a compromised application cannot forge events, or that checkpoint secrets remain secure. Production deployments need protected secret storage, restricted database access, and independent audit backups.

## Run the Tests

From the project root, with the virtual environment activated:

```powershell
python -m pytest -q
```

The project has previously passed a local test run with 80 tests. Run the tests against your current checkout to confirm its present status.

Tests are important, but passing tests alone does not establish that the application is production-ready or that every possible authorization bypass has been eliminated.

## Project Structure

```text
trustvault/
├── app/
│   ├── main.py
│   ├── admin.py
│   ├── documents.py
│   └── permissions.py
├── audit_checkpoints/
├── scripts/
├── storage/
├── tests/
├── .env.example
├── .gitignore
├── requirements.txt
├── README.md
├── THREATS.md
└── PROMPTS.md
```

The repository may contain additional application modules and tests not listed above.

## Security Notes

- Never commit `.env` files, passwords, tokens, or production secrets.
- Do not use real personal documents for public demonstrations.
- Configure secure secrets before deployment.
- Use HTTPS and secure hosting for any public instance.
- Restrict access to uploaded files, the database, and audit checkpoints.
- Test denied requests as well as successful requests.
- Review `THREATS.md` for the threat model and known limitations.

## Deployment and Demo Status

This README documents local development and the application's intended security model. A public production URL, seeded demonstration accounts, and production deployment instructions must be added only after they have actually been configured and verified.

Do not publish administrator passwords or reuse development secrets in a public demo.

## License

Add the project's chosen license before distributing the software under an open-source license.
