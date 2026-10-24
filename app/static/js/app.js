"use strict";

const API = {
  login: "/auth/login",
  register: "/auth/register",
  me: "/me",
  documents: "/documents/",
  audit: "/admin/audit",
  adminPermissions: "/admin/permissions",
  verifyAudit: "/admin/audit/verify",

  grant: id => `/documents/${encodeURIComponent(id)}/permissions`,
  revoke: (id, username) =>
    `/documents/${encodeURIComponent(id)}/permissions/${encodeURIComponent(username)}`,
  document: id => `/documents/${encodeURIComponent(id)}`,
  download: id => `/documents/${encodeURIComponent(id)}/download`,

  // Request Access endpoints
  accessRequest: "/access-requests/",
  myAccessRequests: "/access-requests/mine",
  receivedAccessRequests: "/access-requests/received",
  approveAccessRequest: id =>
    `/access-requests/${encodeURIComponent(id)}/approve`,
  rejectAccessRequest: id =>
    `/access-requests/${encodeURIComponent(id)}/reject`
};

const $ = id => document.getElementById(id);
let previewRequestId = 0;

const state = {
  token: sessionStorage.getItem("trustvault_token"),
  user: null,
  documents: [],
  selectedShareDocument: null,
  auditOffset: 0,
  auditLimit: 50,
  auditTotal: 0,
  toastTimer: null
};
function toast(message, isError = false) {
  const el = $("toast");
  if (!el) return;

  el.textContent = String(message ?? "");
  el.className = `toast show${isError ? " error" : ""}`;

  clearTimeout(state.toastTimer);

  state.toastTimer = setTimeout(() => {
    el.className = "toast";
  }, 3600);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[c]);
}

function dateText(value) {
  if (!value) return "—";

  const d = new Date(value);

  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleString();
}

function sizeText(bytes) {
  const n = Number(bytes);

  if (!Number.isFinite(n) || n < 0) return "—";

  return n < 1024 * 1024
    ? `${(n / 1024).toFixed(1)} KB`
    : `${(n / 1048576).toFixed(2)} MB`;
}

function fileExtension(name) {
  const part = String(name || "").split(".").pop();

  return part && part.length < 7
    ? part.toUpperCase()
    : "FILE";
}

function sameId(a, b) {
  return a != null && b != null && String(a) === String(b);
}

function isAdmin() {
  return String(state.user?.role || "").toLowerCase() === "admin";
}

function setBusy(form, busy) {
  if (!form) return;

  const button = form.querySelector(
    'button[type="submit"],button:not([type])'
  );

  if (!button) return;

  if (busy) {
    if (!button.disabled) {
      button.dataset.originalText = button.textContent;
    }

    button.disabled = true;
    button.textContent = "Please wait…";
  } else {
    button.disabled = false;

    if (button.dataset.originalText !== undefined) {
      button.textContent = button.dataset.originalText;
      delete button.dataset.originalText;
    }
  }
}

function emptyState(
  title,
  message = "There is nothing to display yet."
) {
  return `
    <div class="empty-state">
      <strong>${escapeHtml(title)}</strong>
      ${escapeHtml(message)}
    </div>
  `;
}

function showLoading(id, message) {
  const el = $(id);

  if (el) {
    el.innerHTML = `
      <div class="loading-state">
        ${escapeHtml(message)}
      </div>
    `;
  }
}

function showEmpty(id, title, message) {
  const el = $(id);

  if (el) {
    el.innerHTML = emptyState(title, message);
  }
}

function currentPage() {
  return document
    .querySelector(".page:not([hidden])")
    ?.id?.replace("page-", "") || "dashboard";
}

async function api(path, options = {}) {
  const {
    rawResponse = false,
    skipSessionHandling = false,
    ...fetchOptions
  } = options;

  const headers = new Headers(fetchOptions.headers || {});

  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }

  let body = fetchOptions.body;

  if (body !== undefined && body !== null) {
    if (body instanceof FormData || body instanceof Blob) {
      // Let the browser set the correct Content-Type.
    } else if (typeof body === "object") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
  }

  let response;

  try {
    response = await fetch(path, {
      ...fetchOptions,
      headers,
      body
    });
  } catch {
    throw new Error(
      "Could not connect to TrustVault API. Check that the backend is running."
    );
  }

  if (
    response.status === 401 &&
    state.token &&
    !skipSessionHandling
  ) {
    signOut(false);
    showAuth("login");
    toast("Your session expired. Please sign in again.", true);
    throw new Error("Session expired.");
  }

  // Download mode: do not read the response body here.
  if (rawResponse && response.ok) {
    return { response, data: null };
  }

  // Read the response body only once.
  const contentType =
    response.headers.get("content-type") || "";

  let data = null;

  if (contentType.includes("application/json")) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    const text = await response.text();

    if (text) {
      data = { detail: text };
    }
  }

  if (!response.ok) {
    const detail =
      data?.detail ??
      data?.message ??
      `Request failed (${response.status})`;

    throw new Error(
      typeof detail === "string"
        ? detail
        : JSON.stringify(detail)
    );
  }

  return { response, data };
}

function showAuth(mode = "login") {
  if ($("auth-screen")) {
    $("auth-screen").hidden = false;
  }

  if ($("app-shell")) {
    $("app-shell").hidden = true;
  }

  if ($("login-form")) {
    $("login-form").hidden = mode !== "login";
  }

  if ($("register-form")) {
    $("register-form").hidden = mode !== "register";
  }
}

function showApp() {
  if (!state.user) return;

  $("auth-screen").hidden = true;
  $("app-shell").hidden = false;

  $("top-username").textContent =
    state.user.username || "User";

  $("top-role").textContent =
    state.user.role || "Viewer";

  $("user-avatar").textContent =
    (state.user.username || "U").charAt(0).toUpperCase();

  $("welcome-title").textContent =
    `Welcome back, ${state.user.username || "User"}`;

  $("admin-nav").hidden = !isAdmin();

  goTo("dashboard");
}


function signOut(showMessage = true) {
  state.token = null;
  state.user = null;
  state.documents = [];
  state.selectedShareDocument = null;
  state.auditOffset = 0;
  state.auditTotal = 0;

  // Clear Request Access form and previous user's request lists
  clearAccessRequestForm();

  sessionStorage.removeItem("trustvault_token");

  showAuth("login");

  if (showMessage) {
    toast("You have signed out.");
  }
}

function goTo(page) {
  const allowed = [
    "dashboard",
    "documents",
    "sharing",
    "access-requests",
    "audit",
    "admin-permissions"
  ];

  if (!allowed.includes(page)) return;

  if (!state.user) {
    return showAuth("login");
  }

  if (
    ["audit", "admin-permissions"].includes(page) &&
    !isAdmin()
  ) {
    toast("Administrator access required.", true);
    return;
  }

  document.querySelectorAll(".page").forEach(el => {
    el.hidden = true;
  });

  const target = $(`page-${page}`);

  if (!target) {
    toast(`Page not found: ${page}`, true);
    return;
  }

  target.hidden = false;

  document.querySelectorAll(".nav-item[data-page]").forEach(el => {
    el.classList.toggle("active", el.dataset.page === page);
  });

  const labels = {
    dashboard: "Overview",
    documents: "Documents",
    sharing: "Sharing & Access",
    "access-requests": "Request Access",
    audit: "Audit logs",
    "admin-permissions": "Access review"
  };

  $("breadcrumb-page").textContent = labels[page];

  $("sidebar")?.classList.remove("open");

  if (page === "dashboard") loadDashboard();
  if (page === "documents") loadDocuments();
  if (page === "sharing") loadSharing();
  if (page === "audit") loadAudit();

  if (page === "admin-permissions") {
    loadAdminPermissions();
  }
}


function clearAccessRequestForm() {
  const form = document.getElementById("request-access-form");

  if (form) {
    form.reset();
  }

  const myRequests = document.getElementById("my-access-requests");
  const receivedRequests = document.getElementById("received-access-requests");

  if (myRequests) myRequests.replaceChildren();
  if (receivedRequests) receivedRequests.replaceChildren();
}

function renderDocumentsTable(
  documents,
  targetId,
  showOwner = false
) {
  const container = $(targetId);

  if (!container) return;

  if (!documents.length) {
    container.innerHTML = emptyState(
      "No documents found",
      "Upload a document or change your search filters."
    );
    return;
  }

  const rows = documents.map(doc => {
    const own = sameId(doc.owner_id, state.user?.id);
    const canEdit = own || doc.can_edit === true;

    const filename = escapeHtml(
      doc.original_filename || "Document"
    );

    const title = escapeHtml(
      doc.title || doc.original_filename || "Untitled"
    );

    const id = escapeHtml(doc.id);

    return `
      <tr>
        <td>
          <div class="file-name">
            <span class="file-icon">
              ${escapeHtml(fileExtension(doc.original_filename))}
            </span>
            <div>
              ${title}
              <div class="subtext">${filename}</div>
            </div>
          </div>
        </td>

        <td>${escapeHtml(doc.category || "—")}</td>

        ${
          showOwner
            ? `<td>${
                own
                  ? "You"
                  : escapeHtml(
                      doc.owner_username ||
                      doc.owner_name ||
                      `User #${doc.owner_id ?? "—"}`
                    )
              }</td>`
            : ""
        }

        <td>${sizeText(doc.size_bytes)}</td>
        <td>${dateText(doc.created_at)}</td>

        <td>
  <div class="row-actions">
    <button
      class="small-btn"
      data-action="preview"
      data-id="${id}">
      Preview
    </button>

    <button
      class="small-btn"
      data-action="download"
      data-id="${id}">
      Download
    </button>

    ${
      canEdit
        ? `
          <button
            class="small-btn"
            data-action="edit"
            data-id="${id}">
            Edit
          </button>
        `
        : ""
    }

    ${
      own
        ? `
          <button
            class="small-btn danger"
            data-action="delete"
            data-id="${id}">
            Delete
          </button>
        `
        : ""
    }
  </div>
</td>
      </tr>
    `;
  }).join("");

  container.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Document</th>
          <th>Category</th>
          ${showOwner ? "<th>Owner</th>" : ""}
          <th>Size</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

async function fetchDocuments(query = "") {
  const url = query
    ? `${API.documents}?${query}`
    : API.documents;

  const { data } = await api(url);

  if (Array.isArray(data)) return data;

  if (Array.isArray(data?.items)) return data.items;

  throw new Error("Unexpected documents response from API.");
}

async function loadDashboard() {
  showLoading("recent-documents", "Loading documents…");

  try {
    state.documents = await fetchDocuments();

    const owned = state.documents.filter(d =>
      sameId(d.owner_id, state.user?.id)
    );

    $("stat-documents").textContent =
      state.documents.length;

    $("stat-owned").textContent = owned.length;

    $("stat-shared").textContent =
      state.documents.length - owned.length;

    renderDocumentsTable(
      state.documents.slice(0, 5),
      "recent-documents"
    );
  } catch (e) {
    showEmpty(
      "recent-documents",
      "Could not load documents",
      e.message
    );

    $("stat-documents").textContent = "—";
    $("stat-owned").textContent = "—";
    $("stat-shared").textContent = "—";
  }
}

function getDocumentFilters() {
  const params = new URLSearchParams();

  const fields = {
    search: "search",
    category: "category-filter",
    owner: "owner-filter",
    date_from: "date-from",
    date_to: "date-to"
  };

  for (const [key, id] of Object.entries(fields)) {
    const value = $(id)?.value.trim();

    if (value) {
      params.set(key, value);
    }
  }

  return params.toString();
}

async function loadDocuments() {
  showLoading("document-list", "Loading documents…");

  try {
    state.documents = await fetchDocuments(
      getDocumentFilters()
    );

    renderDocumentsTable(
      state.documents,
      "document-list",
      true
    );
  } catch (e) {
    showEmpty(
      "document-list",
      "Could not load documents",
      e.message
    );
  }
}

async function refreshCurrent() {
  const page = currentPage();

  if (page === "dashboard") await loadDashboard();
  else if (page === "documents") await loadDocuments();
  else if (page === "sharing") await loadSharing();
  else if (page === "audit") await loadAudit();
  else if (page === "admin-permissions") {
    await loadAdminPermissions();
  }
}

async function loadSharing() {
  showLoading("sharing-list", "Loading your documents…");

  $("sharing-manager").hidden = true;
  state.selectedShareDocument = null;

  try {
    state.documents = await fetchDocuments();

    const owned = state.documents.filter(d =>
      sameId(d.owner_id, state.user?.id)
    );

    if (!owned.length) {
      return showEmpty(
        "sharing-list",
        "No owned documents",
        "Upload a document before managing access."
      );
    }

    $("sharing-list").innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Document</th>
            <th>Category</th>
            <th>Created</th>
            <th>Access</th>
          </tr>
        </thead>
        <tbody>
          ${owned.map(d => `
            <tr>
              <td>${escapeHtml(d.title || "Untitled")}</td>
              <td>${escapeHtml(d.category || "—")}</td>
              <td>${dateText(d.created_at)}</td>
              <td>
                <button
                  class="small-btn"
                  data-action="manage-sharing"
                  data-id="${escapeHtml(d.id)}">
                  Manage access
                </button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    showEmpty(
      "sharing-list",
      "Could not load documents",
      e.message
    );
  }
}


async function selectSharingDocument(id) {
  const doc = state.documents.find(d => sameId(d.id, id));

  if (!doc) {
    toast("Document not found. Refresh and try again.", true);
    return;
  }

  state.selectedShareDocument = doc;

  $("sharing-manager").hidden = false;
  $("sharing-title").textContent =
    `Manage access: ${doc.title || doc.original_filename}`;

  $("grant-form").reset();
  $("grant-hint").textContent =
    "Grant access to an existing registered user.";
  $("current-grants").textContent = "Loading access grants…";

  await loadDocumentGrants(doc.id);
}

async function loadDocumentGrants(documentId) {
  const container = $("current-grants");
  container.replaceChildren();

  try {
    const result = await api(
      `/documents/${encodeURIComponent(documentId)}/permissions`
    );
    console.log("Selected document ID:", documentId);
    console.log("Permissions API response:", result);
    const grants = Array.isArray(result.data?.items)
      ? result.data.items
      : [];

    if (grants.length === 0) {
      container.textContent = "No users have been granted access yet.";
      return;
    }

    const table = document.createElement("table");
    table.className = "data-table";

    const thead = document.createElement("thead");
    const headerRow = document.createElement("tr");

    ["Username", "Read", "Edit", "Status", "Action"].forEach(label => {
      const th = document.createElement("th");
      th.textContent = label;
      headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");

    grants.forEach(grant => {
      const row = document.createElement("tr");

      const username = document.createElement("td");
      username.textContent = grant.username;

      const read = document.createElement("td");
      read.textContent = grant.can_read ? "Yes" : "No";

      const edit = document.createElement("td");
      edit.textContent = grant.can_edit ? "Yes" : "No";

      const active = document.createElement("td");
      active.textContent = grant.is_active ? "Active" : "Inactive";

      const action = document.createElement("td");
      const revokeButton = document.createElement("button");

      revokeButton.type = "button";
      revokeButton.className = "btn btn-danger";
      revokeButton.textContent = "Revoke";
      revokeButton.dataset.action = "revoke-sharing";
      revokeButton.dataset.id = String(documentId);
      revokeButton.dataset.username = grant.username;

      action.appendChild(revokeButton);
      row.append(username, read, edit, active, action);
      tbody.appendChild(row);
    });

    table.appendChild(tbody);
    container.appendChild(table);
  } catch (error) {
    container.textContent = "Could not load access grants.";
    toast(error.message || "Failed to load access grants.", true);
  }
}


async function loadCurrentGrants() {
  const doc = state.selectedShareDocument;
  const container = $("current-grants");

  if (!doc || !container) return;

  container.innerHTML =
    '<div class="loading-state">Loading access grants…</div>';

  try {
    const { data } = await api(
      `/documents/${encodeURIComponent(doc.id)}/permissions`
    );

    const items = data?.items;

    if (!Array.isArray(items)) {
      throw new Error("Unexpected permission list response.");
    }

    if (!items.length) {
      container.innerHTML = emptyState(
        "No access grants",
        "Only you currently have access to this document."
      );
      return;
    }

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Account</th>
            <th>Read</th>
            <th>Edit</th>
            <th>Granted</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${items.map(item => `
            <tr>
              <td>${escapeHtml(item.username)}</td>
              <td>${item.is_active ? "Active" : "Inactive"}</td>
              <td>${item.can_read ? "Yes" : "No"}</td>
              <td>${item.can_edit ? "Yes" : "No"}</td>
              <td>${dateText(item.created_at)}</td>
              <td>
                <button
                  class="small-btn danger"
                  data-action="revoke-sharing"
                  data-id="${escapeHtml(doc.id)}"
                  data-username="${escapeHtml(item.username)}">
                  Revoke
                </button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;
  } catch (e) {
    showEmpty(
      "current-grants",
      "Could not load access grants",
      e.message
    );
  }
}


async function grantAccess(event) {
  event.preventDefault();

  const button = event.currentTarget;
  const doc = state.selectedShareDocument;

  if (!doc || !sameId(doc.owner_id, state.user?.id)) {
    return toast("Only the document owner can grant access.", true);
  }

  const username = $("grant-username").value.trim();
  const canEdit = $("grant-edit").checked;
  const canRead = $("grant-read").checked || canEdit;

  if (!username) return toast("Enter a username.", true);
  if (!canRead && !canEdit) {
    return toast("Select read access or edit access.", true);
  }

  setBusy(button, true);

  try {
    await api(API.grant(doc.id), {
      method: "POST",
      body: {
        username,
        can_read: canRead,
        can_edit: canEdit
      }
    });

    toast("Permission granted successfully.");

    $("grant-username").value = "";
    $("grant-read").checked = false;
    $("grant-edit").checked = false;

    await loadDocumentGrants(doc.id);
  } catch (e) {
    toast(e.message || "Failed to grant permission.", true);
  } finally {
    setBusy(button, false);
  }
}

async function revokeAccess(id, username) {
  const doc = state.documents.find(d =>
    sameId(d.id, id)
  );

  if (!doc || !sameId(doc.owner_id, state.user?.id)) {
    return toast(
      "Only the document owner can revoke access.",
      true
    );
  }

  if (!username) {
    return toast("Username is required.", true);
  }

  if (!confirm(`Revoke access for "${username}"?`)) {
    return;
  }

  try {
    await api(API.revoke(id, username), {
      method: "DELETE"
    });

    toast("Access revoked successfully.");

    // Refresh the selected document's current access list.
    if (
      state.selectedShareDocument &&
      sameId(state.selectedShareDocument.id, id)
    ) {
      await loadDocumentGrants(id);
    }
  } catch (e) {
    toast(e.message || "Failed to revoke access.", true);
  }
}

async function loadAudit() {
  showLoading("audit-list", "Loading audit events…");

  if (!isAdmin()) {
    return showEmpty(
      "audit-list",
      "Administrator access required",
      "Sign in with an administrator account."
    );
  }

  const params = new URLSearchParams({
    limit: String(state.auditLimit),
    offset: String(state.auditOffset)
  });

  const action = $("audit-action")?.value.trim();
  const outcome = $("audit-outcome")?.value;

  if (action) params.set("action", action);
  if (outcome) params.set("outcome", outcome);

  try {
    const { data } = await api(
      `${API.audit}?${params}`
    );

    const items = Array.isArray(data)
      ? data
      : data?.items;

    if (!Array.isArray(items)) {
      throw new Error(
        "Unexpected audit response. Expected an array or an object containing items."
      );
    }

    state.auditTotal = Number(
      data?.total ?? items.length
    );

    $("audit-list").innerHTML = items.length
      ? `
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor ID</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Outcome</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(item => {
              const outcomeText =
                String(item.outcome || "—");

              const cls = [
                "success",
                "denied",
                "failure"
              ].includes(outcomeText.toLowerCase())
                ? outcomeText.toLowerCase()
                : "";

              return `
                <tr>
                  <td>${dateText(item.created_at || item.timestamp)}</td>
                  <td>${escapeHtml(item.actor_id ?? item.user_id ?? "—")}</td>
                  <td>${escapeHtml(item.action || "—")}</td>
                  <td>
                    ${escapeHtml(item.resource_type || "—")}
                    ${escapeHtml(item.resource_id ?? "")}
                  </td>
                  <td>
                    <span class="pill ${cls}">
                      ${escapeHtml(outcomeText)}
                    </span>
                  </td>
                  <td>${escapeHtml(item.details || item.reason || "—")}</td>
                </tr>
              `;
            }).join("")}
          </tbody>
        </table>
      `
      : emptyState(
          "No audit events",
          "Try changing the filters."
        );

    const page =
      Math.floor(state.auditOffset / state.auditLimit) + 1;

    $("audit-page").textContent =
      `Page ${page} · ${state.auditTotal} events`;

    $("audit-prev").disabled =
      state.auditOffset === 0;

    $("audit-next").disabled =
      state.auditOffset + state.auditLimit >= state.auditTotal;
  } catch (e) {
    showEmpty(
      "audit-list",
      "Could not load audit logs",
      e.message
    );
  }
}

async function loadAdminPermissions() {
  showLoading(
    "admin-permissions-list",
    "Loading permission records…"
  );

  if (!isAdmin()) {
    return showEmpty(
      "admin-permissions-list",
      "Administrator access required",
      "Sign in with an administrator account."
    );
  }

  try {
    const { data } = await api(
      `${API.adminPermissions}?limit=100&offset=0`
    );

    const items = Array.isArray(data)
      ? data
      : data?.items;

    if (!Array.isArray(items)) {
      throw new Error(
        "Unexpected permissions response. Expected an array or an object containing items."
      );
    }

    $("admin-permissions-list").innerHTML = items.length
      ? `
        <table>
          <thead>
            <tr>
              <th>Document</th>
              <th>Document ID</th>
              <th>Owner ID</th>
              <th>Username</th>
              <th>Read</th>
              <th>Edit</th>
              <th>Granted by</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(item => `
              <tr>
                <td>${escapeHtml(item.document_title || item.title || "—")}</td>
                <td>${escapeHtml(item.document_id ?? item.document_id_fk ?? "—")}</td>
                <td>${escapeHtml(item.owner_id ?? "—")}</td>
                <td>${escapeHtml(item.username || item.grantee_username || "—")}</td>
                <td>
                  <span class="pill ${item.can_read ? "success" : ""}">
                    ${item.can_read ? "Yes" : "No"}
                  </span>
                </td>
                <td>
                  <span class="pill ${item.can_edit ? "success" : ""}">
                    ${item.can_edit ? "Yes" : "No"}
                  </span>
                </td>
                <td>${escapeHtml(item.granted_by_id ?? "—")}</td>
                <td>${dateText(item.created_at)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `
      : emptyState(
          "No permission grants",
          "No permission records were returned."
        );
  } catch (e) {
    showEmpty(
      "admin-permissions-list",
      "Could not load permission review",
      e.message
    );
  }
}

async function verifyAudit() {
  const button = $("verify-audit");

  button.disabled = true;
  button.textContent = "Verifying…";

  try {
    const { data } = await api(API.verifyAudit);

    const valid = Boolean(
      data?.valid ?? data?.verified ?? data?.ok
    );

    const box = $("audit-verification");

    box.hidden = false;

    box.innerHTML = `
      <span>${valid ? "✓" : "!"}</span>
      <div>
        <strong>
          ${valid
            ? "Audit verification passed"
            : "Audit verification result"}
        </strong>
        <p>
          ${escapeHtml(
            data?.message ||
            data?.detail ||
            (
              valid
                ? "The API reported a valid audit chain."
                : "The API did not confirm a valid audit chain."
            )
          )}
        </p>
      </div>
    `;

    box.style.background =
      valid ? "#e8f8ef" : "#fff0f0";

    box.style.color =
      valid ? "#16754f" : "#b42e3a";
  } catch (e) {
    toast(e.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Verify audit chain";
  }
}
/* Universal file preview */

let activePreviewUrl = null;
let activePreviewId = null;


function closePreview() {
  // Cancel the effect of any pending preview request.
  previewRequestId++;

  const dialog = $("preview-dialog");
  const content = $("preview-content");

  if (dialog?.open) {
    dialog.close();
  }

  content?.querySelectorAll("audio, video").forEach(media => {
    media.pause();
    media.removeAttribute("src");
    media.load();
  });

  content?.replaceChildren();

  if (activePreviewUrl) {
    URL.revokeObjectURL(activePreviewUrl);
    activePreviewUrl = null;
  }

  activePreviewId = null;
}


function addPreviewMessage(parent, text, className = "") {
  const el = document.createElement("div");

  el.className = className;
  el.textContent = text;

  parent.appendChild(el);

  return el;
}

function addPreviewMeta(parent, label, value) {
  const card = document.createElement("div");
  const small = document.createElement("small");
  const strong = document.createElement("strong");

  small.textContent = label;
  strong.textContent = value;

  card.append(small, strong);
  parent.appendChild(card);
}


async function previewDocument(id) {
  const doc = state.documents.find(d => sameId(d.id, id));

  if (!doc) {
    toast("Document not found. Refresh and try again.", true);
    return;
  }

  const requestId = ++previewRequestId;
  closePreview();

  // closePreview() increments the request ID, so capture the new ID.
  const currentRequestId = previewRequestId;

  const dialog = $("preview-dialog");
  const content = $("preview-content");

  $("preview-title").textContent =
    doc.title || doc.original_filename || "File preview";
  $("preview-info").textContent = "Loading secure file…";
  content.replaceChildren();

  if (!dialog.open) dialog.showModal();

  addPreviewMessage(content, "Fetching file securely…");

  let previewUrl = null;

  try {
    const { response } = await api(API.download(id), {
      method: "GET",
      rawResponse: true
    });

    if (currentRequestId !== previewRequestId || !dialog.open) return;

    const blob = await response.blob();

    if (currentRequestId !== previewRequestId || !dialog.open) return;

    if (!blob.size) {
      throw new Error("The server returned an empty file.");
    }

    previewUrl = URL.createObjectURL(blob);
    activePreviewId = id;
    activePreviewUrl = previewUrl;

    const filename =
      doc.original_filename ||
      doc.filename ||
      doc.title ||
      `document-${id}`;

    const mime = (
      blob.type || "application/octet-stream"
    ).split(";")[0].toLowerCase();

    $("preview-title").textContent = filename;
    $("preview-info").textContent =
      `${mime} · ${sizeText(blob.size)}`;

    content.replaceChildren();

    const meta = document.createElement("div");
    meta.className = "preview-meta";

    addPreviewMeta(meta, "Filename", filename);
    addPreviewMeta(meta, "File type", mime);
    addPreviewMeta(meta, "File size", sizeText(blob.size));
    addPreviewMeta(meta, "Document ID", String(id));

    content.appendChild(meta);

    const lowerName = filename.toLowerCase();

    if (mime.startsWith("image/") && mime !== "image/svg+xml") {
      const img = document.createElement("img");
      img.alt = filename;
      img.src = previewUrl;
      content.appendChild(img);
      return;
    }

    if (mime.startsWith("audio/") || mime.startsWith("video/")) {
      const media = document.createElement(
        mime.startsWith("audio/") ? "audio" : "video"
      );

      media.src = previewUrl;
      media.controls = true;
      media.preload = "metadata";
      content.appendChild(media);
      return;
    }

    const textExtensions = [
      ".txt", ".md", ".csv", ".json", ".xml",
      ".html", ".htm", ".css", ".js", ".ts",
      ".py", ".java", ".c", ".cpp", ".h",
      ".sql", ".log", ".yaml", ".yml", ".toml",
      ".ini", ".sh", ".bat", ".ps1", ".properties",
      ".env", ".gitignore", ".jsx", ".tsx"
    ];

    const isText =
      mime.startsWith("text/") ||
      mime === "application/json" ||
      mime === "application/xml" ||
      mime === "application/javascript" ||
      mime === "application/x-sh" ||
      textExtensions.some(ext => lowerName.endsWith(ext));

    if (isText) {
      const text = await blob.text();

      if (currentRequestId !== previewRequestId || !dialog.open) return;

      const pre = document.createElement("pre");
      pre.textContent = text.slice(0, 500000);
      content.appendChild(pre);

      if (text.length > 500000) {
        addPreviewMessage(
          content,
          "Only the first 500,000 characters are shown. Download the file to see the complete contents.",
          "preview-warning"
        );
      }
      return;
    }

    if (mime === "application/pdf") {
      const frame = document.createElement("iframe");
      frame.title = `Preview of ${filename}`;
      frame.src = previewUrl;
      frame.setAttribute("sandbox", "");
      frame.setAttribute("referrerpolicy", "no-referrer");
      content.appendChild(frame);
      return;
    }

    addPreviewMessage(
      content,
      "This file type cannot be rendered as its original document by the browser. A generic binary preview is shown below. Use Download to open the file in a compatible application.",
      "preview-warning"
    );

    const arrayBuffer = await blob.slice(0, 512).arrayBuffer();

    if (currentRequestId !== previewRequestId || !dialog.open) return;

    const bytes = new Uint8Array(arrayBuffer);
    const lines = [];

    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const offset = i.toString(16).padStart(8, "0");
      const hexBytes = Array.from(chunk)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(" ");

      lines.push(`${offset}  ${hexBytes}`);
    }

    const pre = document.createElement("pre");
    pre.textContent = lines.join("\n") || "No binary data available.";
    content.appendChild(pre);
  } catch (error) {
    if (currentRequestId !== previewRequestId || !dialog.open) return;

    content.replaceChildren();

    addPreviewMessage(
      content,
      `Preview failed: ${error.message || "Unable to load the file."}`,
      "preview-warning"
    );

    toast(error.message || "Preview failed.", true);
  } finally {
    if (previewUrl && activePreviewUrl !== previewUrl) {
      URL.revokeObjectURL(previewUrl);
    }
  }
}

async function downloadDocument(id) {
  try {
    const { response } = await api(API.download(id), {
      method: "GET",
      rawResponse: true
    });

    const blob = await response.blob();

    if (!blob.size) {
      throw new Error("The downloaded file is empty.");
    }

    const disposition =
      response.headers.get("content-disposition") || "";

    let filename = `trustvault-document-${id}`;

    const utf8 = disposition.match(
      /filename\*=UTF-8''([^;]+)/i
    );

    const normal = disposition.match(
      /filename="?([^";]+)"?/i
    );

    try {
      if (utf8) {
        filename = decodeURIComponent(utf8[1]);
      } else if (normal) {
        filename = normal[1];
      }
    } catch {
      // Use the fallback filename.
    }

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 2000);

    toast("File downloaded successfully.");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteDocument(id) {
  const doc = state.documents.find(d =>
    sameId(d.id, id)
  );

  if (!doc) {
    return toast(
      "Document not found. Refresh and try again.",
      true
    );
  }

  if (!sameId(doc.owner_id, state.user?.id)) {
    return toast(
      "Only the owner can delete this document.",
      true
    );
  }

  if (
    !confirm(
      `Delete "${doc.title || "Untitled"}"? This cannot be undone.`
    )
  ) {
    return;
  }

  try {
    await api(API.document(id), {
      method: "DELETE"
    });

    toast("Document deleted.");
    await refreshCurrent();
  } catch (e) {
    toast(e.message, true);
  }
}

function editDocument(id) {
  const doc = state.documents.find(d =>
    sameId(d.id, id)
  );

  if (!doc) {
    return toast(
      "Document not found. Refresh and try again.",
      true
    );
  }

  const own = sameId(doc.owner_id, state.user?.id);
  const canEdit = own || doc.can_edit === true;

  if (!canEdit) {
    return toast(
      "You do not have permission to edit this document.",
      true
    );
  }

  $("edit-id").value = doc.id;
  $("edit-title").value = doc.title || "";
  $("edit-category").value = doc.category || "";

  $("edit-dialog").showModal();
}

async function saveDocument(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const id = $("edit-id").value;
  const title = $("edit-title").value.trim();
  const category = $("edit-category").value.trim();

  if (!title || !category) {
    return toast(
      "Title and category are required.",
      true
    );
  }

  setBusy(form, true);

  try {
    await api(API.document(id), {
      method: "PATCH",
      body: { title, category }
    });

    $("edit-dialog").close();

    toast("Document details updated.");
    await refreshCurrent();
  } catch (e) {
    toast(e.message, true);
  } finally {
    setBusy(form, false);
  }
}

async function uploadDocument(event) {
  event.preventDefault();

  const file = $("upload-file").files?.[0];

  if (!file) {
    return toast("Choose a file to upload.", true);
  }

  if (file.size > 10 * 1024 * 1024) {
    return toast(
      "File exceeds the 10 MB limit.",
      true
    );
  }

  const title = $("upload-title").value.trim();
  const category = $("upload-category").value.trim();

  if (!title || !category) {
    return toast(
      "Title and category are required.",
      true
    );
  }

  const formData = new FormData();

  formData.append("title", title);
  formData.append("category", category);
  formData.append("file", file);

  const form = event.currentTarget;

  setBusy(form, true);

  try {
    await api(API.documents, {
      method: "POST",
      body: formData
    });

    $("upload-dialog").close();
    form.reset();

    toast("Document uploaded successfully.");

    await refreshCurrent();
  } catch (e) {
    toast(e.message, true);
  } finally {
    setBusy(form, false);
  }
}

async function login(event) {
  event.preventDefault();

  const form = event.currentTarget;

  const username =
    $("login-username").value.trim();

  const password =
    $("login-password").value;

  setBusy(form, true);

  try {
    const { data } = await api(API.login, {
      method: "POST",
      body: { username, password },
      skipSessionHandling: true
    });

    if (!data?.access_token) {
      throw new Error(
        "Login response did not contain an access_token. Check the backend login response format."
      );
    }

    state.token = data.access_token;

    sessionStorage.setItem(
      "trustvault_token",
      state.token
    );

    const profile = await api(API.me);

    if (
      !profile.data ||
      !profile.data.username ||
      profile.data.id == null ||
      !profile.data.role
    ) {
      throw new Error(
        "The /me response must include id, username and role."
      );
    }

    state.user = profile.data;

    showApp();
    toast("Signed in successfully.");
  } catch (e) {
    state.token = null;
    state.user = null;

    sessionStorage.removeItem("trustvault_token");

    showAuth("login");
    toast(e.message, true);
  } finally {
    setBusy(form, false);
  }
}

async function register(event) {
  event.preventDefault();

  const form = event.currentTarget;

  const username =
    $("register-username").value.trim();

  const email =
    $("register-email").value.trim();

  const password =
    $("register-password").value;

  if (!username || !email || !password) {
    return toast(
      "Please fill in all required fields.",
      true
    );
  }

  if (password.length < 12) {
    return toast(
      "Password must contain at least 12 characters.",
      true
    );
  }

  setBusy(form, true);

  try {
    await api(API.register, {
      method: "POST",
      body: { username, email, password },
      skipSessionHandling: true
    });

    form.reset();

    showAuth("login");

    $("login-username").value = username;

    toast("Account created. Sign in to continue.");
  } catch (e) {
    toast(e.message, true);
  } finally {
    setBusy(form, false);
  }
}

function bind(id, eventName, handler) {
  const el = $(id);

  if (el) {
    el.addEventListener(eventName, handler);
  } else {
    console.warn(`HTML element not found: #${id}`);
  }
}

/* Navigation */


document
  .querySelectorAll(".nav-item[data-page]")
  .forEach(btn => {
    btn.addEventListener("click", async () => {
      const page = btn.dataset.page;

      goTo(page);

      if (page === "access-requests") {
        await loadMyAccessRequests();
        await loadReceivedAccessRequests();
      }
    });
  });


document
  .querySelectorAll("[data-goto]")
  .forEach(btn => {
    btn.addEventListener("click", () => {
      goTo(btn.dataset.goto);
    });
  });

document
  .querySelectorAll("[data-close]")
  .forEach(btn => {
    btn.addEventListener("click", () => {
      const dialog = $(btn.dataset.close);

      if (dialog?.open) {
        dialog.close();
      }
    });
  });


document.addEventListener("click", event => {
  if (!(event.target instanceof Element)) return;

  const btn = event.target.closest("[data-action]");

  if (!btn) return;

  const { action, id, username } = btn.dataset;

  if (action === "preview") {
    previewDocument(id);
  } else if (action === "download") {
    downloadDocument(id);
  } else if (action === "edit") {
    editDocument(id);
  } else if (action === "delete") {
    deleteDocument(id);
  } else if (action === "manage-sharing") {
    selectSharingDocument(id);
  } else if (action === "revoke-sharing") {
    revokeAccess(id, username);
  }
});

/* Form handlers: bind to the actual FORM elements. */

bind("login", "submit", login);
bind("register", "submit", register);
bind("grant-form", "submit", grantAccess);
bind("upload-form", "submit", uploadDocument);
bind("edit-form", "submit", saveDocument);
bind("request-access-form", "submit", submitAccessRequest);
bind("show-register", "click", () => {
  showAuth("register");
});

bind("show-login", "click", () => {
  showAuth("login");
});

bind("logout", "click", () => {
  signOut();
});


bind("close-preview", "click", closePreview);

bind("preview-close-bottom", "click", closePreview);

bind("preview-download", "click", () => {
  if (activePreviewId !== null) {
    downloadDocument(activePreviewId);
  }
});

bind("dashboard-upload", "click", () => {
  $("upload-dialog").showModal();
});

bind("documents-upload", "click", () => {
  $("upload-dialog").showModal();
});
bind("refresh-my-access-requests", "click", loadMyAccessRequests);
bind("refresh-received-access-requests", "click", loadReceivedAccessRequests);
bind("apply-filters", "click", loadDocuments);

bind("clear-filters", "click", () => {
  [
    "search",
    "category-filter",
    "owner-filter",
    "date-from",
    "date-to"
  ].forEach(id => {
    if ($(id)) {
      $(id).value = "";
    }
  });

  loadDocuments();
});

bind("apply-audit", "click", () => {
  state.auditOffset = 0;
  loadAudit();
});

bind("refresh-audit", "click", loadAudit);

bind(
  "refresh-admin-permissions",
  "click",
  loadAdminPermissions
);

bind("verify-audit", "click", verifyAudit);

bind("audit-prev", "click", () => {
  state.auditOffset = Math.max(
    0,
    state.auditOffset - state.auditLimit
  );

  loadAudit();
});

bind("audit-next", "click", () => {
  if (
    state.auditOffset + state.auditLimit <
    state.auditTotal
  ) {
    state.auditOffset += state.auditLimit;
    loadAudit();
  }
});

bind("mobile-menu", "click", () => {
  const sidebar = $("sidebar");

  if (!sidebar) return;

  if (window.matchMedia("(max-width: 760px)").matches) {
    sidebar.classList.toggle("open");
  } else {
    sidebar.classList.toggle("collapsed");
  }
});

bind("grant-edit", "change", () => {
  if ($("grant-edit").checked) {
    $("grant-read").checked = true;
  }
});

/* Restore an existing session when possible. */

async function start() {
  if (!state.token) {
    showAuth("login");
    return;
  }

  try {
    const { data } = await api(API.me);

    if (
      !data ||
      data.id == null ||
      !data.username ||
      !data.role
    ) {
      throw new Error(
        "The /me response must include id, username and role."
      );
    }

    state.user = data;
    showApp();
  } catch (e) {
    signOut(false);
    showAuth("login");

    if (e.message !== "Session expired.") {
      console.warn(
        "Unable to restore previous session:",
        e.message
      );
    }
  }
}

start();


async function submitAccessRequest(event) {
  event.preventDefault();

  const documentId = $("request-document-id")?.value.trim();
  const requestedAccess = $("request-access-type")?.value;
  const reason = $("request-access-reason")?.value.trim();

  if (!documentId || !/^\d+$/.test(documentId)) {
    toast("Please enter a valid document ID.", true);
    return;
  }

  try {
    const result = await api(API.accessRequest, {
      method: "POST",
      body: {
        document_id: Number(documentId),
        requested_access: requestedAccess,
        reason: reason || ""
      }
    });

    toast(result.data?.message || "Access request submitted.");
    event.target.reset();
    await loadMyAccessRequests();
  } catch (error) {
    toast(error.message || "Could not submit access request.", true);
  }
}

async function loadMyAccessRequests() {
  const container = $("my-access-requests");
  if (!container) return;

  try {
    const result = await api(API.myAccessRequests);
    const requests = Array.isArray(result.data)
      ? result.data
      : result.data?.items || result.data?.requests || [];

    container.replaceChildren();

    if (requests.length === 0) {
      container.textContent = "You have not submitted any access requests.";
      return;
    }

    requests.forEach(request => {
      const item = document.createElement("p");
      item.textContent =
        `Document: ${request.document_title || request.document_id} | ` +
        `Access: ${request.requested_access} | Status: ${request.status}`;
      container.appendChild(item);
    });
  } catch (error) {
    container.textContent =
      error.message || "Could not load your access requests.";
  }
}

async function loadReceivedAccessRequests() {
  const container = $("received-access-requests");
  if (!container) return;

  try {
    const result = await api(API.receivedAccessRequests);
    const requests = Array.isArray(result.data)
       ? result.data
       : result.data?.items || result.data?.requests || [];


    container.replaceChildren();

    if (requests.length === 0) {
      container.textContent = "No pending access requests.";
      return;
    }

    requests.forEach(request => {
      const item = document.createElement("div");
      const details = document.createElement("p");

      details.textContent =
        `${request.requester_username || "User"} requests ` +
        `${request.requested_access} access to ` +
        `${request.document_title || "document " + request.document_id}` +
        (request.reason ? ` — Reason: ${request.reason}` : "");

      item.appendChild(details);

      ["approve", "reject"].forEach(action => {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent =
          action === "approve" ? "Approve" : "Reject";

        button.addEventListener("click", async () => {
          await reviewAccessRequest(request.id, action);
        });

        item.appendChild(button);
      });

      container.appendChild(item);
    });
  } catch (error) {
    container.textContent =
      error.message || "Could not load received requests.";
  }
}

async function reviewAccessRequest(requestId, action) {
  const endpoint =
    action === "approve"
      ? API.approveAccessRequest(requestId)
      : API.rejectAccessRequest(requestId);

  try {
    const result = await api(endpoint, { method: "POST" });

    toast(
      result.data?.message ||
      `Access request ${action === "approve" ? "approved" : "rejected"}.`
    );

    await loadReceivedAccessRequests();
  } catch (error) {
    toast(error.message || "Could not review the request.", true);
  }
}
