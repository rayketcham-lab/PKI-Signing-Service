/**
 * Code Signing Service — Client-side JavaScript
 *
 * Unified sign form with TOS scroll-to-accept, batch file upload (max 10),
 * auto-routing (PE/PS = Authenticode, other = detached CMS).
 * Admin dashboard with clickable cert details (openssl-style).
 * No external dependencies. All dynamic content sanitized via DOM APIs.
 */

"use strict";

var MAX_FILES = 10;

/* Known PE extensions that get Authenticode signing */
var PE_EXTENSIONS = ["exe", "dll", "sys", "ocx", "scr", "cpl", "drv"];
/* Known PowerShell extensions */
var PS_EXTENSIONS = ["ps1", "psm1", "psd1"];
/* MSI/CAB extensions */
var MSI_EXTENSIONS = ["msi", "cab"];
/* All extensions routed to /api/v1/sign (Authenticode/PS/MSI) */
var SIGN_EXTENSIONS = PE_EXTENSIONS.concat(PS_EXTENSIONS).concat(MSI_EXTENSIONS);

/* ─── Utility Functions ─────────────────────────────────────────────── */

function formatBytes(bytes) {
    if (bytes === 0) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    if (i >= units.length) i = units.length - 1;
    return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
}

function formatUptime(seconds) {
    var d = Math.floor(seconds / 86400);
    var h = Math.floor((seconds % 86400) / 3600);
    var m = Math.floor((seconds % 3600) / 60);
    var s = seconds % 60;
    var parts = [];
    if (d > 0) parts.push(d + "d");
    if (h > 0) parts.push(h + "h");
    if (m > 0) parts.push(m + "m");
    parts.push(s + "s");
    return parts.join(" ");
}

function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

function clearChildren(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
}

function showPanel(el, show) {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
}

function showProgress(el, show) {
    if (show) el.classList.add("visible");
    else el.classList.remove("visible");
}

function showAlert(el, message, type) {
    el.className = "alert alert-" + (type || "info") + " mt-2";
    el.textContent = message;
    el.classList.remove("hidden");
}

function hideAlert(el) {
    if (el) el.classList.add("hidden");
}

function createResultRow(label, value) {
    var row = document.createElement("div");
    row.className = "result-row";
    var labelSpan = document.createElement("span");
    labelSpan.className = "result-label";
    labelSpan.textContent = label + ":";
    var valueSpan = document.createElement("span");
    valueSpan.className = "result-value";
    valueSpan.textContent = String(value);
    row.appendChild(labelSpan);
    row.appendChild(valueSpan);
    return row;
}

function createResultRowWithBadge(label, text, badgeClass) {
    var row = document.createElement("div");
    row.className = "result-row";
    var labelSpan = document.createElement("span");
    labelSpan.className = "result-label";
    labelSpan.textContent = label + ":";
    var valueSpan = document.createElement("span");
    valueSpan.className = "result-value";
    var badge = document.createElement("span");
    badge.className = "badge " + badgeClass;
    badge.textContent = text;
    valueSpan.appendChild(badge);
    row.appendChild(labelSpan);
    row.appendChild(valueSpan);
    return row;
}

function getFileExtension(filename) {
    var parts = filename.split(".");
    if (parts.length < 2) return "";
    return parts[parts.length - 1].toLowerCase();
}

/* ─── TOS Scroll-to-Accept ──────────────────────────────────────────── */

function initTosScroll() {
    var tosBox = document.getElementById("tos-box");
    var tosCheckbox = document.getElementById("tos-accept");
    var signForm = document.getElementById("sign-form");
    if (!tosBox || !tosCheckbox) return;

    tosBox.addEventListener("scroll", function () {
        /* Enable checkbox when scrolled within 10px of bottom */
        var atBottom = (tosBox.scrollHeight - tosBox.scrollTop - tosBox.clientHeight) < 10;
        if (atBottom) {
            tosCheckbox.disabled = false;
        }
    });

    tosCheckbox.addEventListener("change", function () {
        if (signForm) {
            if (tosCheckbox.checked) {
                signForm.classList.remove("hidden");
            } else {
                signForm.classList.add("hidden");
            }
        }
    });
}

/* ─── Batch File Upload ─────────────────────────────────────────────── */

var selectedFiles = [];

function initFileUpload() {
    var uploadArea = document.getElementById("file-upload-area");
    var fileInput = document.getElementById("file-input");
    var fileList = document.getElementById("file-list");
    var fileCount = document.getElementById("file-count");
    var submitBtn = document.getElementById("sign-submit-btn");
    if (!uploadArea || !fileInput) return;

    uploadArea.addEventListener("dragenter", function (e) {
        e.preventDefault();
        uploadArea.classList.add("drag-over");
    });
    uploadArea.addEventListener("dragover", function (e) {
        e.preventDefault();
        uploadArea.classList.add("drag-over");
    });
    uploadArea.addEventListener("dragleave", function (e) {
        e.preventDefault();
        uploadArea.classList.remove("drag-over");
    });
    uploadArea.addEventListener("drop", function (e) {
        e.preventDefault();
        uploadArea.classList.remove("drag-over");
        addFiles(e.dataTransfer.files);
    });

    fileInput.addEventListener("change", function () {
        addFiles(fileInput.files);
        fileInput.value = "";
    });

    function addFiles(fileListObj) {
        for (var i = 0; i < fileListObj.length; i++) {
            if (selectedFiles.length >= MAX_FILES) break;
            /* prevent duplicates by name+size */
            var dup = false;
            for (var j = 0; j < selectedFiles.length; j++) {
                if (selectedFiles[j].name === fileListObj[i].name &&
                    selectedFiles[j].size === fileListObj[i].size) {
                    dup = true;
                    break;
                }
            }
            if (!dup) selectedFiles.push(fileListObj[i]);
        }
        renderFileList();
    }

    function renderFileList() {
        clearChildren(fileList);
        selectedFiles.forEach(function (file, idx) {
            var item = document.createElement("div");
            item.className = "file-list-item";

            var nameSpan = document.createElement("span");
            nameSpan.className = "file-name";
            nameSpan.textContent = file.name;

            var sizeSpan = document.createElement("span");
            sizeSpan.className = "file-size";
            sizeSpan.textContent = formatBytes(file.size);

            var ext = getFileExtension(file.name);
            var typeSpan = document.createElement("span");
            typeSpan.className = "file-size";
            if (SIGN_EXTENSIONS.indexOf(ext) !== -1) {
                typeSpan.textContent = "(Authenticode)";
            } else {
                typeSpan.textContent = "(Detached CMS)";
            }

            var removeBtn = document.createElement("button");
            removeBtn.className = "file-remove";
            removeBtn.textContent = "\u00d7";
            removeBtn.title = "Remove";
            removeBtn.setAttribute("data-idx", String(idx));
            removeBtn.addEventListener("click", function () {
                var removeIdx = parseInt(this.getAttribute("data-idx"), 10);
                selectedFiles.splice(removeIdx, 1);
                renderFileList();
            });

            item.appendChild(nameSpan);
            item.appendChild(typeSpan);
            item.appendChild(sizeSpan);
            item.appendChild(removeBtn);
            fileList.appendChild(item);
        });

        if (fileCount) {
            fileCount.textContent = selectedFiles.length > 0
                ? selectedFiles.length + " of " + MAX_FILES + " files selected"
                : "";
        }
        if (submitBtn) {
            submitBtn.disabled = selectedFiles.length === 0;
        }
    }
}

/* ─── Sign Form Submit ──────────────────────────────────────────────── */

function initSignForm() {
    var form = document.getElementById("sign-form");
    if (!form) return;

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        if (selectedFiles.length === 0) return;

        var spinner = document.getElementById("spinner-overlay");
        var spinnerText = document.getElementById("spinner-text");
        var responseDiv = document.getElementById("response-content");
        var submitBtn = document.getElementById("sign-submit-btn");

        clearChildren(responseDiv);
        if (spinner) spinner.classList.add("visible");
        if (spinnerText) spinnerText.textContent = "Signing " + selectedFiles.length + " file(s)...";
        if (submitBtn) submitBtn.disabled = true;

        var formData = new FormData();
        for (var i = 0; i < selectedFiles.length; i++) {
            formData.append("file", selectedFiles[i]);
        }
        var certSelect = document.getElementById("sign-cert-select");
        if (certSelect && certSelect.value) {
            formData.append("cert_type", certSelect.value);
        }

        fetch("/api/v1/sign-batch", { method: "POST", body: formData })
            .then(function (res) {
                if (!res.ok) {
                    return res.json().then(function (err) {
                        throw new Error(err.message || err.error || "Batch signing failed");
                    });
                }
                var totalFiles = res.headers.get("X-PKI-Sign-Files-Total") || "?";
                var signedFiles = res.headers.get("X-PKI-Sign-Files-Signed") || "?";
                var durationMs = res.headers.get("X-PKI-Sign-Duration-Ms") || "?";
                return res.blob().then(function (blob) {
                    return {
                        blob: blob,
                        totalFiles: totalFiles,
                        signedFiles: signedFiles,
                        durationMs: durationMs
                    };
                });
            })
            .then(function (result) {
                if (spinner) spinner.classList.remove("visible");
                if (submitBtn) submitBtn.disabled = false;

                var card = document.createElement("div");
                card.className = "result-card result-batch";

                var h4 = document.createElement("h4");
                h4.textContent = "Batch Signing Complete";
                card.appendChild(h4);

                card.appendChild(createResultRow("Files Processed", result.totalFiles));
                card.appendChild(createResultRow("Files Signed", result.signedFiles));
                card.appendChild(createResultRow("Duration", result.durationMs + " ms"));
                card.appendChild(createResultRow("Archive Size", formatBytes(result.blob.size)));

                var dlUrl = URL.createObjectURL(result.blob);
                var dlWrapper = document.createElement("div");
                dlWrapper.style.marginTop = "0.75rem";
                var dlLink = document.createElement("a");
                dlLink.href = dlUrl;
                dlLink.download = "signed_files.zip";
                dlLink.className = "btn primary";
                dlLink.textContent = "Download Signed Files (ZIP)";
                dlWrapper.appendChild(dlLink);
                card.appendChild(dlWrapper);

                var hint = document.createElement("div");
                hint.className = "file-upload-hint";
                hint.style.marginTop = "0.5rem";
                hint.textContent = "ZIP contains signed files with signed_ prefix and signing_summary.csv";
                card.appendChild(hint);

                responseDiv.appendChild(card);
            })
            .catch(function (err) {
                if (spinner) spinner.classList.remove("visible");
                if (submitBtn) submitBtn.disabled = false;

                var card = document.createElement("div");
                card.className = "result-card result-error";
                var h4 = document.createElement("h4");
                h4.textContent = "Batch Signing Failed";
                card.appendChild(h4);
                card.appendChild(createResultRow("Error", err.message));
                responseDiv.appendChild(card);
            });
    });
}

/* ─── Certificate Dropdown ──────────────────────────────────────────── */

/**
 * Format a cert config name like "desktop_rsa2048" into a readable label
 * like "Desktop RSA-2048".
 */
function formatCertLabel(name) {
    var algoMap = {
        "rsa2048": "RSA-2048",
        "rsa3072": "RSA-3072",
        "rsa4096": "RSA-4096",
        "p256": "ECDSA P-256",
        "p384": "ECDSA P-384"
    };
    var typeMap = {
        "desktop": "Desktop",
        "server": "Server",
        "multipurpose": "Multipurpose"
    };

    /* Try to split on underscore: type_algo */
    var parts = name.split("_");
    if (parts.length >= 2) {
        var typeName = parts[0].toLowerCase();
        var algoName = parts.slice(1).join("_").toLowerCase();
        var typeLabel = typeMap[typeName] || parts[0];
        var algoLabel = algoMap[algoName] || parts.slice(1).join("_");
        return typeLabel + " " + algoLabel;
    }
    /* Fallback: capitalize first letter */
    return name.charAt(0).toUpperCase() + name.slice(1);
}

/**
 * Extract the category prefix from a cert name (e.g., "desktop" from "desktop_rsa2048").
 * Returns the capitalized category or "Other" if no underscore.
 */
function certCategory(name) {
    var typeMap = {
        "desktop": "Desktop",
        "server": "Server",
        "multipurpose": "Multipurpose"
    };
    var prefix = name.split("_")[0].toLowerCase();
    return typeMap[prefix] || "Other";
}

function fetchCertificates() {
    fetch("/api/v1/certificate")
        .then(function (res) { return res.json(); })
        .then(function (data) {
            var select = document.getElementById("sign-cert-select");
            if (!select) return;
            clearChildren(select);
            if (data.certificates && data.certificates.length > 0) {
                /* Group certs by category (Desktop, Server, Multipurpose, Other) */
                var groups = {};
                var groupOrder = [];
                data.certificates.forEach(function (cert, idx) {
                    var cat = certCategory(cert.name);
                    if (!groups[cat]) {
                        groups[cat] = [];
                        groupOrder.push(cat);
                    }
                    groups[cat].push({ cert: cert, idx: idx });
                });

                groupOrder.forEach(function (cat) {
                    var optgroup = document.createElement("optgroup");
                    optgroup.label = cat;

                    groups[cat].forEach(function (entry) {
                        var opt = document.createElement("option");
                        opt.value = entry.cert.name;
                        var label = formatCertLabel(entry.cert.name);
                        if (entry.idx === data.default_index) {
                            label += " - Default";
                            opt.selected = true;
                        }
                        opt.textContent = label;
                        optgroup.appendChild(opt);
                    });

                    select.appendChild(optgroup);
                });
            } else {
                var opt = document.createElement("option");
                opt.value = "";
                opt.textContent = "No certificates available";
                select.appendChild(opt);
            }
        })
        .catch(function () {
            var select = document.getElementById("sign-cert-select");
            if (select) {
                clearChildren(select);
                var opt = document.createElement("option");
                opt.value = "";
                opt.textContent = "Failed to load certificates";
                select.appendChild(opt);
            }
        });
}

/* ─── Server Status ─────────────────────────────────────────────────── */

function fetchServerStatus() {
    fetch("/api/v1/status")
        .then(function (res) { return res.json(); })
        .then(function (data) {
            var dot = document.getElementById("status-dot");
            var text = document.getElementById("status-text");
            var version = document.getElementById("status-version");
            var uptime = document.getElementById("status-uptime");
            var signed = document.getElementById("status-signed");
            var footerVersion = document.getElementById("footer-version");
            if (dot) { dot.classList.add("online"); dot.classList.remove("offline"); }
            if (text) text.textContent = "Server Online";
            if (version) version.textContent = "v" + data.version;
            if (uptime) uptime.textContent = "Uptime: " + formatUptime(data.uptime_seconds);
            if (signed) signed.textContent = "Files signed: " + data.files_signed;
            if (footerVersion) footerVersion.textContent = data.version;
        })
        .catch(function () {
            var dot = document.getElementById("status-dot");
            var text = document.getElementById("status-text");
            if (dot) { dot.classList.remove("online"); dot.classList.add("offline"); }
            if (text) text.textContent = "Server Offline";
        });
}

/* ─── Drop Zone Setup (for verify page) ─────────────────────────────── */

function initDropZone(dropZoneId, inputId, nameDisplayId, onFileSelected) {
    var zone = document.getElementById(dropZoneId);
    var input = document.getElementById(inputId);
    var nameEl = document.getElementById(nameDisplayId);
    if (!zone || !input) return;

    zone.addEventListener("dragenter", function (e) { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragover", function (e) { e.preventDefault(); zone.classList.add("drag-over"); });
    zone.addEventListener("dragleave", function (e) { e.preventDefault(); zone.classList.remove("drag-over"); });
    zone.addEventListener("drop", function (e) {
        e.preventDefault();
        zone.classList.remove("drag-over");
        if (e.dataTransfer.files.length > 0) {
            input.files = e.dataTransfer.files;
            handleFileSelected(zone, nameEl, input.files[0], onFileSelected);
        }
    });
    input.addEventListener("change", function () {
        if (input.files.length > 0) handleFileSelected(zone, nameEl, input.files[0], onFileSelected);
    });
    zone.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
}

function handleFileSelected(zone, nameEl, file, callback) {
    zone.classList.add("has-file");
    if (nameEl) nameEl.textContent = file.name + " (" + formatBytes(file.size) + ")";
    if (callback) callback(file);
}

/* ─── Verify Forms ──────────────────────────────────────────────────── */

function initVerifyForm() {
    var form = document.getElementById("verify-form");
    var btn = document.getElementById("verify-submit-btn");
    var input = document.getElementById("verify-file-input");
    if (!form) return;

    initDropZone("verify-drop-zone", "verify-file-input", "verify-file-name", function () {
        if (btn) btn.disabled = false;
    });

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        if (!input.files || input.files.length === 0) return;

        var progress = document.getElementById("verify-progress");
        var result = document.getElementById("verify-result");
        var resultTitle = document.getElementById("verify-result-title");
        var resultBody = document.getElementById("verify-result-body");

        showPanel(result, false);
        showProgress(progress, true);
        btn.disabled = true;

        var formData = new FormData();
        formData.append("file", input.files[0]);

        fetch("/api/v1/verify", { method: "POST", body: formData })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                showProgress(progress, false);
                btn.disabled = false;
                var isValid = data.valid || data.signature_valid;
                result.className = "result-panel visible " + (isValid ? "result-success" : "result-error");
                resultTitle.textContent = isValid ? "Signature Valid" : "Signature Invalid";
                clearChildren(resultBody);
                if (isValid) {
                    resultBody.appendChild(createResultRowWithBadge("Status", "VALID", "badge-success"));
                } else {
                    resultBody.appendChild(createResultRowWithBadge("Status", "INVALID", "badge-error"));
                }
                if (data.signer_subject) resultBody.appendChild(createResultRow("Signer", data.signer_subject));
                if (data.signer_issuer) resultBody.appendChild(createResultRow("Issuer", data.signer_issuer));
                if (data.algorithm) resultBody.appendChild(createResultRow("Algorithm", data.algorithm));
                if (data.digest_algorithm) resultBody.appendChild(createResultRow("Digest", data.digest_algorithm));
                if (data.timestamp_time) resultBody.appendChild(createResultRow("Timestamp", data.timestamp_time));
                if (data.computed_digest) resultBody.appendChild(createResultRow("Computed Hash", data.computed_digest));
                if (data.message) resultBody.appendChild(createResultRow("Details", data.message));
                if (data.error) resultBody.appendChild(createResultRow("Error", data.error));
            })
            .catch(function (err) {
                showProgress(progress, false);
                btn.disabled = false;
                result.className = "result-panel visible result-error";
                resultTitle.textContent = "Verification Failed";
                clearChildren(resultBody);
                resultBody.appendChild(createResultRow("Error", err.message));
            });
    });
}

function initVerifyDetachForm() {
    var form = document.getElementById("verify-detach-form");
    var btn = document.getElementById("verify-detach-submit-btn");
    var fileInput = document.getElementById("verify-detach-file-input");
    var sigInput = document.getElementById("verify-detach-sig-input");
    if (!form) return;

    var hasFile = false;
    var hasSig = false;
    function checkReady() { btn.disabled = !(hasFile && hasSig); }

    initDropZone("verify-detach-file-drop", "verify-detach-file-input", "verify-detach-file-name", function () {
        hasFile = true; checkReady();
    });
    initDropZone("verify-detach-sig-drop", "verify-detach-sig-input", "verify-detach-sig-name", function () {
        hasSig = true; checkReady();
    });

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        if (!fileInput.files[0] || !sigInput.files[0]) return;

        var progress = document.getElementById("verify-detach-progress");
        var result = document.getElementById("verify-detach-result");
        var resultTitle = document.getElementById("verify-detach-result-title");
        var resultBody = document.getElementById("verify-detach-result-body");

        showPanel(result, false);
        showProgress(progress, true);
        btn.disabled = true;

        var formData = new FormData();
        formData.append("file", fileInput.files[0]);
        formData.append("signature", sigInput.files[0]);

        fetch("/api/v1/verify-detached", { method: "POST", body: formData })
            .then(function (res) { return res.json(); })
            .then(function (data) {
                showProgress(progress, false);
                btn.disabled = false;
                var isValid = data.valid || data.signature_valid;
                result.className = "result-panel visible " + (isValid ? "result-success" : "result-error");
                resultTitle.textContent = isValid ? "Detached Signature Valid" : "Detached Signature Invalid";
                clearChildren(resultBody);
                if (isValid) {
                    resultBody.appendChild(createResultRowWithBadge("Status", "VALID", "badge-success"));
                } else {
                    resultBody.appendChild(createResultRowWithBadge("Status", "INVALID", "badge-error"));
                }
                if (data.signer_subject) resultBody.appendChild(createResultRow("Signer", data.signer_subject));
                if (data.algorithm) resultBody.appendChild(createResultRow("Algorithm", data.algorithm));
                if (data.message) resultBody.appendChild(createResultRow("Details", data.message));
                if (data.error) resultBody.appendChild(createResultRow("Error", data.error));
            })
            .catch(function (err) {
                showProgress(progress, false);
                btn.disabled = false;
                result.className = "result-panel visible result-error";
                resultTitle.textContent = "Verification Failed";
                clearChildren(resultBody);
                resultBody.appendChild(createResultRow("Error", err.message));
            });
    });
}

/* ─── Admin: Statistics ─────────────────────────────────────────────── */

function loadAdminStats() {
    fetch("/admin/stats")
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function (data) {
            setStatText("stat-uptime", formatUptime(data.uptime_seconds || 0));
            setStatText("stat-files-signed", String(data.files_signed || 0));
            setStatText("stat-files-verified", String(data.files_verified || 0));
            setStatText("stat-bytes-signed", formatBytes(data.bytes_signed || 0));
            setStatText("stat-sign-errors", String(data.sign_errors || 0));
            var avg = "--";
            if (data.files_signed > 0 && data.total_sign_duration_ms !== undefined) {
                avg = Math.round(data.total_sign_duration_ms / data.files_signed) + " ms";
            } else if (data.average_sign_duration_ms !== undefined) {
                avg = data.average_sign_duration_ms + " ms";
            }
            setStatText("stat-avg-duration", avg);
            hideAlert(document.getElementById("stats-error"));
        })
        .catch(function (err) {
            var el = document.getElementById("stats-error");
            if (el) showAlert(el, "Failed to load stats: " + err.message, "error");
        });
}

function setStatText(id, value) {
    var el = document.getElementById(id);
    if (el) el.textContent = value;
}

/* ─── Admin: Certificates (clickable with openssl-style detail) ──── */

var adminCertsData = [];

function loadAdminCerts() {
    fetch("/admin/certs")
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function (data) {
            var tbody = document.getElementById("certs-tbody");
            if (!tbody) return;

            var certs = data.certificates || data;
            adminCertsData = certs;
            clearChildren(tbody);

            if (!Array.isArray(certs) || certs.length === 0) {
                var emptyRow = document.createElement("tr");
                var emptyCell = document.createElement("td");
                emptyCell.colSpan = 5;
                emptyCell.className = "text-center text-muted";
                emptyCell.textContent = "No certificates loaded";
                emptyRow.appendChild(emptyCell);
                tbody.appendChild(emptyRow);
                return;
            }

            certs.forEach(function (cert, idx) {
                var fp = cert.fingerprint_sha256 || "--";
                var shortFp = fp.length > 20 ? fp.substring(0, 20) + "..." : fp;

                var tr = document.createElement("tr");
                tr.className = "clickable";
                tr.setAttribute("data-cert-name", cert.name || "");
                tr.addEventListener("click", function (e) {
                    if (e.target.tagName === "BUTTON") return;
                    showCertDetail(this.getAttribute("data-cert-name"));
                });

                var tdName = document.createElement("td");
                tdName.textContent = cert.name || "--";
                tdName.style.fontWeight = "600";
                tr.appendChild(tdName);

                var tdSubject = document.createElement("td");
                tdSubject.textContent = cert.subject || "--";
                tdSubject.style.fontSize = "0.8rem";
                tr.appendChild(tdSubject);

                var tdFp = document.createElement("td");
                tdFp.className = "mono";
                tdFp.title = fp;
                tdFp.textContent = shortFp;
                tr.appendChild(tdFp);

                var tdStatus = document.createElement("td");
                var badge = document.createElement("span");
                if (cert.is_default) {
                    badge.className = "badge badge-default";
                    badge.textContent = "DEFAULT";
                } else {
                    badge.className = "badge badge-info";
                    badge.textContent = "LOADED";
                }
                tdStatus.appendChild(badge);
                tr.appendChild(tdStatus);

                var tdAction = document.createElement("td");
                if (!cert.is_default) {
                    var actionBtn = document.createElement("button");
                    actionBtn.className = "btn btn-sm btn-secondary";
                    actionBtn.textContent = "Set Default";
                    actionBtn.setAttribute("data-cert-name", cert.name);
                    actionBtn.addEventListener("click", function (e) {
                        e.stopPropagation();
                        setDefaultCert(this.getAttribute("data-cert-name"));
                    });
                    tdAction.appendChild(actionBtn);
                }
                tr.appendChild(tdAction);

                tbody.appendChild(tr);
            });

            hideAlert(document.getElementById("certs-error"));
        })
        .catch(function (err) {
            var el = document.getElementById("certs-error");
            if (el) showAlert(el, "Failed to load certificates: " + err.message, "error");
        });
}

function showCertDetail(certName) {
    var overlay = document.getElementById("cert-detail-overlay");
    var title = document.getElementById("cert-detail-title");
    var body = document.getElementById("cert-detail-body");
    if (!overlay || !body) return;

    title.textContent = "Certificate: " + certName;
    body.textContent = "Loading...";
    overlay.classList.add("visible");

    fetch("/admin/certs/" + encodeURIComponent(certName))
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function (cert) {
            clearChildren(body);

            var fields = [
                ["Name", cert.name],
                ["Subject", cert.subject],
                ["Issuer", cert.issuer],
                ["Serial Number", cert.serial_number],
                ["Not Before", cert.not_before],
                ["Not After", cert.not_after],
                ["Fingerprint (SHA-256)", cert.fingerprint_sha256],
                ["Key Usage", cert.key_usage],
                ["Extended Key Usage", cert.extended_key_usage],
                ["Chain Length", cert.chain_length],
                ["DER Size (bytes)", cert.cert_size_bytes],
                ["Default Certificate", cert.is_default ? "Yes" : "No"]
            ];

            fields.forEach(function (pair) {
                var fieldDiv = document.createElement("div");
                fieldDiv.className = "cert-field";

                var labelEl = document.createElement("span");
                labelEl.className = "cert-field-label";
                labelEl.textContent = pair[0];
                fieldDiv.appendChild(labelEl);

                var valueEl = document.createElement("span");
                valueEl.className = "cert-field-value";
                var val = pair[1];
                if (val === null || val === undefined) val = "(not available)";
                valueEl.textContent = String(val);
                fieldDiv.appendChild(valueEl);

                body.appendChild(fieldDiv);
            });
        })
        .catch(function (err) {
            body.textContent = "Error loading certificate: " + err.message;
        });
}

function initCertDetailOverlay() {
    var overlay = document.getElementById("cert-detail-overlay");
    var closeBtn = document.getElementById("cert-detail-close");
    if (!overlay) return;

    if (closeBtn) {
        closeBtn.addEventListener("click", function () {
            overlay.classList.remove("visible");
        });
    }
    overlay.addEventListener("click", function (e) {
        if (e.target === overlay) overlay.classList.remove("visible");
    });
}

function setDefaultCert(name) {
    fetch("/admin/certs/" + encodeURIComponent(name) + "/default", { method: "POST" })
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function () { loadAdminCerts(); })
        .catch(function (err) {
            var el = document.getElementById("certs-error");
            if (el) showAlert(el, "Failed to set default: " + err.message, "error");
        });
}

function reloadCerts() {
    fetch("/admin/reload", { method: "POST" })
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function () {
            loadAdminCerts();
            var el = document.getElementById("certs-error");
            if (el) showAlert(el, "Certificates reloaded successfully.", "success");
        })
        .catch(function (err) {
            var el = document.getElementById("certs-error");
            if (el) showAlert(el, "Reload failed: " + err.message, "error");
        });
}

/* ─── Admin: Audit Log ──────────────────────────────────────────────── */

function loadAdminAudit() {
    fetch("/admin/audit")
        .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.json();
        })
        .then(function (data) {
            var tbody = document.getElementById("audit-tbody");
            if (!tbody) return;

            var entries = data.entries || data;
            clearChildren(tbody);

            if (!Array.isArray(entries) || entries.length === 0) {
                var emptyRow = document.createElement("tr");
                var emptyCell = document.createElement("td");
                emptyCell.colSpan = 5;
                emptyCell.className = "text-center text-muted";
                emptyCell.textContent = "No audit entries yet";
                emptyRow.appendChild(emptyCell);
                tbody.appendChild(emptyRow);
                return;
            }

            /* Show newest first */
            entries.reverse().forEach(function (entry) {
                var status = entry.status || "--";
                var statusLower = status.toLowerCase();
                var badgeClass = "badge-info";
                if (statusLower === "success" || statusLower === "ok") badgeClass = "badge-success";
                else if (statusLower === "error" || statusLower === "failed") badgeClass = "badge-error";

                var tr = document.createElement("tr");

                var tdTime = document.createElement("td");
                var ts = entry.timestamp || "--";
                /* Show a friendlier timestamp */
                if (ts !== "--") {
                    try {
                        var d = new Date(ts);
                        ts = d.toLocaleString();
                    } catch (ignored) {}
                }
                tdTime.textContent = ts;
                tdTime.style.fontSize = "0.8rem";
                tr.appendChild(tdTime);

                var tdAction = document.createElement("td");
                tdAction.textContent = entry.action || "--";
                tr.appendChild(tdAction);

                var tdFile = document.createElement("td");
                tdFile.textContent = entry.filename || "--";
                tr.appendChild(tdFile);

                var tdStatus = document.createElement("td");
                var badge = document.createElement("span");
                badge.className = "badge " + badgeClass;
                badge.textContent = status;
                tdStatus.appendChild(badge);
                tr.appendChild(tdStatus);

                var tdDur = document.createElement("td");
                tdDur.textContent = entry.duration_ms !== undefined ? entry.duration_ms + " ms" : "--";
                tr.appendChild(tdDur);

                tbody.appendChild(tr);
            });

            hideAlert(document.getElementById("audit-error"));
        })
        .catch(function (err) {
            var el = document.getElementById("audit-error");
            if (el) showAlert(el, "Failed to load audit log: " + err.message, "error");
        });
}

/* ─── Admin: Load All Data ──────────────────────────────────────────── */

function loadAdminData() {
    loadAdminStats();
    loadAdminCerts();
    loadAdminAudit();
}

/* ─── Initialization ────────────────────────────────────────────────── */

function initPage() {
    fetchServerStatus();

    /* Sign page */
    initTosScroll();
    initFileUpload();
    initSignForm();
    fetchCertificates();

    /* Verify page */
    initVerifyForm();
    initVerifyDetachForm();

    /* Admin page */
    initCertDetailOverlay();

    if (document.getElementById("stats-card")) {
        loadAdminData();

        var refreshStatsBtn = document.getElementById("refresh-stats-btn");
        if (refreshStatsBtn) refreshStatsBtn.addEventListener("click", loadAdminStats);

        var refreshAuditBtn = document.getElementById("refresh-audit-btn");
        if (refreshAuditBtn) refreshAuditBtn.addEventListener("click", loadAdminAudit);

        var reloadCertsBtn = document.getElementById("reload-certs-btn");
        if (reloadCertsBtn) reloadCertsBtn.addEventListener("click", reloadCerts);

        setInterval(loadAdminStats, 30000);
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPage);
} else {
    initPage();
}
