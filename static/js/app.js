/**
 * PhishGuard: Threat Intelligence & Phishing Analysis Engine
 * Frontend Controller (Zero Autoload on Startup, Clean Dual-Perspective Views)
 */

let currentAnalysisResult = null;
let currentMode = "email";
let currentAudienceView = "user"; // "user" or "analyst"
let selectedFile = null;

document.addEventListener("DOMContentLoaded", async () => {
    // Populate preset scenario dropdown without auto-loading any text or running analysis
    await loadSamplesList();

    // Setup live character/line counter
    const emailInput = document.getElementById("emailInput");
    if (emailInput) {
        emailInput.addEventListener("input", updateInputStats);
    }

    // Setup drag and drop for file upload
    setupDropZone();
});

// Update live character and line counts
function updateInputStats() {
    const text = document.getElementById("emailInput").value;
    const chars = text.length;
    const lines = text ? text.split(/\r\n|\r|\n/).length : 0;
    const statsEl = document.getElementById("inputStats");
    if (statsEl) {
        statsEl.textContent = `${chars.toLocaleString()} chars • ${lines.toLocaleString()} lines`;
    }
}

// Mode Switching (Email Inspector, Standalone URL, File Upload)
function switchMode(mode) {
    currentMode = mode;
    const tabEmail = document.getElementById("tabEmail");
    const tabUrl = document.getElementById("tabUrl");
    const tabUpload = document.getElementById("tabUpload");

    const emailControls = document.getElementById("emailControls");
    const urlControls = document.getElementById("urlControls");
    const uploadControls = document.getElementById("uploadControls");

    tabEmail.classList.remove("active");
    tabUrl.classList.remove("active");
    tabUpload.classList.remove("active");

    emailControls.style.display = "none";
    urlControls.style.display = "none";
    uploadControls.style.display = "none";

    if (mode === "email") {
        tabEmail.classList.add("active");
        emailControls.style.display = "block";
    } else if (mode === "url") {
        tabUrl.classList.add("active");
        urlControls.style.display = "block";
    } else if (mode === "upload") {
        tabUpload.classList.add("active");
        uploadControls.style.display = "block";
    }
}

// Audience View Switching (General User vs SOC Forensics)
function switchAudienceView(view) {
    currentAudienceView = view;
    const btnUser = document.getElementById("btnUserView");
    const btnAnalyst = document.getElementById("btnAnalystView");
    const userSection = document.getElementById("userViewSection");
    const analystSection = document.getElementById("analystViewSection");

    if (view === "user") {
        btnUser.classList.add("active");
        btnAnalyst.classList.remove("active");
        userSection.style.display = "block";
        analystSection.style.display = "none";
    } else {
        btnAnalyst.classList.add("active");
        btnUser.classList.remove("active");
        userSection.style.display = "none";
        analystSection.style.display = "block";
    }
}

// Populate sample selector dropdown without loading or auto-running
async function loadSamplesList() {
    try {
        const res = await fetch("/api/samples");
        const data = await res.json();
        const select = document.getElementById("sampleSelect");

        if (data.samples && data.samples.length > 0) {
            select.innerHTML = '<option value="">-- Choose a test scenario to inspect --</option>';
            data.samples.forEach(s => {
                const opt = document.createElement("option");
                opt.value = s.filename;
                opt.textContent = `[${s.type.toUpperCase()}] ${s.title}`;
                select.appendChild(opt);
            });
        }
    } catch (err) {
        console.error("Failed to load scenario list:", err);
    }
}

// Explicit load of chosen scenario into textarea ONLY when user clicks 'Load Scenario'
async function loadSelectedSample() {
    const select = document.getElementById("sampleSelect");
    const filename = select.value;
    if (!filename) {
        alert("Please select a scenario from the dropdown first.");
        return;
    }

    try {
        const res = await fetch(`/api/sample/${encodeURIComponent(filename)}`);
        const data = await res.json();
        if (data.content) {
            document.getElementById("emailInput").value = data.content;
            updateInputStats();
            // Note: Does NOT automatically analyze. User must click "Run Threat Inspection"
        }
    } catch (err) {
        alert("Failed to load scenario: " + err.message);
    }
}

function clearEmailInput() {
    document.getElementById("emailInput").value = "";
    document.getElementById("sampleSelect").value = "";
    updateInputStats();
}

function setTestUrl(url) {
    document.getElementById("urlInput").value = url;
}

// Setup drag and drop for .eml upload
function setupDropZone() {
    const dropZone = document.getElementById("dropZone");
    if (!dropZone) return;

    ["dragenter", "dragover"].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(name => {
        dropZone.addEventListener(name, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", (e) => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            handleSingleFile(files[0]);
        }
    });
}

function handleFileSelected(event) {
    const files = event.target.files;
    if (files && files.length > 0) {
        handleSingleFile(files[0]);
    }
}

function handleSingleFile(file) {
    selectedFile = file;
    const statusBox = document.getElementById("uploadStatus");
    const nameEl = document.getElementById("uploadFileName");
    if (statusBox && nameEl) {
        nameEl.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        statusBox.style.display = "flex";
    }
}

async function uploadAndAnalyze() {
    if (!selectedFile) {
        alert("Please select or drop a file first.");
        return;
    }

    const btn = document.getElementById("btnExecuteUpload");
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = "Processing File...";

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
        const res = await fetch("/api/upload-eml", {
            method: "POST",
            body: formData
        });
        const data = await res.json();

        if (res.ok) {
            currentAnalysisResult = { mode: "email", data: data };
            renderAllResults(data, "email");
        } else {
            alert(data.error || "File inspection error occurred.");
        }
    } catch (err) {
        alert("Upload failed: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// Run Email Analysis
async function analyzeEmail() {
    const emailText = document.getElementById("emailInput").value;
    if (!emailText.trim()) {
        alert("Please enter email content or load a scenario first.");
        return;
    }

    const btn = document.getElementById("btnAnalyzeEmail");
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = "Executing Static Heuristics...";

    try {
        const res = await fetch("/api/analyze-email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: emailText })
        });
        const data = await res.json();

        if (res.ok) {
            currentAnalysisResult = { mode: "email", data: data };
            renderAllResults(data, "email");
        } else {
            alert(data.error || "Analysis error occurred.");
        }
    } catch (err) {
        alert("Request error: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// Run URL Analysis
async function analyzeUrl() {
    const targetUrl = document.getElementById("urlInput").value;
    if (!targetUrl.trim()) {
        alert("Please enter a target URL to evaluate.");
        return;
    }

    const btn = document.getElementById("btnAnalyzeUrl");
    const origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = "Scanning Lexical Vectors...";

    try {
        const res = await fetch("/api/analyze-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetUrl.trim() })
        });
        const data = await res.json();

        if (res.ok) {
            // Adapt URL response structure into unified schema
            const unifiedData = adaptUrlDataToReport(data);
            currentAnalysisResult = { mode: "url", data: unifiedData };
            renderAllResults(unifiedData, "url");
        } else {
            alert(data.error || "URL Analysis failed.");
        }
    } catch (err) {
        alert("Request error: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// Adapter function to map standalone URL scan to dual-perspective report structure
function adaptUrlDataToReport(urlData) {
    const score = urlData.score;
    let risk_color = "#10B981";
    let classification = "Benign / Verified URL Endpoint";

    if (score >= 80) {
        risk_color = "#EF4444";
        classification = "Weaponized Phishing Landing Target / Malicious Host";
    } else if (score >= 56) {
        risk_color = "#F97316";
        classification = "Deceptive Brand Impersonation / Typosquatting Target";
    } else if (score >= 26) {
        risk_color = "#F59E0B";
        classification = "Suspicious URL Parameter / Atypical Infrastructure";
    }

    // General user view for URL
    let userHeading = "Safe Link Destination";
    let userDesc = "This link conforms to standard domain conventions. No malicious impersonation was detected.";
    let userBadge = "VERIFIED SAFE";
    let userBadgeColor = "#10B981";

    if (score >= 56) {
        userHeading = "DO NOT CLICK: Malicious Link Detected";
        userDesc = `This URL mimics or exploits '${urlData.registered_domain}'. Entering passwords on this page will expose your account credentials.`;
        userBadge = "DANGEROUS LINK";
        userBadgeColor = "#EF4444";
    } else if (score >= 26) {
        userHeading = "Exercise Caution with this Link";
        userDesc = `This link exhibits unusual characteristics (${urlData.registered_domain}). Verify the destination before logging in.`;
        userBadge = "CAUTION ADVISED";
        userBadgeColor = "#F59E0B";
    }

    const red_flags = [];
    urlData.findings.forEach(f => {
        red_flags.push({
            title: f.rule.replace("URL_", "").replace(/_/g, " "),
            severity: f.severity,
            explanation: f.explanation
        });
    });

    return {
        score: score,
        risk_level: urlData.risk_level,
        risk_color: risk_color,
        threat_classification: classification,
        header_score: 0,
        body_score: 0,
        url_score: score,
        findings_count: urlData.findings.length,
        findings: urlData.findings,
        mitre_techniques: urlData.findings.map(f => f.mitre).filter(Boolean),
        urls: [urlData],
        iocs: {
            domains: urlData.registered_domain ? [urlData.defanged_domain || urlData.registered_domain] : [],
            ips: urlData.is_ip ? [urlData.defanged_host || urlData.host] : [],
            urls: [urlData.defanged_url || urlData.url]
        },
        subject: `Target URL: ${urlData.url}`,
        from: "Direct Endpoint Submission",
        header_details: {
            from: "N/A (Standalone URL Scan)",
            display_name: "N/A",
            from_domain: "N/A",
            return_path: "N/A",
            return_path_domain: "N/A",
            reply_to: "N/A",
            reply_to_domain: "N/A",
            spf_status: "NONE",
            dkim_status: "NONE",
            dmarc_status: "NONE"
        },
        general_user_view: {
            verdict_badge: userBadge,
            verdict_color: userBadgeColor,
            verdict_heading: userHeading,
            verdict_desc: userDesc,
            red_flags: red_flags,
            safety_actions: [
                "Do not open this URL in a browser or submit credentials.",
                "Verify the domain directly through an official bookmark or search engine.",
                "Submit suspicious URLs to your security team for perimeter blocklisting."
            ],
            user_links: [{
                url: urlData.url,
                domain: urlData.registered_domain,
                risk_level: urlData.risk_level,
                verdict: urlData.user_verdict || "Evaluated standalone endpoint."
            }]
        },
        soc_playbook: [
            score >= 56 ? "PERIMETER BLOCK: Push URL and host IP to corporate proxy and edge firewalls." : "MONITOR: Log endpoint query; no immediate block required.",
            "EDR HUNT: Query SIEM logs for DNS requests resolving to this domain across all endpoints."
        ],
        disclaimer: urlData.disclaimer || ""
    };
}

// Master Render Pipeline
function renderAllResults(data, mode) {
    // Hide empty standby screen and display report container
    const emptyState = document.getElementById("emptyStandbyState");
    const reportContainer = document.getElementById("reportContainer");
    if (emptyState) emptyState.style.display = "none";
    if (reportContainer) reportContainer.style.display = "block";

    // 1. Render Top Score Banner
    const scoreVal = document.getElementById("scoreValue");
    const riskBadge = document.getElementById("riskBadge");
    const scoreSummary = document.getElementById("scoreSummary");
    const scoreBanner = document.getElementById("scoreBanner");

    scoreVal.textContent = data.score;
    riskBadge.textContent = `${data.risk_level} RISK`;
    riskBadge.style.backgroundColor = `${data.risk_color}22`;
    riskBadge.style.color = data.risk_color;
    riskBadge.style.border = `1px solid ${data.risk_color}55`;

    scoreBanner.style.borderLeftColor = data.risk_color;
    scoreSummary.textContent = data.threat_classification;

    // 2. Render General User View
    renderGeneralUserView(data.general_user_view);

    // 3. Render SOC Forensics View
    renderSocAnalystView(data);
}

// Render General User View
function renderGeneralUserView(userView) {
    if (!userView) return;

    const heading = document.getElementById("userVerdictHeading");
    const desc = document.getElementById("userVerdictDesc");
    const verdictCard = document.getElementById("userVerdictCard");

    heading.textContent = userView.verdict_heading;
    desc.textContent = userView.verdict_desc;
    verdictCard.style.borderLeft = `4px solid ${userView.verdict_color}`;

    // Red Flags Grid
    const flagsGrid = document.getElementById("userRedFlagsGrid");
    flagsGrid.innerHTML = "";

    if (!userView.red_flags || userView.red_flags.length === 0) {
        flagsGrid.innerHTML = `
            <div class="red-flag-card" style="border-left-color: var(--color-low);">
                <div class="flag-title">No Red Flags Found</div>
                <div class="flag-explanation">All checks conformed to verified, legitimate communication standards.</div>
            </div>
        `;
    } else {
        userView.red_flags.forEach(f => {
            let color = "var(--color-critical)";
            if (f.severity === "HIGH") color = "var(--color-high)";
            if (f.severity === "MEDIUM") color = "var(--color-medium)";

            const card = document.createElement("div");
            card.className = "red-flag-card";
            card.style.borderLeftColor = color;
            card.innerHTML = `
                <div class="flag-header">
                    <span class="flag-title">${escapeHtml(f.title)}</span>
                    <span class="flag-sev" style="background:${color}22; color:${color}; border:1px solid ${color}44;">${f.severity}</span>
                </div>
                <div class="flag-explanation">${escapeHtml(f.explanation)}</div>
            `;
            flagsGrid.appendChild(card);
        });
    }

    // Safety Actions List
    const actionsList = document.getElementById("userActionList");
    actionsList.innerHTML = "";
    (userView.safety_actions || []).forEach(action => {
        const li = document.createElement("li");
        li.textContent = action;
        actionsList.appendChild(li);
    });

    // Inspected Links for End User
    const linksBlock = document.getElementById("userLinksBlock");
    const linksTbody = document.getElementById("userLinksTableBody");
    linksTbody.innerHTML = "";

    if (userView.user_links && userView.user_links.length > 0) {
        linksBlock.style.display = "block";
        userView.user_links.forEach(l => {
            let badgeClass = "sev-low";
            if (l.risk_level === "CRITICAL") badgeClass = "sev-critical";
            if (l.risk_level === "HIGH") badgeClass = "sev-high";
            if (l.risk_level === "MEDIUM") badgeClass = "sev-medium";

            const row = document.createElement("tr");
            row.innerHTML = `
                <td style="font-family:var(--font-mono); font-size:0.74rem;">${escapeHtml(l.domain || l.url)}</td>
                <td><span class="sev-badge ${badgeClass}">${l.risk_level}</span></td>
                <td>${escapeHtml(l.verdict)}</td>
            `;
            linksTbody.appendChild(row);
        });
    } else {
        linksBlock.style.display = "none";
    }
}

// Render SOC Forensics View
function renderSocAnalystView(data) {
    // 1. Metric Telemetry Cards
    document.getElementById("metricHeader").textContent = `${data.header_score}/100`;
    document.getElementById("metricBody").textContent = `${data.body_score}/100`;
    document.getElementById("metricUrl").textContent = `${data.url_score}/100`;
    document.getElementById("metricFlags").textContent = data.findings_count;

    // 2. RFC Header Matrix
    const hd = data.header_details || {};
    document.getElementById("rfcFrom").textContent = hd.from || "-";
    document.getElementById("rfcReturnPath").textContent = hd.return_path_domain ? `${hd.return_path_domain} (${hd.return_path_domain === hd.from_domain ? 'Aligned' : 'Mismatch'})` : (hd.return_path || "-");
    document.getElementById("rfcReplyTo").textContent = hd.reply_to_domain ? `${hd.reply_to_domain} (${hd.reply_to_domain === hd.from_domain ? 'Aligned' : 'Divergent'})` : (hd.reply_to || "-");

    renderAuthPill("rfcSpf", hd.spf_status);
    renderAuthPill("rfcDkim", hd.dkim_status);
    renderAuthPill("rfcDmarc", hd.dmarc_status);

    // 3. MITRE ATT&CK Matrix Correlation
    const mitreBlock = document.getElementById("mitreBlock");
    const mitreList = document.getElementById("mitreTagsList");
    const mitreCounter = document.getElementById("mitreCounter");
    mitreList.innerHTML = "";

    if (data.mitre_techniques && data.mitre_techniques.length > 0) {
        mitreBlock.style.display = "block";
        mitreCounter.textContent = data.mitre_techniques.length;
        data.mitre_techniques.forEach(m => {
            const pill = document.createElement("div");
            pill.className = "mitre-pill";
            pill.innerHTML = `
                <span class="mitre-id">${m.id}</span>
                <span class="mitre-name">${m.name}</span>
                <span class="mitre-tactic">${m.tactic}</span>
            `;
            mitreList.appendChild(pill);
        });
    } else {
        mitreBlock.style.display = "none";
    }

    // 4. Detected Threat Indicators Table
    const findingsTbody = document.getElementById("findingsTableBody");
    const findingsCounter = document.getElementById("findingsCounter");
    findingsTbody.innerHTML = "";
    findingsCounter.textContent = data.findings.length;

    if (data.findings.length === 0) {
        findingsTbody.innerHTML = `
            <tr>
                <td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">
                    No anomalous indicators flagged. All heuristics within acceptable baseline.
                </td>
            </tr>
        `;
    } else {
        data.findings.forEach(f => {
            let sevClass = "sev-low";
            if (f.severity === "CRITICAL") sevClass = "sev-critical";
            if (f.severity === "HIGH") sevClass = "sev-high";
            if (f.severity === "MEDIUM") sevClass = "sev-medium";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="sev-badge ${sevClass}">${f.severity}</span></td>
                <td>
                    <div style="font-weight:600; color:var(--text-primary);">${escapeHtml(f.category || '')}</div>
                    <div style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted);">${escapeHtml(f.rule || '')}</div>
                </td>
                <td><span class="weight-pill">+${f.points || 0} pts</span></td>
                <td style="color:var(--text-secondary); line-height:1.4;">${escapeHtml(f.explanation || '')}</td>
            `;
            findingsTbody.appendChild(tr);
        });
    }

    // 5. Extracted Hyperlinks Inspection Table
    const urlsBlock = document.getElementById("extractedUrlsBlock");
    const urlsTbody = document.getElementById("urlsTableBody");
    const urlsCounter = document.getElementById("urlsCounter");
    urlsTbody.innerHTML = "";

    if (data.urls && data.urls.length > 0) {
        urlsBlock.style.display = "block";
        urlsCounter.textContent = data.urls.length;

        data.urls.forEach(u => {
            let sevClass = "sev-low";
            if (u.risk_level === "CRITICAL") sevClass = "sev-critical";
            if (u.risk_level === "HIGH") sevClass = "sev-high";
            if (u.risk_level === "MEDIUM") sevClass = "sev-medium";

            const anomalies = (u.findings || []).map(af => af.rule.replace("URL_", "")).join(", ") || "None";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td style="word-break:break-all; max-width:240px;">${escapeHtml(u.defanged_url || u.url)}</td>
                <td>${escapeHtml(u.defanged_domain || u.registered_domain || '-')}</td>
                <td>${u.entropy !== undefined ? u.entropy : '-'}</td>
                <td><span class="sev-badge ${sevClass}">${u.risk_level}</span></td>
                <td style="color:var(--text-muted);">${escapeHtml(anomalies)}</td>
            `;
            urlsTbody.appendChild(tr);
        });
    } else {
        urlsBlock.style.display = "none";
    }

    // 6. Defanged Indicators of Compromise (IoCs)
    const iocsBox = document.getElementById("iocsContainer");
    const iocs = data.iocs || {};
    let iocHtml = "";

    if (iocs.domains && iocs.domains.length > 0) {
        iocHtml += `<div class="ioc-group"><span class="ioc-tag">[Domains]:</span> ${iocs.domains.map(escapeHtml).join(", ")}</div>`;
    }
    if (iocs.ips && iocs.ips.length > 0) {
        iocHtml += `<div class="ioc-group"><span class="ioc-tag">[IP Addresses]:</span> ${iocs.ips.map(escapeHtml).join(", ")}</div>`;
    }
    if (iocs.urls && iocs.urls.length > 0) {
        iocHtml += `<div class="ioc-group"><span class="ioc-tag">[URLs]:</span><br/>${iocs.urls.map(u => `&bull; ${escapeHtml(u)}`).join("<br/>")}</div>`;
    }

    if (!iocHtml) {
        iocHtml = `<span style="color:var(--text-muted);">No external threat IoCs identified in this artifact.</span>`;
    }
    iocsBox.innerHTML = iocHtml;

    // 7. Blue Team Playbook
    const playbookList = document.getElementById("playbookList");
    playbookList.innerHTML = "";
    (data.soc_playbook || []).forEach(action => {
        const li = document.createElement("li");
        li.textContent = action;
        playbookList.appendChild(li);
    });
}

function renderAuthPill(elementId, status) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const st = (status || "NONE").toUpperCase();
    let pillClass = "pill-none";
    if (st === "PASS") pillClass = "pill-pass";
    if (st === "FAIL") pillClass = "pill-fail";
    if (st === "SOFTFAIL") pillClass = "pill-softfail";

    el.innerHTML = `<span class="auth-pill ${pillClass}">${st}</span>`;
}

// Copy Defanged IoCs
function copyDefangedIocs() {
    if (!currentAnalysisResult || !currentAnalysisResult.data) {
        alert("No active analysis result to copy.");
        return;
    }

    const iocs = currentAnalysisResult.data.iocs || {};
    let text = "--- PHISHGUARD DEFANGED IoCs ---\n";

    if (iocs.domains && iocs.domains.length) {
        text += `[Domains]\n${iocs.domains.join("\n")}\n\n`;
    }
    if (iocs.ips && iocs.ips.length) {
        text += `[IP Addresses]\n${iocs.ips.join("\n")}\n\n`;
    }
    if (iocs.urls && iocs.urls.length) {
        text += `[Defanged URLs]\n${iocs.urls.join("\n")}\n\n`;
    }

    navigator.clipboard.writeText(text).then(() => {
        alert("Defanged IoCs copied to clipboard!");
    }).catch(err => {
        alert("Failed to copy IoCs: " + err);
    });
}

// Export Full JSON Report
function exportReportJson() {
    if (!currentAnalysisResult || !currentAnalysisResult.data) {
        alert("No active report to export.");
        return;
    }

    const jsonStr = JSON.stringify(currentAnalysisResult.data, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishguard_threat_report_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Copy Markdown Summary for Incident Ticketing (Jira / ServiceNow)
function copyReportText() {
    if (!currentAnalysisResult || !currentAnalysisResult.data) {
        alert("No active report to copy.");
        return;
    }

    const d = currentAnalysisResult.data;
    let md = `## PhishGuard Forensic Threat Assessment\n`;
    md += `- **Subject / Target**: ${d.subject}\n`;
    md += `- **Threat Score**: ${d.score}/100 [${d.risk_level} RISK]\n`;
    md += `- **Classification**: ${d.threat_classification}\n`;
    md += `- **Vector Scores**: Headers: ${d.header_score}/100 | Body: ${d.body_score}/100 | URLs: ${d.url_score}/100\n\n`;

    md += `### Triggered Indicators (${d.findings.length}):\n`;
    d.findings.forEach(f => {
        md += `- [${f.severity}] ${f.category} / ${f.rule} (+${f.points} pts): ${f.explanation}\n`;
    });

    md += `\n### SOC Blue Team Playbook:\n`;
    (d.soc_playbook || []).forEach(p => {
        md += `- ${p}\n`;
    });

    navigator.clipboard.writeText(md).then(() => {
        alert("Incident markdown summary copied to clipboard!");
    }).catch(err => {
        alert("Failed to copy summary: " + err);
    });
}

// Safe string escaping for DOM injection
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
