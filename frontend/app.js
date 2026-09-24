    document.addEventListener("DOMContentLoaded", () => {
        // Form & Upload Elements
        const form = document.getElementById("uploadForm");
        const fileInput = document.getElementById("mediaFile");
        const dropZone = document.getElementById("dropZone");
        const dropPrompt = document.getElementById("dropPrompt");
        const uploadButton = document.getElementById("uploadButton");
        const clearFileBtn = document.getElementById("clearFileBtn");

        const stagingStrip = document.getElementById("fileStagingStrip");
        const stagingThumb = document.getElementById("stagingThumb");
        const stagingFilename = document.getElementById("stagingFilename");
        const stagingFilesize = document.getElementById("stagingFilesize");
        const stagingMime = document.getElementById("stagingMime");

        // Dual Engine Elements
        const legacyVerdictBadge = document.getElementById("legacyVerdictBadge");
        const legacyHeadline = document.getElementById("legacyHeadline");
        const legacySub = document.getElementById("legacySub");
        const legacySig = document.getElementById("legacySig");
        const legacyRevocationCheck = document.getElementById("legacyRevocationCheck");
        const legacyExclusionCheck = document.getElementById("legacyExclusionCheck");
        const legacyVulnerabilityMsg = document.getElementById("legacyVulnerabilityMsg");

        const provoVerdictBadge = document.getElementById("provoVerdictBadge");
        const provoHeadline = document.getElementById("provoHeadline");
        const provoSub = document.getElementById("provoSub");
        const provoRevocationVal = document.getElementById("provoRevocationVal");
        const provoTimestampVal = document.getElementById("provoTimestampVal");
        const provoInjectionVal = document.getElementById("provoInjectionVal");
        const provoMitigationMsg = document.getElementById("provoMitigationMsg");

        // Sidebar Telemetry Elements
        const auditAwaitingState = document.getElementById("auditAwaitingState");
        const auditDataContainer = document.getElementById("auditDataContainer");
        const resFilename = document.getElementById("resFilename");
        const resFilesize = document.getElementById("resFilesize");
        const resSha256 = document.getElementById("resSha256");

        const resRevocationBadge = document.getElementById("resRevocationBadge");
        const resRevocationMsg = document.getElementById("resRevocationMsg");
        const resRevocationMethod = document.getElementById("resRevocationMethod");
        const resRevocationEvidence = document.getElementById("resRevocationEvidence");

        const resTimestampBadge = document.getElementById("resTimestampBadge");
        const resTimestampMsg = document.getElementById("resTimestampMsg");
        const resTimestampClaimedTime = document.getElementById("resTimestampClaimedTime");
        const resTimestampEvidence = document.getElementById("resTimestampEvidence");
        const resPipelineBadge = document.getElementById("resPipelineBadge");
        const resPipelineMsg = document.getElementById("resPipelineMsg");
        const resPipelineFindings = document.getElementById("resPipelineFindings");
        const resPipelineCoverage = document.getElementById("resPipelineCoverage");

        const resManifestFound = document.getElementById("resManifestFound");
        const resActiveManifest = document.getElementById("resActiveManifest");
        const resClaimGenerator = document.getElementById("resClaimGenerator");
        const resValidationState = document.getElementById("resValidationState");
        const resAssertionsList = document.getElementById("resAssertionsList");

        const resExploitTitle = document.getElementById("resExploitTitle");
        const resExploitDetail = document.getElementById("resExploitDetail");
        const resVerdictReasons = document.getElementById("resVerdictReasons");
        const resRawJson = document.getElementById("resRawJson");

        const resExifBadge = document.getElementById("resExifBadge");
        const resExifMsg = document.getElementById("resExifMsg");
        const resExifRows = document.getElementById("resExifRows");
        const resExifScope = document.getElementById("resExifScope");

        const btnCopyJson = document.getElementById("btnCopyJson");
        let activeTelemetryPayload = null;

        const comparisonKey = "provo.inspection.comparison.v1";
        const comparisonLink = document.getElementById("openComparisonPage");
        const comparisonNotice = document.getElementById("comparisonAvailability");
        let uploadGeneration = 0;
        let originalUploadedResult = null;

        function invalidateComparison() {
            uploadGeneration += 1;
            comparisonLink?.classList.add("hidden");
            if (comparisonNotice) comparisonNotice.textContent = "";
            try { sessionStorage.removeItem(comparisonKey); } catch (_) { /* Storage may be disabled. */ }
        }
        if (comparisonLink) invalidateComparison();

        // Backend Health Ping
        const backendStatusText = document.getElementById("backendStatusText");
        const backendStatusPill = document.getElementById("backendStatusPill");

        async function pingBackend() {
            if (!backendStatusText || !backendStatusPill) return;
            try {
                const res = await fetch("/api/health");
                if (res.ok) {
                    backendStatusText.textContent = "ONLINE (FASTAPI)";
                    backendStatusPill.classList.add("status-online");
                } else {
                    throw new Error("Bad status");
                }
            } catch (err) {
                backendStatusText.textContent = "STANDALONE / DISCONNECTED";
                backendStatusPill.classList.add("status-warn");
            }
        }
        pingBackend();

        if (form) {
        // Drag & Drop Handling
        dropZone.addEventListener("click", (e) => {
            if (e.target !== clearFileBtn && !clearFileBtn.contains(e.target)) {
                fileInput.click();
            }
        });

        dropZone.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                fileInput.click();
            }
        });

        ["dragenter", "dragover"].forEach(evt => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(evt => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.remove("dragover");
            });
        });

        dropZone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                fileInput.files = e.dataTransfer.files;
                stageFile(fileInput.files[0]);
            }
        });

        fileInput.addEventListener("change", () => {
            if (fileInput.files && fileInput.files[0]) {
                stageFile(fileInput.files[0]);
            }
        });

        function stageFile(file) {
            invalidateComparison();
            stagingFilename.textContent = file.name;
            stagingFilesize.textContent = (file.size / (1024 * 1024)).toFixed(2) + " MB";

            const ext = file.name.split('.').pop().toUpperCase();
            stagingMime.textContent = ext || "FILE";

            if (file.type.startsWith("image/")) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    stagingThumb.src = e.target.result;
                    stagingThumb.style.display = "block";
                };
                reader.readAsDataURL(file);
            } else {
                stagingThumb.style.display = "none";
            }

            dropPrompt.classList.add("hidden");
            stagingStrip.classList.remove("hidden");
        }

        clearFileBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            invalidateComparison();
            fileInput.value = "";
            stagingStrip.classList.add("hidden");
            dropPrompt.classList.remove("hidden");
        });

        // Form Submit -> POST /api/upload
        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const file = fileInput.files[0];

            if (!file) {
                alert("Please select or drop a media file first, then execute the inspection.");
                return;
            }

            if (file.size > 25 * 1024 * 1024) {
                alert("File exceeds maximum allowed limit of 25 MB.");
                return;
            }

            const formData = new FormData();
            formData.append("file", file);

            invalidateComparison();
            const requestGeneration = uploadGeneration;
            uploadButton.disabled = true;
            uploadButton.querySelector(".btn-text").textContent = "Executing Hardened Inspection...";

            try {
                const response = await fetch("/api/upload", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();
                if (!response.ok) {
                    throw new Error(data.detail || "Inspection request failed");
                }

                if (requestGeneration !== uploadGeneration) return;
                activeTelemetryPayload = data;
                renderInspectionResults(data);
                if (data.simulated !== true && data.c2pa && typeof data.c2pa === "object") {
                    try {
                        sessionStorage.setItem(comparisonKey, JSON.stringify({ version: 1, result: data }));
                        comparisonLink?.classList.remove("hidden");
                    } catch (_) {
                        if (comparisonNotice) comparisonNotice.textContent = "Inspection complete. Enable tab session storage to open the comparison page.";
                    }
                }

            } catch (err) {
                alert("Upload failed: " + err.message + "\nCheck that the PROVO backend is running, then retry.");
            } finally {
                uploadButton.disabled = false;
                uploadButton.querySelector(".btn-text").textContent = "Execute PROVO Security Inspection";
            }
        });

        } // Optional upload form: not present on the comparison page.

        // Render Telemetry & Dual-Engine Matrix
        function renderInspectionResults(data) {
            const c2pa = data.c2pa || {};
            const isManifest = c2pa.manifest_found === true;
            const certRev = c2pa.certificate_revocation || {};
            const timestamp = c2pa.timestamp_security || {};
            const hardened = c2pa.hardened_verdict || {};
            const validationState = String(c2pa.validation_state || "Unchecked");
            const activeResults = c2pa.validation_results?.activeManifest || {};
            const successes = Array.isArray(activeResults.success) ? activeResults.success : [];
            const failures = Array.isArray(activeResults.failure) ? activeResults.failure : [];
            const successCodes = new Set(successes.map(item => item?.code).filter(Boolean));
            const failureCodes = new Set(failures.map(item => item?.code).filter(Boolean));

            // Missing backend verdicts deliberately fail closed. Only an explicit
            // HARDENED_VALID response may receive the green treatment.
            let verdict = hardened.verdict;
            if (!verdict) {
                verdict = !isManifest
                    ? "NO_PROVENANCE"
                    : (data.status === "error" || c2pa.status === "error" ? "INSPECTION_ERROR" : "VALID_WITH_GAPS");
            }

            const verdictPresentation = {
                HARDENED_VALID: {
                    badge: "HARDENED VALID", badgeClass: "badge-pass", titleClass: "text-cyan",
                    title: "HARDENED VALIDATION PASSED", headline: "All Required Evidence Passed",
                    action: "No policy failure was reported by the hardened backend."
                },
                VALID_WITH_GAPS: {
                    badge: "VALID WITH GAPS", badgeClass: "badge-warn", titleClass: "text-gold",
                    title: "VALIDATION EVIDENCE IS INCOMPLETE", headline: "Do Not Treat as Fully Trusted",
                    action: "Hold or review the asset until the missing evidence is resolved."
                },
                UNTRUSTED_SIGNER: {
                    badge: "UNTRUSTED SIGNER", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "SIGNER TRUST NOT ESTABLISHED", headline: "Untrusted Signing Credential",
                    action: "Reject or quarantine under a trust-required policy."
                },
                TAMPERED: {
                    badge: "TAMPERED", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "CONTENT INTEGRITY FAILURE", headline: "Tampering Evidence Detected",
                    action: "Quarantine the asset; signed bytes or assertions failed validation."
                },
                REVOKED_SIGNER: {
                    badge: "REVOKED SIGNER", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "REVOKED SIGNING CREDENTIAL", headline: "Revocation Evidence Detected",
                    action: "Quarantine the asset and investigate the compromised credential."
                },
                TIMESTAMP_INVALID: {
                    badge: "TIMESTAMP INVALID", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "TIMESTAMP SECURITY FAILURE", headline: "Timestamp Cannot Be Trusted",
                    action: "Do not rely on the claimed signing time."
                },
                CREDENTIAL_INVALID: {
                    badge: "CREDENTIAL INVALID", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "SIGNING CREDENTIAL INVALID", headline: "Certificate Validation Failed",
                    action: "Reject or quarantine because credential validity was not established."
                },
                POLICY_VIOLATION: {
                    badge: "POLICY VIOLATION", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "HARDENED POLICY VIOLATION", headline: "Required Security Policy Failed",
                    action: "Apply the configured enforcement policy before distribution."
                },
                NO_PROVENANCE: {
                    badge: "NO PROVENANCE", badgeClass: "badge-warn", titleClass: "text-gold",
                    title: "NO C2PA PROVENANCE FOUND", headline: "Authenticity Not Established",
                    action: "Treat the asset as provenance-unknown; absence is not evidence of manipulation or safety."
                },
                INSPECTION_ERROR: {
                    badge: "INSPECTION ERROR", badgeClass: "badge-threat", titleClass: "text-crimson",
                    title: "INSPECTION COULD NOT COMPLETE", headline: "No Security Decision Available",
                    action: "Fail closed and retry or escalate the inspection error."
                }
            };
            const display = verdictPresentation[verdict] || verdictPresentation.VALID_WITH_GAPS;

            auditAwaitingState.classList.add("hidden");
            auditDataContainer.classList.remove("hidden");

            // 1. File Identity
            resFilename.textContent = data.filename || "Uploaded File";
            const fileSize = Number(data.file_size);
            resFilesize.textContent = Number.isFinite(fileSize)
                ? (fileSize / (1024 * 1024)).toFixed(2) + " MB (" + fileSize + " bytes)"
                : "Not supplied";
            resSha256.textContent = data.sha256 || "N/A";

            // 2. Revocation Status
            resRevocationBadge.textContent = (certRev.status || "UNKNOWN").toUpperCase();
            resRevocationBadge.className = "status-indicator-badge " +
                (certRev.status === "revoked" ? "badge-threat" : (certRev.status === "not_revoked" ? "badge-pass" : "badge-warn"));
            resRevocationMsg.textContent = certRev.message || "No revocation message provided";
            resRevocationMethod.textContent = certRev.method || "c2pa_ocsp_validation";

            const revocationEvidence = Array.isArray(certRev.evidence) ? certRev.evidence : [];
            resRevocationEvidence.textContent = revocationEvidence.length
                ? revocationEvidence.map(item => item?.code || "unnamed evidence").join(", ")
                : "No conclusive evidence returned";

            // 3. Timestamp Security
            const timestampStatus = String(timestamp.status || "unknown").toLowerCase();
            resTimestampBadge.textContent = timestampStatus.toUpperCase();
            resTimestampBadge.className = "status-indicator-badge " +
                (timestampStatus === "valid" ? "badge-pass" : (timestampStatus === "invalid" ? "badge-threat" : "badge-warn"));
            resTimestampMsg.textContent = timestamp.message || "No conclusive timestamp security result was returned.";
            resTimestampClaimedTime.textContent = timestamp.claimed_time || c2pa.signature_info?.time || "Not supplied";
            const timestampEvidence = Array.isArray(timestamp.evidence) ? timestamp.evidence : [];
            resTimestampEvidence.textContent = timestampEvidence.length
                ? timestampEvidence.map(item => item?.code || "unnamed evidence").join(", ")
                : "No conclusive evidence returned";

            const pipeline = c2pa.pipeline_audit || {};
            resPipelineBadge.textContent = String(pipeline.status || "not_assessed").toUpperCase();
            resPipelineBadge.className = "status-indicator-badge " +
                (pipeline.status === "invalid" ? "badge-threat" : "badge-warn");
            resPipelineMsg.textContent = pipeline.message || "No pipeline audit was returned by this backend.";
            resPipelineFindings.replaceChildren();
            for (const finding of (Array.isArray(pipeline.findings) ? pipeline.findings : [])) {
                const li = document.createElement("li");
                li.textContent = `${finding.code || "Finding"}: ${finding.message || "Review required"}`;
                resPipelineFindings.appendChild(li);
            }
            const coverage = pipeline.coverage && typeof pipeline.coverage === "object" ? pipeline.coverage : {};
            resPipelineCoverage.textContent = Object.entries(coverage)
                .map(([check, status]) => `${check}: ${status}`).join(" · ");

            // 4. Manifest Details
            resManifestFound.textContent = isManifest ? "TRUE (DETECTED)" : "FALSE (NO MANIFEST)";
            resManifestFound.className = "data-val font-mono " + (isManifest ? "text-cyan" : "text-crimson");
            resActiveManifest.textContent = c2pa.active_manifest || "None";
            resClaimGenerator.textContent = c2pa.claim_generator || "Unknown Claim Generator";
            resValidationState.textContent = validationState;
            resValidationState.className = "data-val font-mono " +
                (validationState.toLowerCase() === "valid" ? "text-cyan" : "text-crimson");

            resAssertionsList.innerHTML = "";
            const assertions = c2pa.assertions || [];
            if (assertions.length > 0) {
                assertions.forEach(label => {
                    const li = document.createElement("li");
                    li.className = "assertion-tag font-mono";
                    li.textContent = label;
                    resAssertionsList.appendChild(li);
                });
            } else {
                resAssertionsList.innerHTML = "<li class='text-dim font-mono'>No assertions declared</li>";
            }

            // 7. Supplementary EXIF consistency; never turn metadata into a cryptographic verdict.
            const metadata = c2pa.metadata_consistency || {};
            const exifStatus = data.simulated === true ? "not_evaluated" : (metadata.status || "not_evaluated");
            const exifTitles = {
                match: "FIELDS MATCH", mismatch: "REVIEW DISCREPANCY", inconclusive: "INCONCLUSIVE",
                no_exif: "NO SUPPORTED EXIF", no_c2pa_metadata: "NO C2PA METADATA",
                not_applicable: "NOT APPLICABLE", error: "EXTRACTION ERROR",
                not_evaluated: "NOT EVALUATED"
            };
            resExifBadge.textContent = exifTitles[exifStatus] || "INCONCLUSIVE";
            // A metadata match is informational, not a green authenticity verdict.
            resExifBadge.className = "status-indicator-badge " +
                (exifStatus === "mismatch" ? "badge-threat" : "badge-warn");
            resExifMsg.textContent = data.simulated === true
                ? "Demonstration preset: no real EXIF bytes or C2PA metadata were inspected."
                : (metadata.message || "This inspection did not return EXIF consistency results.");
            resExifScope.textContent = metadata.scope_note ||
                "EXIF can be changed or removed; C2PA assertions are signer claims. Metadata consistency does not establish scene authenticity.";
            resExifRows.replaceChildren();
            const exifRows = Array.isArray(metadata.comparisons) && data.simulated !== true
                ? metadata.comparisons : [];
            for (const item of exifRows) {
                const row = document.createElement("div");
                row.className = "exif-comparison-row";
                const head = document.createElement("div");
                head.className = "exif-row-heading";
                const label = document.createElement("strong");
                label.textContent = item.label || item.field || "Metadata field";
                const fieldStatus = document.createElement("span");
                fieldStatus.className = "exif-field-status " + (item.status === "mismatch" ? "exif-discrepancy" : "");
                fieldStatus.textContent = String(item.status || "unavailable").replaceAll("_", " ").toUpperCase();
                head.append(label, fieldStatus);
                const values = document.createElement("div");
                values.className = "exif-values";
                for (const [name, value] of [["EMBEDDED EXIF", item.exif], ["C2PA ASSERTION", item.c2pa]]) {
                    const cell = document.createElement("div");
                    const key = document.createElement("span");
                    key.className = "exif-value-label";
                    key.textContent = name;
                    const valueElement = document.createElement("span");
                    valueElement.className = "exif-value";
                    valueElement.textContent = value == null ? "Not available" : String(value);
                    cell.append(key, valueElement);
                    values.appendChild(cell);
                }
                const explanation = document.createElement("p");
                explanation.className = "exif-row-detail";
                explanation.textContent = item.explanation || "";
                row.append(head, values, explanation);
                resExifRows.appendChild(row);
            }

            // 5. Hardened Verdict: backend output is the authoritative policy decision.
            resExploitTitle.textContent = display.title;
            resExploitTitle.className = "exploit-title " + display.titleClass;
            resExploitDetail.textContent = hardened.summary || display.action;
            resVerdictReasons.innerHTML = "";
            const reasons = Array.isArray(hardened.reasons) && hardened.reasons.length
                ? hardened.reasons
                : [display.action];
            reasons.forEach(reason => {
                const li = document.createElement("li");
                li.textContent = reason;
                resVerdictReasons.appendChild(li);
            });

            if (legacyVerdictBadge) {
            // C2PA evidence without PROVO policy: not a competing or defective validator.
            const stateLower = validationState.toLowerCase();
            const sdkValid = stateLower === "valid";
            const sdkInvalid = stateLower === "invalid";
            legacyVerdictBadge.textContent = sdkValid ? "SDK: VALID" : (sdkInvalid ? "SDK: INVALID" : "SDK: INCONCLUSIVE");
            legacyVerdictBadge.className = "verdict-badge " + (sdkValid ? "badge-pass" : (sdkInvalid ? "badge-threat" : "badge-warn"));
            legacyHeadline.textContent = sdkValid ? "SDK Reports Valid" : (sdkInvalid ? "SDK Reports Invalid" : "SDK State Unresolved");
            legacySub.textContent = "This card reflects the validator state only; it is not a claim that the media is objectively true.";
            legacySig.textContent = successCodes.has("claimSignature.validated")
                ? "VALIDATED"
                : (failureCodes.has("claimSignature.mismatch") ? "INVALID" : "NOT ESTABLISHED");
            legacyRevocationCheck.textContent = validationState.toUpperCase();
            legacyExclusionCheck.textContent = failureCodes.has("signingCredential.untrusted")
                ? "UNTRUSTED"
                : (successCodes.has("signingCredential.trusted") ? "TRUSTED" : "NOT ESTABLISHED");
            legacyVulnerabilityMsg.textContent = sdkValid && verdict !== "HARDENED_VALID"
                ? `The SDK reports Valid while PROVO reports ${verdict}. This is a difference in acceptance policy, not proof that C2PA missed the underlying evidence.`
                : "C2PA evidence is shown without PROVO’s additional policy. An intact signature alone does not establish scene truth or satisfy every application’s trust requirements.";

            provoVerdictBadge.textContent = display.badge;
            provoVerdictBadge.className = "verdict-badge " + display.badgeClass;
            provoHeadline.textContent = display.headline;
            provoHeadline.className = "verdict-headline " + display.titleClass;
            provoSub.textContent = hardened.summary || display.action;
            provoRevocationVal.textContent = String(certRev.status || "unknown").toUpperCase();
            provoRevocationVal.className = "readout-val font-mono " +
                (certRev.status === "not_revoked" ? "text-cyan" : (certRev.status === "revoked" ? "text-crimson" : "text-gold"));
            provoTimestampVal.textContent = timestampStatus.toUpperCase();
            provoTimestampVal.className = "readout-val font-mono " +
                (timestampStatus === "valid" ? "text-cyan" : (timestampStatus === "invalid" ? "text-crimson" : "text-gold"));
            provoInjectionVal.textContent = verdict;
            provoInjectionVal.className = "readout-val font-mono " + display.titleClass;
            provoMitigationMsg.textContent = display.action;

            }
            const sourceLabel = document.getElementById("comparisonSource");
            if (sourceLabel) sourceLabel.textContent = (data.simulated === true ? "SIMULATED PRESET — " : "UPLOADED FILE RESULT — ") + (data.filename || "Unnamed asset");
            resRawJson.textContent = JSON.stringify(data, null, 2);
            document.getElementById("telemetrySourceNote").textContent = data.simulated === true
                ? "SIMULATED DEMONSTRATION DATA — no uploaded file was inspected."
                : "UPLOADED FILE RESULT — findings apply to this inspection, not proof of the depicted event.";
            document.getElementById("openTelemetryPage").classList.remove("hidden");
        }

        // Evaluation Presets
        const evalButtons = document.querySelectorAll("[data-eval]");
        evalButtons.forEach(btn => {
            btn.addEventListener("click", () => {
                const sampleType = btn.getAttribute("data-eval");
                triggerEvaluationSample(sampleType);
                evalButtons.forEach(item => item.setAttribute("aria-pressed", String(item === btn)));
            });
        });

        function triggerEvaluationSample(type) {
            let mockResult = {};

            if (type === "revoked") {
                mockResult = {
                    status: "uploaded",
                    file_id: "provo-revoked-sample-01",
                    filename: "compromised_signer_deepfake.jpg",
                    file_size: 3410291,
                    sha256: "9f83c2718228392a83f9821d7b1a0391d848209341209e8471b0231d8f742110",
                    verification_status: "manifest_found",
                    c2pa: {
                        status: "manifest_found",
                        manifest_found: true,
                        active_manifest: "urn:c2pa:provo:exploit:revoked:01",
                        claim_generator: "Adobe Firefly Authenticity Suite v2.0",
                        signature_info: { issuer: "Rogue CA Sub-Authority", alg: "es256" },
                        assertions: ["c2pa.actions", "c2pa.hash.data", "stds.schema-org.CreativeWork"],
                        validation_state: "Valid",
                        validation_results: {
                            activeManifest: {
                                success: [{ code: "claimSignature.validated" }],
                                failure: [{ code: "signingCredential.revoked" }]
                            }
                        },
                        certificate_revocation: {
                            status: "revoked",
                            checked: true,
                            method: "c2pa_ocsp_validation",
                            message: "The signing certificate was revoked at signing time.",
                            evidence: [{ code: "signingCredential.revoked" }]
                        },
                        timestamp_security: {
                            status: "valid", checked: true, trusted: true,
                            claimed_time: "2026-01-17T09:14:00Z",
                            message: "The simulated timestamp is valid and trusted.",
                            evidence: [{ code: "timeStamp.validated" }, { code: "timeStamp.trusted" }]
                        },
                        hardened_verdict: {
                            verdict: "REVOKED_SIGNER", severity: "critical", hardened_valid: false,
                            summary: "Revocation evidence identifies the active signing credential as revoked.",
                            reasons: ["The active manifest contains signingCredential.revoked evidence."],
                            standard_validation_state: "Valid",
                            evidence_codes: ["signingCredential.revoked"]
                        }
                    }
                };
            } else if (type === "modified") {
                mockResult = {
                    status: "uploaded",
                    file_id: "provo-modified-sample-02",
                    filename: "tests_samples_modified.jpg",
                    file_size: 1001720,
                    sha256: "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                    verification_status: "manifest_found",
                    c2pa: {
                        status: "manifest_found",
                        manifest_found: true,
                        active_manifest: "urn:c2pa:provo:test:sample:modified",
                        claim_generator: "C2PA Test Harness / Hardware Ingestion",
                        signature_info: { issuer: "Hardware Root CA", alg: "rs256" },
                        assertions: ["c2pa.actions", "c2pa.exclusion.ranges"],
                        validation_state: "Invalid",
                        validation_results: {
                            activeManifest: {
                                success: [{ code: "signingCredential.notRevoked" }],
                                failure: [{ code: "assertion.dataHash.mismatch" }]
                            }
                        },
                        certificate_revocation: {
                            status: "not_revoked",
                            checked: true,
                            method: "c2pa_ocsp_validation",
                            message: "OCSP evidence shows certificate was not revoked.",
                            evidence: [{ code: "signingCredential.notRevoked" }]
                        },
                        timestamp_security: {
                            status: "unknown", checked: false, trusted: false,
                            claimed_time: null,
                            message: "No conclusive timestamp evidence was returned.", evidence: []
                        },
                        hardened_verdict: {
                            verdict: "TAMPERED", severity: "critical", hardened_valid: false,
                            summary: "The signed content or assertion hashes failed validation.",
                            reasons: ["The active manifest contains assertion.dataHash.mismatch evidence."],
                            standard_validation_state: "Invalid",
                            evidence_codes: ["assertion.dataHash.mismatch"]
                        }
                    }
                };
            } else if (type === "signed" || type === "exclusion") {
                mockResult = {
                    status: "uploaded",
                    file_id: "provo-original-sample-03",
                    filename: "tests_samples_original_signed.jpg",
                    file_size: 1047024,
                    sha256: "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                    verification_status: "manifest_found",
                    c2pa: {
                        status: "manifest_found",
                        manifest_found: true,
                        active_manifest: "urn:c2pa:provo:test:sample:original_signed",
                        claim_generator: "Leica Camera Authenticity Engine v1.0",
                        signature_info: { issuer: "Leica Camera AG CA", alg: "es256" },
                        assertions: ["c2pa.actions", "c2pa.hash.data", "c2pa.thumbnail.claim.jpeg"],
                        validation_state: "Valid",
                        validation_results: {
                            activeManifest: {
                                success: [
                                    { code: "claimSignature.validated" },
                                    { code: "signingCredential.trusted" },
                                    { code: "signingCredential.notRevoked" },
                                    { code: "timeStamp.validated" },
                                    { code: "timeStamp.trusted" }
                                ],
                                failure: []
                            }
                        },
                        certificate_revocation: {
                            status: "not_revoked",
                            checked: true,
                            method: "c2pa_ocsp_validation",
                            message: "OCSP evidence shows the certificate was not revoked at signing time.",
                            evidence: [{ code: "signingCredential.notRevoked" }]
                        },
                        timestamp_security: {
                            status: "valid", checked: true, trusted: true,
                            claimed_time: "2026-01-17T09:14:00Z",
                            message: "The simulated timestamp is valid and trusted.",
                            evidence: [{ code: "timeStamp.validated" }, { code: "timeStamp.trusted" }]
                        },
                        hardened_verdict: {
                            verdict: "HARDENED_VALID", severity: "none", hardened_valid: true,
                            summary: "All security evidence required by the prototype policy is present.",
                            reasons: ["Signature, signer trust, revocation, and timestamp evidence passed."],
                            standard_validation_state: "Valid",
                            evidence_codes: ["claimSignature.validated", "signingCredential.trusted", "signingCredential.notRevoked", "timeStamp.validated", "timeStamp.trusted"]
                        }
                    }
                };
            } else {
                mockResult = {
                    status: "uploaded",
                    file_id: "provo-ordinary-sample-04",
                    filename: "tests_samples_ordinary.jpg",
                    file_size: 4820316,
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    verification_status: "no_manifest",
                    c2pa: {
                        status: "no_manifest",
                        manifest_found: false,
                        validation_state: "NoManifestFound",
                        certificate_revocation: {
                            status: "unknown",
                            checked: false,
                            method: "c2pa_ocsp_validation",
                            message: "No conclusive OCSP revocation evidence was returned.", evidence: []
                        },
                        timestamp_security: {
                            status: "unknown", checked: false, trusted: false,
                            claimed_time: null,
                            message: "No C2PA timestamp is available without a manifest.", evidence: []
                        },
                        hardened_verdict: {
                            verdict: "NO_PROVENANCE", severity: "medium", hardened_valid: false,
                            summary: "No C2PA manifest was found, so provenance cannot be established.",
                            reasons: ["The asset contains no discoverable C2PA manifest."],
                            standard_validation_state: "NoManifestFound",
                            evidence_codes: []
                        }
                    }
                };
            }

            mockResult.simulated = true;
            mockResult.c2pa.metadata_consistency = {
                status: "not_evaluated", checked: false,
                message: "Simulated preset; real metadata was not inspected.",
                exif: {}, c2pa: {}, comparisons: [], assertion_labels: []
            };
            mockResult.c2pa.pipeline_audit = {
                status: mockResult.c2pa.manifest_found ? "no_flags" : "not_assessed",
                checked: mockResult.c2pa.manifest_found,
                coverage: { demonstration: "simulated" },
                findings: [],
                message: "Simulated preset: no file bytes were inspected. Upload a file for a real audit."
            };
            if (type === "exclusion") {
                const code = "assertion.dataHash.additionalExclusionsPresent";
                mockResult.filename = "SIMULATED_extra_exclusion.jpg";
                mockResult.c2pa.validation_results.activeManifest.informational = [{ code }];
                mockResult.c2pa.pipeline_audit.status = "review_required";
                mockResult.c2pa.pipeline_audit.findings = [{
                    code, level: "review", category: "additional_exclusion",
                    message: "Simulated additional exclusion: inspect bytes outside the hard binding."
                }];
                mockResult.c2pa.hardened_verdict = {
                    verdict: "VALID_WITH_GAPS", severity: "warning", hardened_valid: false,
                    summary: "The SDK state is Valid, but an additional exclusion requires review.",
                    reasons: ["Pipeline structure requires review."],
                    standard_validation_state: "Valid", evidence_codes: [code]
                };
            }
            activeTelemetryPayload = mockResult;
            renderInspectionResults(mockResult);
            document.getElementById("intercept-matrix").scrollIntoView({ behavior: "smooth" });
        }

        // The dedicated comparison page starts with the executed upload result.
        if (document.body.dataset.page === "comparison") {
            try {
                const saved = JSON.parse(sessionStorage.getItem(comparisonKey) || "null");
                if (saved?.version === 1 && saved.result?.c2pa && saved.result.simulated !== true) {
                    originalUploadedResult = saved.result;
                    activeTelemetryPayload = saved.result;
                    renderInspectionResults(saved.result);
                    document.getElementById("comparisonGate").classList.add("hidden");
                    document.getElementById("workbench").classList.remove("hidden");
                }
            } catch (_) { /* Missing, blocked or malformed state keeps the gate visible. */ }
            document.getElementById("restoreUploadedResult").addEventListener("click", () => {
                if (!originalUploadedResult) return;
                activeTelemetryPayload = originalUploadedResult;
                renderInspectionResults(originalUploadedResult);
                evalButtons.forEach(item => item.setAttribute("aria-pressed", "false"));
            });
        }

        // Copy JSON Button
        btnCopyJson.addEventListener("click", () => {
            if (!activeTelemetryPayload) {
                alert("No telemetry to copy. Please ingest an asset first.");
                return;
            }
            navigator.clipboard.writeText(JSON.stringify(activeTelemetryPayload, null, 2)).then(() => {
                const original = btnCopyJson.textContent;
                btnCopyJson.textContent = "COPIED!";
                setTimeout(() => btnCopyJson.textContent = original, 1800);
            });
        });

        // Contact Modal Controls
        const contactModal = document.getElementById("contactModal");
        const btnOpenContactHeader = document.getElementById("btnOpenContactHeader");
        const btnHeroContact = document.getElementById("btnHeroContact");
        const btnFooterContact = document.getElementById("btnFooterContact");
        const btnCloseContactModal = document.getElementById("btnCloseContactModal");
        const btnDismissModal = document.getElementById("btnDismissModal");
        const btnJumpToForm = document.getElementById("btnJumpToForm");

        function openModal() {
            if (contactModal) contactModal.showModal();
        }

        function closeModal() {
            if (contactModal) contactModal.close();
        }

        if (btnOpenContactHeader) btnOpenContactHeader.addEventListener("click", openModal);
        if (btnHeroContact) btnHeroContact.addEventListener("click", openModal);
        if (btnFooterContact) btnFooterContact.addEventListener("click", openModal);
        if (btnCloseContactModal) btnCloseContactModal.addEventListener("click", closeModal);
        if (btnDismissModal) btnDismissModal.addEventListener("click", closeModal);
        if (btnJumpToForm) {
            btnJumpToForm.addEventListener("click", () => {
                closeModal();
            });
        }

        // Contact Form Submission (Simulated / Local)
        const contactForm = document.getElementById("contactForm");
        const contactStatusMsg = document.getElementById("contactStatusMsg");

        if (contactForm) {
            contactForm.addEventListener("submit", (e) => {
                e.preventDefault();
                contactStatusMsg.textContent = "Demo only: this form does not transmit data. Please use the GitHub repository to contact the project team.";
                contactStatusMsg.style.color = "var(--gold-primary)";
            });
        }

        // Scroll Progress & Parallax
        const scrollIndicator = document.getElementById("scrollProgress");
        window.addEventListener("scroll", () => {
            const scrollTop = window.scrollY;
            const docHeight = document.documentElement.scrollHeight - window.innerHeight;
            const scrollPercent = (scrollTop / (docHeight || 1)) * 100;
            if (scrollIndicator) scrollIndicator.style.width = scrollPercent + "%";

            // Parallax element calculation
            const parallaxEls = document.querySelectorAll("[data-parallax-speed]");
            parallaxEls.forEach(el => {
                const speed = parseFloat(el.getAttribute("data-parallax-speed") || 0);
                el.style.transform = `translate3d(0, ${scrollTop * speed}px, 0)`;
            });
        }, { passive: true });
    });
