// Open a standalone, read-only snapshot without storing inspection data on disk
// or sending it to a new API. Dynamic evidence is already rendered as text.
document.getElementById("openTelemetryPage").addEventListener("click", function (event) {
    if (document.getElementById("auditDataContainer").classList.contains("hidden")) {
        event.preventDefault();
        return;
    }

    const report = document.implementation.createHTMLDocument("PROVO | Forensic telemetry report");
    report.documentElement.lang = "en";
    const charset = report.createElement("meta");
    charset.setAttribute("charset", "utf-8");
    report.head.prepend(charset);
    const viewport = report.createElement("meta");
    viewport.name = "viewport";
    viewport.content = "width=device-width, initial-scale=1";
    report.head.appendChild(viewport);
    const stylesheet = report.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = new URL("/style.css", window.location.href).href;
    report.head.appendChild(stylesheet);
    report.body.className = "provo-app comparison-report";

    const main = report.createElement("main");
    main.className = "report-page";
    const back = report.createElement("a");
    back.href = new URL("/", window.location.href).href;
    back.textContent = "← Back to Homepage";
    main.appendChild(back);

    const panel = document.getElementById("auditSidebar").cloneNode(true);
    panel.querySelector(".telemetry-actions").remove();
    const title = report.createElement("h1");
    title.className = "sidebar-title";
    title.textContent = "FORENSIC TELEMETRY REPORT";
    panel.querySelector(".sidebar-title").replaceWith(title);
    const note = panel.querySelector("#telemetrySourceNote");
    note.textContent += " Snapshot opened " + new Date().toLocaleString() + ". This page does not update automatically.";
    main.appendChild(panel);
    report.body.appendChild(main);

    const url = URL.createObjectURL(new Blob(["<!DOCTYPE html>\n", report.documentElement.outerHTML], {
        type: "text/html;charset=utf-8"
    }));
    // Normal link navigation preserves browser popup protections and noopener.
    this.href = url;
    // The new tab has time to load; no indefinite accumulation of report blobs.
    setTimeout(() => URL.revokeObjectURL(url), 60000);
});
