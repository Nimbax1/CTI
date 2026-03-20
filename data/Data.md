```dataviewjs
let pages = dv.pages('"TTP_&_Malware"').where(p => p.file.name !== "index");
let flatData = [];

for (let p of pages) {
    let mainBranchStr = Array.isArray(p.MainBranch) ? p.MainBranch.join(", ") : (p.MainBranch || "N/A");
    let capabilitiesStr = Array.isArray(p.capabilities) ? p.capabilities.join(", ") : (p.capabilities || "N/A");
    let destCountriesStr = Array.isArray(p.dst_countries) ? p.dst_countries.join(", ") : (p.dst_countries || "N/A");
    let originStr = Array.isArray(p.origin) ? p.origin.join(", ") : (p.origin || "N/A");
    let actorsStr = Array.isArray(p.threat_actor) ? p.threat_actor.join(", ") : (p.threat_actor || "N/A");
    
    let dateStr = "N/A";
    if (p.date_detection) {
        dateStr = p.date_detection.toISODate ? p.date_detection.toISODate() : String(p.date_detection).substring(0, 10);
    }

    flatData.push([
        p.file.link,
        destCountriesStr,
        originStr,
        dateStr,
        actorsStr,
        mainBranchStr,
        capabilitiesStr
    ]);
}

if (flatData.length === 0) {
    dv.paragraph("Nessun dato trovato in TTP_&_Malware");
} else {
    dv.table(
        ["File Malware", "Dest Countries", "Origin", "Date detection", "Threat Actor", "MainBranch", "Capabilities"],
        flatData
    );
}


```

