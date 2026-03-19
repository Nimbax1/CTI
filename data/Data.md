```dataviewjs
let pages = dv.pages('"TTP_&_Malware"').where(p => {
    if (!p.MainBranch) return false;
    let branch = Array.isArray(p.MainBranch) ? p.MainBranch.join(" ") : String(p.MainBranch);
    return branch.includes("DarkSword");
});

let flatData = [];

for (let p of pages) {
    let mainBranchStr = Array.isArray(p.MainBranch) ? p.MainBranch.join(", ") : (p.MainBranch || "N/A");
    let capabilitiesStr = Array.isArray(p.capabilities) ? p.capabilities.join(", ") : (p.capabilities || "N/A");
    
    let allDestCountries = new Set();
    let allOrigins = new Set();
    let allDates = new Set();
    let allActors = new Set();
    
    let actorsList = Array.isArray(p.threat_actor) ? p.threat_actor : (p.threat_actor ? [p.threat_actor] : []);
    
    for (let actorLink of actorsList) {
        let actorPath = "";
        if (actorLink.path) {
            actorPath = actorLink.path;
        } else if (typeof actorLink === "string") {
            actorPath = actorLink.replace(/\[\[|\]\]/g, "");
        }
        
        if (actorPath) {
            let actorPage = dv.page(actorPath);
            if (actorPage) {
                allActors.add(`[[${actorPath}|${actorPath.split('/').pop().replace(/\.md$/i, "")}]]`);
                
                if (actorPage.origin) {
                    let origins = Array.isArray(actorPage.origin) ? actorPage.origin : [actorPage.origin];
                    origins.forEach(o => { if (o) allOrigins.add(String(o)) });
                }
                
                if (actorPage.campaigns) {
                    let campaigns = Array.isArray(actorPage.campaigns) ? actorPage.campaigns : [actorPage.campaigns];
                    
                    for (let camp of campaigns) {
                        if (camp.country) allDestCountries.add(String(camp.country));
                        
                        if (camp.tools) {
                            let tools = Array.isArray(camp.tools) ? camp.tools : [camp.tools];
                            for (let t of tools) {
                                let tName = (typeof t === "object" && t.name) ? String(t.name) : String(t);
                                if (tName.includes("DarkSword") && t.date) {
                                    let dateStr = t.date.toISODate ? t.date.toISODate() : String(t.date).substring(0, 10);
                                    allDates.add(dateStr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    flatData.push([
        p.file.link,
        allDestCountries.size > 0 ? Array.from(allDestCountries).join(", ") : "N/A",
        allOrigins.size > 0 ? Array.from(allOrigins).join(", ") : "N/A",
        allDates.size > 0 ? Array.from(allDates).join(", ") : "N/A",
        allActors.size > 0 ? Array.from(allActors).join(", ") : "N/A",
        mainBranchStr,
        capabilitiesStr
    ]);
}

if (flatData.length === 0) {
    dv.paragraph("Nessun dato trovato");
} else {
    dv.table(
        ["File Malware", "Dest Countries", "Origin", "Date detection", "Threat Actor", "MainBranch", "Capabilities"],
        flatData
    );
}

```

