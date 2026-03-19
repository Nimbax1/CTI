```dataviewjs
let pages = dv.pages('"Actors"');
let flatData = [];

for (let p of pages) {
    if (!p.campaigns) continue;
    
    let activity = Array.isArray(p.activity) ? p.activity.join(", ") : (p.activity || "N/A");
    
    let targetsTrovati = new Set();
    let activityLinks = Array.isArray(p.activity) ? p.activity : (p.activity ? [p.activity] : []);
    
    for (let link of activityLinks) {
        let path = "";
        if (link.path) {
            path = link.path;
        } else if (typeof link === "string") {
            path = link.replace(/\[\[|\]\]/g, "");
        }
        if (path) {
            let activityPage = dv.page(path);
            if (activityPage && activityPage.target_industry) {
                let targets = Array.isArray(activityPage.target_industry) 
                    ? activityPage.target_industry 
                    : [activityPage.target_industry];
                for (let t of targets) {
                    targetsTrovati.add(String(t));
                }
            }
        }
    }
    let finalTargets = targetsTrovati.size > 0 ? Array.from(targetsTrovati).join(", ") : "N/A";
    
    let campaigns = Array.isArray(p.campaigns) ? p.campaigns : [p.campaigns];
    
    for (let camp of campaigns) {
        if (!camp.country) continue;
        
        let toolNames = [];
        let toolDates = [];
        
        if (camp.tools) {
            let toolsArray = Array.isArray(camp.tools) ? camp.tools : [camp.tools];
            
            for (let t of toolsArray) {
                if (typeof t === "object" && t.name) {
                    let toolName = "";
                    if (typeof t.name === "object" && t.name.path) {
                        let cleanName = t.name.path.split('/').pop().replace(/\.md$/i, "");
                        toolName = `[[${t.name.path}|${cleanName}]]`;
                    } else {
                        let strName = String(t.name);
                        let cleanPath = strName.replace(/\[\[|\]\]/g, "");
                        let cleanName = cleanPath.split('/').pop().replace(/\.md$/i, "");
                        toolName = `[[${cleanPath}|${cleanName}]]`;
                    }
                    
                    let toolDate = "N/A";
                    if (t.date) {
                        if (t.date.toISODate) {
                            toolDate = t.date.toISODate(); 
                        } else {
                            toolDate = String(t.date).substring(0, 10);
                        }
                    }
                    
                    toolNames.push(toolName);
                    toolDates.push(toolDate);
                } 
                else {
                    let toolName = "";
                    if (typeof t === "object" && t.path) {
                        let cleanName = t.path.split('/').pop().replace(/\.md$/i, "");
                        toolName = `[[${t.path}|${cleanName}]]`;
                    } else {
                        let strName = String(t);
                        let cleanPath = strName.replace(/\[\[|\]\]/g, "");
                        let cleanName = cleanPath.split('/').pop().replace(/\.md$/i, "");
                        toolName = `[[${cleanPath}|${cleanName}]]`;
                    }
                    
                    toolNames.push(toolName);
                    toolDates.push("N/A"); 
                }
            }
        }

        flatData.push({
            paese:      String(camp.country),
            attore:     p.file.link,
            malware:    toolNames.length > 0 ? toolNames.join("<br>") : "N/A",
            date_tools: toolDates.length > 0 ? toolDates.join("<br>") : "N/A",
            activity:   activity,   
            target:     finalTargets
        });
    }
}

let gruppi = {};
for (let item of flatData) {
    if (!gruppi[item.paese]) gruppi[item.paese] = [];
    gruppi[item.paese].push(item);
}

if (Object.keys(gruppi).length === 0) {
    dv.paragraph(" Nessun dato trovato.");
}

for (let paese in gruppi) {
    dv.header(2, paese);
    dv.table(
        ["Actor", "Tool/Malware", "Date Detected", "Activity", "Target"],
        gruppi[paese].map(row => [row.attore, row.malware, row.date_tools, row.activity, row.target])
    );
}


```
