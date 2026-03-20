```dataviewjs
let pages = dv.pages('"TTP_&_Malware"');
let flatData = [];

for (let p of pages) {
    let countries = [];
    if (p.dst_countries) {
        countries = Array.isArray(p.dst_countries) ? p.dst_countries : [p.dst_countries];
    } else {
        continue;
    }

    let actors = [];
    if (p.threat_actor) {
        actors = Array.isArray(p.threat_actor) ? p.threat_actor : [p.threat_actor];
    } else {
        actors = ["Unknown Actor"];
    }
    let activityName = p.file.link; 

    let date = "N/A";
    if (p.date_detection) {
        date = p.date_detection.toISODate ? p.date_detection.toISODate() : String(p.date_detection).substring(0, 10);
    }
    
    let mb = p.MainBranch ? (Array.isArray(p.MainBranch) ? p.MainBranch.join(", ") : String(p.MainBranch)) : "N/A";
    let target = p.target_industry ? (Array.isArray(p.target_industry) ? p.target_industry.join(", ") : String(p.target_industry)) : "N/A";

    for (let c of countries) {
        let countryName = String(c).trim();
        if (!countryName) continue;
        
        for (let a of actors) {
            let actorLink = String(a).trim();

            flatData.push({
                country: countryName,
                actor: actorLink,
                activity: activityName,
                date: date,
                mainBranch: mb,
                target: target
            });
        }
    }
}
let gruppi = {};
for (let item of flatData) {
    if (!gruppi[item.country]) gruppi[item.country] = {};
    if (!gruppi[item.country][item.actor]) gruppi[item.country][item.actor] = [];
    gruppi[item.country][item.actor].push(item);
}

if (Object.keys(gruppi).length === 0) {
    dv.paragraph("Nessun dato trovato.");
}
for (let country of Object.keys(gruppi).sort()) {
    dv.header(2, country);
    let rows = [];
    
    for (let actor of Object.keys(gruppi[country]).sort()) {
        let items = gruppi[country][actor];

        let activities = items.map(i => i.activity).join("<br>");
        let dates      = items.map(i => i.date).join("<br>");
        let mbs        = items.map(i => i.mainBranch).join("<br>");
        let targets    = items.map(i => i.target).join("<br>");

        rows.push([actor, activities, dates, mbs, targets]);
    }
    
    dv.table(["Actor", "Activity", "Date", "MainBranch", "Target"], rows);
}



```
