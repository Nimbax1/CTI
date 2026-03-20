import os
import re
import yaml
from collections import defaultdict

VAULT_ROOT = "."
MALWARE_DIR = "TTP_&_Malware"
README_FILE = "README.md"


def lower_dict_keys(x):
    if isinstance(x, dict):
        return {str(k).lower(): lower_dict_keys(v) for k, v in x.items()}
    elif isinstance(x, list):
        return [lower_dict_keys(v) for v in x]
    else:
        return x


def extract_yaml(content):
    match = re.search(r'^---\s*(.*?)\s*---', content, re.DOTALL | re.MULTILINE)
    if match:
        try:
            parsed = yaml.safe_load(match.group(1))
            return lower_dict_keys(parsed) if parsed else {}
        except:
            return {}
    return {}


def parse_array(val):
    if not val: return []
    if isinstance(val, list): return val
    return [val]


def clean_link(val):
    if not val: return "N/A"
    val = str(val).strip()
    m = re.search(r'\[\[(.*?)(?:\|.*?)?\]\]', val)
    if m: return m.group(1).split('/')[-1].replace('.md', '')
    return val.replace('[[', '').replace(']]', '')


def make_md_link(raw_val, paths_index):
    if not raw_val: return "N/A"
    clean = clean_link(raw_val)
    if clean.lower() in paths_index:
        return f"[{clean}](./{paths_index[clean.lower()]})"
    return clean


def build_vault_index():
    idx = {}
    for root, _, files in os.walk(VAULT_ROOT):
        if '.git' in root or '.obsidian' in root: continue
        for f in files:
            if f.endswith('.md'):
                idx[f[:-3].lower()] = os.path.relpath(os.path.join(root, f), VAULT_ROOT).replace('\\', '/')
    return idx

def build_malware_table(paths_index):
    if not os.path.exists(MALWARE_DIR):
        return "Nessun dato trovato in TTP_&_Malware"

    flat_data = []

    for filename in os.listdir(MALWARE_DIR):
        if not filename.endswith('.md'): continue
        if filename.lower() == 'index.md': continue

        filepath = os.path.join(MALWARE_DIR, filename)
        basename = filename[:-3]

        with open(filepath, 'r', encoding='utf-8') as f:
            data = extract_yaml(f.read())
        if not data: continue

        mb = parse_array(data.get('mainbranch'))
        mb_str = ", ".join(make_md_link(x, paths_index) for x in mb) if mb else "N/A"

        cap = parse_array(data.get('capabilities'))
        cap_str = ", ".join(str(x) for x in cap) if cap else "N/A"

        dst = parse_array(data.get('dst_countries'))
        dst_str = ", ".join(str(x) for x in dst) if dst else "N/A"

        orig = parse_array(data.get('origin'))
        orig_str = ", ".join(str(x) for x in orig) if orig else "N/A"

        act = parse_array(data.get('threat_actor'))
        act_str = ", ".join(make_md_link(x, paths_index) for x in act) if act else "N/A"

        date_raw = data.get('date_detection')
        date_str = str(date_raw)[:10] if date_raw else "N/A"

        file_link = f"[{basename}](./{paths_index.get(basename.lower(), filepath)})"

        flat_data.append([file_link, dst_str, orig_str, date_str, act_str, mb_str, cap_str])

    if not flat_data:
        return "Nessun dato trovato in TTP_&_Malware"

    md = "## TTP & Malware\n\n"
    md += "| File Malware | Dest Countries | Origin | Date detection | Threat Actor | MainBranch | Capabilities |\n"
    md += "|---|---|---|---|---|---|---|\n"
    for item in sorted(flat_data, key=lambda x: x[0]):
        md += "| " + " | ".join(item) + " |\n"

    return md + "\n"

def build_actors_table(paths_index):
    if not os.path.exists(MALWARE_DIR):
        return "Nessun dato trovato."

    flat_data = []

    for filename in os.listdir(MALWARE_DIR):
        if not filename.endswith('.md'): continue
        if filename.lower() == 'index.md': continue

        filepath = os.path.join(MALWARE_DIR, filename)
        basename = filename[:-3]

        with open(filepath, 'r', encoding='utf-8') as f:
            data = extract_yaml(f.read())
        if not data: continue

        countries = parse_array(data.get('dst_countries'))
        if not countries: continue

        actors = parse_array(data.get('threat_actor'))
        if not actors: actors = ["Unknown Actor"]

        activityName = f"[{basename}](./{paths_index.get(basename.lower(), filepath)})"

        date_raw = data.get('date_detection')
        date_str = str(date_raw)[:10] if date_raw else "N/A"

        mb = parse_array(data.get('mainbranch'))
        mb_str = ", ".join(make_md_link(x, paths_index) for x in mb) if mb else "N/A"

        target = parse_array(data.get('target_industry'))
        target_str = ", ".join(str(x) for x in target) if target else "N/A"

        for c in countries:
            c_name = str(c).strip()
            if not c_name: continue

            for a in actors:
                a_name = str(a).strip()
                a_link = make_md_link(a_name, paths_index) if a_name != "Unknown Actor" else "Unknown Actor"

                flat_data.append({
                    "country": c_name,
                    "actor": a_link,
                    "activity": activityName,
                    "date": date_str,
                    "mainBranch": mb_str,
                    "target": target_str
                })

    groups = defaultdict(lambda: defaultdict(list))
    for item in flat_data:
        groups[item['country']][item['actor']].append(item)

    if not groups:
        return "Nessun dato trovato."

    md = "## Actors Activity by Country\n\n"
    for country in sorted(groups.keys()):
        md += f"### {country}\n\n"
        md += "| Actor | Activity | Date | MainBranch | Target |\n"
        md += "|---|---|---|---|---|\n"

        for actor in sorted(groups[country].keys()):
            items = groups[country][actor]
            activities = "<br>".join(i['activity'] for i in items)
            dates = "<br>".join(i['date'] for i in items)
            mbs = "<br>".join(i['mainBranch'] for i in items)
            targets = "<br>".join(i['target'] for i in items)

            md += f"| {actor} | {activities} | {dates} | {mbs} | {targets} |\n"
        md += "\n"

    return md

def update_readme(new_content_md):
    if not os.path.exists(README_FILE):
        print(f"File {README_FILE} not found!")
        return

    with open(README_FILE, 'r', encoding='utf-8') as f:
        readme = f.read()

    start_marker = "<!-- TABELLA_START -->"
    end_marker = "<!-- TABELLA_END -->"

    if start_marker in readme and end_marker in readme:
        part_before = readme.split(start_marker)[0]
        part_after = readme.split(end_marker)[-1]

        new_readme = part_before + start_marker + "\n\n" + new_content_md + end_marker + part_after

        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(new_readme)
        print("Done! README updated.")
    else:
        print("Not Done! Markers <!-- TABELLA_START --> or <!-- TABELLA_END --> not found in README.md.")


if __name__ == "__main__":
    print("Indexing Vault...")
    paths_index = build_vault_index()

    print("Building Malware table...")
    malware_md = build_malware_table(paths_index)

    print("Building Actors by Country table...")
    actors_md = build_actors_table(paths_index)

    combined_md = malware_md + "---\n\n" + actors_md

    print("Updating README...")
    update_readme(combined_md)
