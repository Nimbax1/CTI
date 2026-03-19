import os
import re
import yaml
from collections import defaultdict

VAULT_ROOT = "."
ACTORS_DIR = "Actors"
MALWARE_DIR = "TTP_&_Malware"
README_FILE = "README.md"


def extract_yaml(content):
    match = re.search(r'^---\s*(.*?)\s*---', content, re.DOTALL | re.MULTILINE)
    if match:
        try:
            return yaml.safe_load(match.group(1))
        except Exception as e:
            print(f"Errore YAML: {e}")
            return None
    return None


def clean_obsidian_link(raw_link):
    link_str = str(raw_link).strip()
    match = re.search(r'\[\[(.*?)(?:\|.*?)?\]\]', link_str)
    if match:
        clean_name = match.group(1).split('/')[-1].replace('.md', '')
        return clean_name
    return link_str.replace('[[', '').replace(']]', '')


def build_vault_index():

    file_paths = {}
    file_targets = {}

    for root, dirs, files in os.walk(VAULT_ROOT):
        if '.git' in root or '.obsidian' in root:
            continue

        for file in files:
            if file.endswith('.md'):
                filepath = os.path.join(root, file)
                basename = file.replace('.md', '')

                rel_path = os.path.relpath(filepath, VAULT_ROOT).replace('\\', '/')
                file_paths[basename] = rel_path

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = extract_yaml(f.read())
                        if data and 'target_industry' in data:
                            targets = data['target_industry']
                            if not isinstance(targets, list):
                                targets = [targets]
                            file_targets[basename] = [str(t) for t in targets if t]
                except:
                    pass

    return file_paths, file_targets


def build_markdown_table():

    if not os.path.exists(ACTORS_DIR):
        print(f"Cartella {ACTORS_DIR} non trovata!")
        return ""

    paths_index, targets_index = build_vault_index()

    gruppi = defaultdict(list)

    for filename in os.listdir(ACTORS_DIR):
        if not filename.endswith('.md'): continue

        filepath = os.path.join(ACTORS_DIR, filename)
        actor_basename = filename.replace('.md', '')
        actor_link = f"[{actor_basename}](./{paths_index.get(actor_basename, filepath)})"

        with open(filepath, 'r', encoding='utf-8') as f:
            data = extract_yaml(f.read())

        if not data or 'campaigns' not in data: continue

        activity_raw = data.get('activity', [])
        if not isinstance(activity_raw, list): activity_raw = [activity_raw]

        activity_clean = []
        targets_trovati = set()

        for act in activity_raw:
            if not act: continue
            act_name = clean_obsidian_link(act)

            act_path = paths_index.get(act_name, '#')
            activity_clean.append(f"[{act_name}](./{act_path})")

            if act_name in targets_index:
                for t in targets_index[act_name]:
                    targets_trovati.add(t)

        activity_str = ", ".join(activity_clean) if activity_clean else "N/A"
        final_targets = ", ".join(sorted(list(targets_trovati))) if targets_trovati else "N/A"

        campaigns = data.get('campaigns', [])
        if not isinstance(campaigns, list): campaigns = [campaigns]

        for camp in campaigns:
            paese = camp.get('country')
            if not paese: continue

            tools = camp.get('tools', [])
            if not isinstance(tools, list): tools = [tools]

            tool_names = []
            tool_dates = []

            for t in tools:
                if isinstance(t, dict) and 'name' in t:
                    raw_name = t.get('name', '')
                    raw_date = t.get('date', 'N/A')
                else:
                    raw_name = str(t)
                    raw_date = "N/A"

                if not raw_name: continue

                clean_name = clean_obsidian_link(raw_name)
                malware_path = paths_index.get(clean_name, '#')
                linked_tool = f"[{clean_name}](./{malware_path})"

                tool_names.append(linked_tool)

                tool_dates.append(str(raw_date)[:10])

            malware_str = "<br>".join(tool_names) if tool_names else "N/A"
            dates_str = "<br>".join(tool_dates) if tool_dates else "N/A"

            record = f"| {actor_link} | {malware_str} | {dates_str} | {activity_str} | {final_targets} |"
            gruppi[paese].append(record)

    if not gruppi:
        return "*No data Found.*"

    final_md = ""
    for paese in sorted(gruppi.keys()):
        final_md += f"## {paese}\n\n"
        final_md += "| Actor | Tool/Malware | Date Detected | Activity | Target |\n"
        final_md += "|---|---|---|---|---|\n"
        final_md += "\n".join(gruppi[paese]) + "\n\n"

    return final_md


def update_readme(new_table_md):
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

        new_readme = part_before + start_marker + "\n\n" + new_table_md + "\n" + end_marker + part_after

        with open(README_FILE, 'w', encoding='utf-8') as f:
            f.write(new_readme)
        print("Done!")
    else:
        print("Not Done! Check .md files")

if __name__ == "__main__":
    markdown_output = build_markdown_table()
    update_readme(markdown_output)