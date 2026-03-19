import os
import re
import yaml
from collections import defaultdict

VAULT_ROOT = "."
ACTORS_DIR = "Actors"
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
            return lower_dict_keys(parsed) if parsed else None
        except Exception as e:
            print(f"YAML Error: {e}")
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


def build_actors_table(paths_index, targets_index):
    if not os.path.exists(ACTORS_DIR):
        print(f"Directory {ACTORS_DIR} not found!")
        return ""

    groups = defaultdict(list)

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
        found_targets = set()

        for act in activity_raw:
            if not act: continue
            act_name = clean_obsidian_link(act)

            act_path = paths_index.get(act_name, '#')
            activity_clean.append(f"[{act_name}](./{act_path})")

            if act_name in targets_index:
                for t in targets_index[act_name]:
                    found_targets.add(t)

        activity_str = ", ".join(activity_clean) if activity_clean else "N/A"
        final_targets = ", ".join(sorted(list(found_targets))) if found_targets else "N/A"

        campaigns = data.get('campaigns', [])
        if not isinstance(campaigns, list): campaigns = [campaigns]

        for camp in campaigns:
            if not isinstance(camp, dict): continue

            country = camp.get('country')
            if not country: continue

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
            groups[country].append(record)

    if not groups:
        return "*No data found for Actors.*"

    final_md = "## Actors by Country\n\n"
    for country in sorted(groups.keys()):
        final_md += f"### {country}\n\n"
        final_md += "| Actor | Tool/Malware | Date Detected | Activity | Target |\n"
        final_md += "|---|---|---|---|---|\n"
        final_md += "\n".join(groups[country]) + "\n\n"

    return final_md


def build_malware_table(paths_index):
    if not os.path.exists(MALWARE_DIR):
        print(f"Directory {MALWARE_DIR} not found!")
        return ""

    flat_data = []

    for filename in os.listdir(MALWARE_DIR):
        if not filename.endswith('.md'): continue

        filepath = os.path.join(MALWARE_DIR, filename)
        basename = filename.replace('.md', '')
        malware_link = f"[{basename}](./{paths_index.get(basename, filepath)})"

        with open(filepath, 'r', encoding='utf-8') as f:
            data = extract_yaml(f.read())

        if not data: continue

        main_branch_raw = data.get('mainbranch', [])
        if not main_branch_raw:
            continue

        if not isinstance(main_branch_raw, list): main_branch_raw = [main_branch_raw]
        main_branch_str = ", ".join(str(b) for b in main_branch_raw if b)

        capabilities_raw = data.get('capabilities', [])
        if not isinstance(capabilities_raw, list): capabilities_raw = [capabilities_raw]
        capabilities_str = ", ".join(str(c) for c in capabilities_raw if c) or "N/A"

        all_dest_countries = set()
        all_origins = set()
        all_dates = set()
        all_actors = set()

        threat_actors = data.get('threat_actor', [])
        if not isinstance(threat_actors, list): threat_actors = [threat_actors]

        for actor in threat_actors:
            if not actor: continue

            actor_clean = clean_obsidian_link(actor)
            actor_path = paths_index.get(actor_clean, '#')
            all_actors.add(f"[{actor_clean}](./{actor_path})")

            actor_rel_path = paths_index.get(actor_clean)
            if actor_rel_path:
                actor_real_path = os.path.join(VAULT_ROOT, actor_rel_path)
                try:
                    with open(actor_real_path, 'r', encoding='utf-8') as af:
                        actor_data = extract_yaml(af.read())
                except:
                    actor_data = None

                if actor_data:
                    origins = actor_data.get('origin', [])
                    if not isinstance(origins, list): origins = [origins]
                    for o in origins:
                        if o: all_origins.add(str(o))

                    campaigns = actor_data.get('campaigns', [])
                    if not isinstance(campaigns, list): campaigns = [campaigns]

                    for camp in campaigns:
                        if not isinstance(camp, dict): continue

                        country = camp.get('country')
                        if country: all_dest_countries.add(str(country))

                        tools = camp.get('tools', [])
                        if not isinstance(tools, list): tools = [tools]

                        for t in tools:
                            if isinstance(t, dict):
                                t_name = str(t.get('name', ''))
                                t_date = str(t.get('date', 'N/A'))
                            else:
                                t_name = str(t)
                                t_date = 'N/A'

                            if basename.lower() in t_name.lower() and t_date != 'N/A':
                                all_dates.add(t_date[:10])

        dest_str = ", ".join(sorted(list(all_dest_countries))) if all_dest_countries else "N/A"
        orig_str = ", ".join(sorted(list(all_origins))) if all_origins else "N/A"
        date_str = ", ".join(sorted(list(all_dates))) if all_dates else "N/A"
        actor_str = ", ".join(sorted(list(all_actors))) if all_actors else "N/A"
        mb_str = main_branch_str if main_branch_str else "N/A"

        record = f"| {malware_link} | {dest_str} | {orig_str} | {date_str} | {actor_str} | {mb_str} | {capabilities_str} |"
        flat_data.append((mb_str, basename, record))

    if not flat_data:
        return "*No data found for Malware.*"

    flat_data.sort(key=lambda x: (x[0], x[1]))

    final_md = "## TTP & Malware (All MainBranches)\n\n"
    final_md += "| File Malware | Dest Countries | Origin | Date detection | Threat Actor | MainBranch | Capabilities |\n"
    final_md += "|---|---|---|---|---|---|---|\n"
    for item in flat_data:
        final_md += item[2] + "\n"
    final_md += "\n"

    return final_md


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
        print("Done!")
    else:
        print("Not Done! Markers <!-- TABELLA_START --> or <!-- TABELLA_END --> not found in README.md.")


if __name__ == "__main__":
    print("Indexing Vault...")
    paths_index, targets_index = build_vault_index()

    print("Building Actors table...")
    actors_md = build_actors_table(paths_index, targets_index)

    print("Building Malware table...")
    malware_md = build_malware_table(paths_index)

    combined_md = actors_md + "---\n\n" + malware_md

    print("Updating README...")
    update_readme(combined_md)
