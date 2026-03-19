import os
import re
import yaml


def format_value(val):
    if val is None or val == "" or val == []:
        return ""

    if isinstance(val, (str, int, float, bool)):
        return str(val)

    if isinstance(val, list):
        items = []
        for item in val:
            if isinstance(item, dict):
                if 'name' in item and 'date' in item:
                    items.append(f"<li>{item.get('name')} (<em>{item.get('date')}</em>)</li>")
                else:
                    items.append(f"<li>{format_value(item)}</li>")
            else:
                items.append(f"<li>{item}</li>")

        return f"<ul style='margin: 0; padding-left: 20px;'>{''.join(items)}</ul>"

    if isinstance(val, dict):
        items = []
        for k, v in val.items():
            if isinstance(v, list):
                items.append(f"<b>{str(k).capitalize()}:</b><br>{format_value(v)}")
            else:
                items.append(f"<b>{str(k).capitalize()}:</b> {format_value(v)}")

        return "<br>".join(items)

    return str(val)


def expose_yaml_in_docs():
    for root, dirs, files in os.walk('docs'):
        for file in files:
            if file.endswith('.md'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                match = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n(.*)', content, re.DOTALL)
                if match:
                    yaml_content = match.group(1)
                    rest_of_content = match.group(2)

                    rest_of_content = re.sub(
                        r'\?\?\? abstract "CTI Properties \(Click to expand\)".*?(?=\n#|\Z)',
                        '',
                        rest_of_content,
                        flags=re.DOTALL
                    ).lstrip()

                    try:
                        data = yaml.safe_load(yaml_content)
                        if not isinstance(data, dict):
                            continue

                        box = '??? abstract "CTI Properties (Click to expand)"\n'
                        box += '    | Property | Details |\n'
                        box += '    |----------|---------|\n'

                        for key, value in data.items():
                            formatted_val = format_value(value)
                            formatted_val = str(formatted_val).replace("\n", "").replace("\r", "")

                            box += f'    | **{key}** | {formatted_val} |\n'

                        box += '\n\n'

                        new_content = f"---\n{yaml_content}\n---\n\n{box}{rest_of_content}"
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(new_content)

                    except yaml.YAMLError as e:
                        print(f"YAML Error in {filepath}: {e}")


if __name__ == '__main__':
    expose_yaml_in_docs()
