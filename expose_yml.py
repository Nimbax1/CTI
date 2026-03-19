import os
import re
import yaml


def format_value(val):
    if val is None or val == "" or val == []:
        return ""

    if isinstance(val, (str, int, float)):
        return str(val)

    if isinstance(val, list):
        res = []
        for item in val:
            if isinstance(item, dict):
                dict_str = ", ".join(f"*{k}*: {format_value(v)}" for k, v in item.items())
                res.append(f"• {dict_str}")
            else:
                res.append(f"• {item}")
        return "<br>".join(res)

    if isinstance(val, dict):
        return "<br>".join(f"*{k}*: {format_value(v)}" for k, v in val.items())

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

                    try:
                        data = yaml.safe_load(yaml_content)
                        if not isinstance(data, dict):
                            continue

                        box = '??? abstract "Proprietà CTI (Clicca per espandere)"\n'
                        box += '    | Proprietà | Dettagli |\n'
                        box += '    |-----------|----------|\n'

                        for key, value in data.items():
                            formatted_val = format_value(value)
                            formatted_val = str(formatted_val).replace("\n", " ").replace("\r", "")

                            box += f'    | **{key}** | {formatted_val} |\n'

                        box += '\n\n'

                        new_content = f"---\n{yaml_content}\n---\n\n{box}{rest_of_content}"
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(new_content)

                    except yaml.YAMLError:
                        pass


if __name__ == '__main__':
    expose_yaml_in_docs()
