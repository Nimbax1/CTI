import os
import re


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

                    box = '??? abstract "Proprietà CTI (Clicca per espandere)"\n'
                    for line in yaml_content.split('\n'):
                        indent = len(line) - len(line.lstrip())
                        spaces = ' ' * indent
                        clean_line = line.strip()

                        if not clean_line:
                            continue

                        if ':' in clean_line and not clean_line.startswith('-'):
                            parts = clean_line.split(':', 1)
                            key = parts[0].strip()
                            value = parts[1].strip()
                            if value:
                                box += f'    {spaces}**{key}**: {value}  \n'
                            else:
                                box += f'    {spaces}**{key}**:  \n'
                        else:
                            box += f'    {spaces}{clean_line}  \n'

                    box += '\n\n'

                    new_content = f"---\n{yaml_content}\n---\n\n{box}{rest_of_content}"
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)


if __name__ == '__main__':
    expose_yaml_in_docs()
