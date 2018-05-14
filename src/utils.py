import re
import collections


# regexp for: auto i; int i; std::vector<std::string> ....
# TODO: rewrite pattern to avoid detection return as type
regex_declaration = r"^\s*(extern\s+)?(unsigned|signed)?\s*(const\s+)?(int|short|char|long|double|float|byte)[\s*]([a-zA-Z0-9_:<>]*).*(;)"

# regexp for raw arrays: char a[10]; ...
regex_array = r'([a-zA-Z0-9_:<>]*\s)([a-zA-Z_][a-zA-Z0-9_:<>]*)(\[([^\]]+)])'


def get_declareted_variables(code):
    row_counter = 0
    parse_tuple = collections.namedtuple('Metainfo', ['line', 'type', 'name'])
    metainfo = []
    for line in code:
        row_counter += 1
        result = re.finditer(regex_declaration, line)
        for matchNum, match in enumerate(result):
            matchNum = matchNum + 1
            # TODO: make regex great again
            if match.group(1) != 'return':
                temp_info = parse_tuple(line = row_counter, type = match.group(4), name = match.group(5))
                metainfo.append(temp_info)
    return metainfo
