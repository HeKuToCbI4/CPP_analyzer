import utils
import base_parser
import collections
import re


class BufOverflowParser(base_parser.BaseParser): 
    def __init__(self):
        self.output = []
        self.vuln_name = 'Buffer Overflow'
        self.pattern = [r'(strcpy|printf|strcat|memcpy|gets|sprintf|vsprintf|strncpy|scanfs|sscanf|snscanf|strlen)',
                        r'([a-zA-Z0-9_:<>]*\s)([a-zA-Z_][a-zA-Z0-9_:<>]*)(\[([^\]]+)])']
    
    def parse(self, cpp_code):
        line_counter = 0
        for line in cpp_code:
            line_counter += 1
            
            # unsafety functions 
            matches = re.finditer(self.pattern[0], line, re.IGNORECASE)
            for matchNum, match in enumerate(matches):
                matchNum = matchNum + 1
                self.output.append(base_parser.warning(line_counter, str(line), self.vuln_name, 'WARNING', 'Usage of unsafety functions. Possible bufferoveflow'))
            
            # raw arrays 
            matches = re.finditer(self.pattern[1], line, re.IGNORECASE)
            for matchNum, match in enumerate(matches):
                matchNum = matchNum + 1
                if match.group(1) != ' ':
                    self.output.append(base_parser.warning(line_counter, str(line), self.vuln_name, 'WARNING', 'Usage of raw arrays. Possible bufferoveflow'))
        return self.output


if __name__ == "__main__":
    with open("../tests/bufover_test.cpp") as file:
        parser = BufOverflowParser()
        out = parser.parse(file)
        for state in out:
            print(state)