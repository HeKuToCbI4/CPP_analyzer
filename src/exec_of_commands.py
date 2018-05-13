import utils
import base_parser
import collections
import re


class ExecOfCommands(base_parser.BaseParser): 
    def __init__(self):
        self.output = []
        self.vuln_name = 'Execution of Commands'
        self.pattern = [r'(system|popen|execlp|execvp|ShellExecute)']
    
    def parse(self, cpp_code):
        line_counter = 0
        for line in cpp_code:
            line_counter += 1
            
            # unsafety functions 
            matches = re.finditer(self.pattern[0], line, re.IGNORECASE)
            for matchNum, match in enumerate(matches):
                matchNum = matchNum + 1
                self.output.append(base_parser.warning(line_counter, str(line), self.vuln_name, 'WARNING', 'Usage of unsafety functions. Possible execution of command'))
            
        return self.output
