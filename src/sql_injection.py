import utils
import base_parser
import collections
import re


class SQLInjectionParser(base_parser.BaseParser): 
    def __init__(self):
        self.output = []
        self.vuln_name = 'SQL Injection'
        self.pattern = [r'mysql_query\(|sql_exec\(|query_exec\(']
    
    def parse(self, cpp_code):
        line_counter = 0
        for line in cpp_code:
            line_counter += 1
             
            matches = re.finditer(self.pattern[0], line, re.IGNORECASE)
            for matchNum, match in enumerate(matches):
                matchNum = matchNum + 1
                self.output.append(base_parser.warning(line_counter, str(line), self.vuln_name, 'WARNING', 'possible SQL Injection'))
            
        return self.output
            
if __name__ == "__main__":
    with open("../tests/sql_test.cpp") as file:
        parser = SQLInjectionParser()
        out = parser.parse(file)
        for state in out:
            print(state)