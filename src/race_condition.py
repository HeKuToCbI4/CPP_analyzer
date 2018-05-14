import base_parser
import collections
import re
import utils

class RaceConditionParser(base_parser.BaseParser):
    def __init__(self):
        self.output = []
        self.vuln_name = 'Race Conditions'

    def parse(self, cpp_code):
        line_counter = 0
        same_variable_names = []
        for variable in utils.get_declareted_variables(cpp_code):
            if variable.name not in same_variable_names:
                same_variable_names.append(variable.name)
            else:
                self.output.append(base_parser.warning(line_counter, str(variable.line), self.vuln_name, 'CRITICAL',
                                                       'Usage of same variable names, possible races.'))
        return self.output


if __name__ == "__main__":
    with open("../tests/race_condition_test.cpp") as file:
        parser = RaceConditionParser()
        out = parser.parse(file)
        for state in out:
            print(state)
