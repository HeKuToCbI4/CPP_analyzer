#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from UI import UI
from src.buffer_overflow import BufOverflowParser
from src.format_string import FormatStringParser
from src.sql_injection import SQLInjectionParser
from src.crypto_gen import RandomGenParser
from src.exec_of_commands import ExecOfCommands
from src.race_condition import RaceConditionParser
from src.integer_overflow import IntegerOverflowParser

HANDLER = {
    "Buffer Overflow": BufOverflowParser,
    "Format String Vulnerability": FormatStringParser,
    "SQL injection": SQLInjectionParser,
    "Command Injection": ExecOfCommands,
    # "Neglect of Error Handling":		None,
    # "Bad Data Storage Management":		None,
    # "Data Leak":						None,
    "Not Crypto-resistant Algorithms": RandomGenParser,
    "Integer Overflow":				IntegerOverflowParser,
    "Race Condition":					RaceConditionParser,
    # "Readers–writers problem":			None,
    # "Locked Mutexes problem":         None
}


def commentRemover(text):
    import re
    pattern = re.compile(r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"', re.DOTALL | re.MULTILINE)
    replacer = lambda match: None if match.group(0).startswith('/') else match.group(0)
    return re.sub(pattern, replacer, text)

if __name__ == '__main__':
    from re import match

    CLEAN_CODE = lambda program: [line.lstrip() for line in commentRemover(open(program, 'r').read()).splitlines() if
                                  not match(r'^\s*$', line)]

    ui = UI(HANDLER.keys())  #
    ui.StartMain(lambda vulnerability, program: HANDLER[vulnerability]().parse(CLEAN_CODE(program)))
