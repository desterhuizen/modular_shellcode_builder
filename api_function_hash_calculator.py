"""
This script calculates a hash value for a given input string using a custom algorithm.
The algorithm involves summing the ASCII values of the characters in the string,
and performing a right rotate operation on the sum after each character, except for the last one.

The hash values are used by the shell_code_blocks.py script to find functions in the system API that match the hash.
"""

#!/usr/bin/python
import sys
from utils import calculate_function_hash

if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    edx = calculate_function_hash(esi)
    print(edx)