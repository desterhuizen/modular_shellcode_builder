import unittest
from unittest.mock import patch, MagicMock
import sys

import shellcode_blocks

class TestShellcodeBlocks(unittest.TestCase):
    def test_parse_arguments_defaults(self):
        test_args = ['prog']
        with patch.object(sys, 'argv', test_args):
            args = shellcode_blocks.parse_arguments()
            self.assertEqual(args.command, [])
            self.assertEqual(args.language, 'python')
            self.assertEqual(args.variable, 'buf')

    def test_validate_arguments_winexec_with_lhost_lport(self):
        args = MagicMock()
        args.exec = 'WIN_EXEC'
        args.lhost = '127.0.0.1'
        args.lport = 4444
        with patch('shellcode_blocks.print_info'), self.assertRaises(SystemExit):
            shellcode_blocks.validate_arguments(args)

    def test_validate_arguments_missing_lhost_or_lport(self):
        args = MagicMock()
        args.exec = 'CREATE_PROCESS'
        args.lhost = '127.0.0.1'
        args.lport = None
        with patch('shellcode_blocks.print_info'), self.assertRaises(SystemExit):
            shellcode_blocks.validate_arguments(args)
        args.lhost = None
        args.lport = 4444
        with patch('shellcode_blocks.print_info'), self.assertRaises(SystemExit):
            shellcode_blocks.validate_arguments(args)

    @patch('shellcode_blocks.create_asm_start', return_value='start;')
    @patch('shellcode_blocks.find_kernel32', return_value='find;')
    @patch('shellcode_blocks.resolve_kernel32_functions', return_value='resolve;')
    @patch('shellcode_blocks.get_ip_hex', return_value='0x0100007f')
    @patch('shellcode_blocks.get_port_hex', return_value='0x115c')
    @patch('shellcode_blocks.load_ws2_32_and_resolve_symbols', return_value='ws2;')
    @patch('shellcode_blocks.create_socket_and_connect', return_value='sock;')
    def test_generate_shellcode_reverse_shell(self, *mocks):
        args = MagicMock()
        args.lhost = '127.0.0.1'
        args.lport = 4444
        args.force_break = False
        args.verbose = False
        args.force_break_functions = False
        asm = shellcode_blocks.generate_shellcode(args)
        self.assertIn('start;', asm)
        self.assertIn('sock;', asm)

    @patch('shellcode_blocks.create_asm_start', return_value='start;')
    @patch('shellcode_blocks.find_kernel32', return_value='find;')
    @patch('shellcode_blocks.resolve_kernel32_functions', return_value='resolve;')
    @patch('shellcode_blocks.change_command_to_memory_hex', return_value=[{'hex': '646d63'}])
    @patch('shellcode_blocks.create_command_string', return_value='cmdstr;')
    @patch('shellcode_blocks.create_startup_info_a', return_value='startup;')
    @patch('shellcode_blocks.create_process_a', return_value='proc;')
    def test_generate_shellcode_command(self, *mocks):
        args = MagicMock()
        args.lhost = None
        args.lport = None
        args.command = ['cmd.exe']
        args.force_break = False
        args.verbose = False
        args.force_break_functions = False
        asm = shellcode_blocks.generate_shellcode(args)
        self.assertIn('cmdstr;', asm)
        self.assertIn('startup;', asm)
        self.assertIn('proc;', asm)

if __name__ == '__main__':
    unittest.main()