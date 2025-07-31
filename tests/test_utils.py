import unittest
from unittest.mock import patch
import io
import struct
from utils import (
    ror_str, calculate_function_hash, get_ip_hex, get_port_hex,
    make_print_friendly_asm, change_command_to_memory_hex, create_command_string, print_info, SUCCESS, FAIL,
    add_negated_value, create_asm_start, resolve_kernel32_functions
)

class TestUtils(unittest.TestCase):
    def test_ror_str(self):
        # Test right rotate by 1 on 0b1001 (32-bit)
        self.assertEqual(ror_str(0b1001, 1), 0b10000000000000000000000000000100)
        # Test right rotate by 4 on 0x12345678 (should match actual function output)
        self.assertEqual(ror_str(0x12345678, 4), 0x81234567)
        # Test rotating 0 by any count returns 0
        self.assertEqual(ror_str(0, 5), 0)
        # Test rotating a full 32 bits returns the original value
        self.assertEqual(ror_str(0xDEADBEEF, 32), 0xDEADBEEF)

    def test_calculate_function_hash(self):
        h = calculate_function_hash('CreateProcessA')
        self.assertIsInstance(h, str)
        self.assertTrue(h.startswith('0x'))

    def test_get_ip_hex(self):
        self.assertEqual(get_ip_hex('127.0.0.1'), '0x0100007f')
        self.assertEqual(get_ip_hex('192.168.1.1'), '0x0101a8c0')

    def test_get_ip_hex_invalid(self):
        self.assertEqual(get_ip_hex('127.0.0.1.1'), False)

    def test_get_port_hex(self):
        port = 4444
        packed = struct.pack('<h', port)
        expected = "0x" + "".join("{:02x}".format(c) for c in packed)
        self.assertEqual(get_port_hex(port), expected)

    def test_make_print_friendly_asm(self):
        asm = "label:mov eax, ebx;add eax, 1;"
        formatted = make_print_friendly_asm(asm)
        self.assertIn('label:', formatted)
        self.assertIn('mov eax, ebx', formatted)

    def test_change_command_to_memory_hex(self):
        chunks = change_command_to_memory_hex('cmd', [], False)
        self.assertIsInstance(chunks, list)
        self.assertTrue(all('hex' in c for c in chunks))

        chunks = change_command_to_memory_hex('aaaaa', [], False)
        self.assertIsInstance(chunks, list)
        self.assertTrue(all('hex' in c for c in chunks))

    def test_create_command_string(self):
        chunks = [{'hex': '646d63'}]  # 'cmd' in hex, little-endian
        asm = create_command_string(chunks, 0, False, False)
        self.assertIn('push', asm)
        self.assertIn('pop   ebx', asm)

        chunks = [{'hex': '646d63'}]  # 'cmd' in hex, little-endian
        asm = create_command_string(chunks, 0, False, True)
        self.assertIn('int3', asm)
        self.assertIn('push', asm)
        self.assertIn('pop   ebx', asm)

        chunks = [{'hex': '646d63', 'func': 'neg'}]  # 'cmd' in hex, little-endian
        asm = create_command_string(chunks, 0, False, True)
        self.assertIn('int3', asm)
        self.assertIn('push', asm)
        self.assertIn('neg   eax', asm)

    def test_print_info_success_0(self):
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            print_info('Test', SUCCESS, 0, True)
            self.assertIn('[+] Test', fake_out.getvalue())
    def test_print_info_success_1(self):
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            print_info('Test', SUCCESS, 1, True)
            self.assertIn('   | Test', fake_out.getvalue())

    def test_print_info_fail(self):
        with patch('sys.stdout', new=io.StringIO()) as fake_out:
            print_info('Test', FAIL, 0, True)
            self.assertIn('[-] Test', fake_out.getvalue())


    def test_add_negated_value(self):

        # Example hex for 'cmd\0' in little-endian: ff6d6400
        cmd_hex = '636d64ff'
        asm = add_negated_value(cmd_hex, verbose=False)
        # Check that the assembly code contains all required instructions
        self.assertIn('mov   eax, 0xff646d63', asm)
        self.assertIn('neg   eax', asm)
        self.assertIn('dec   al', asm)
        self.assertIn('push  eax', asm)

    def test_create_asm_start(self):
        # Test without force_break
        asm_normal = create_asm_start(False)
        self.assertIn("start:", asm_normal)
        self.assertIn("mov     ebp, esp", asm_normal)
        self.assertIn("add     esp, 0xfffff9f0", asm_normal)
        self.assertNotIn("int3", asm_normal)

        # Test with force_break enabled
        asm_with_break = create_asm_start(True)
        self.assertIn("start:", asm_with_break)
        self.assertIn("int3", asm_with_break)
        self.assertIn("mov     ebp, esp", asm_with_break)
        self.assertIn("add     esp, 0xfffff9f0", asm_with_break)

    def test_resolve_kernel32_functions(self):
        # Test without force_break
        asm_normal = resolve_kernel32_functions('CreateProcessA', verbose=False, force_break=False)
        self.assertIn("resolve_kernel32_funcitons:", asm_normal)
        self.assertNotIn("int3", asm_normal)
        self.assertIn("push 0x", asm_normal)  # Should contain hash pushes
        self.assertIn("call dword ptr [ebp+0x04]", asm_normal)
        self.assertIn("mov   [ebp+0x10], eax", asm_normal)  # First function storage
        self.assertIn("mov   [ebp+0x14], eax", asm_normal)  # Second function storage
        self.assertIn("mov   [ebp+0x18], eax", asm_normal)  # Third function storage

        # Test with force_break
        asm_with_break = resolve_kernel32_functions('WinExec', verbose=False, force_break=True)
        self.assertIn("resolve_kernel32_funcitons:", asm_with_break)
        self.assertIn("int3", asm_with_break)

        asm_verbose = resolve_kernel32_functions(verbose=True)
        self.assertIsInstance(asm_verbose, str)
if __name__ == '__main__':
    unittest.main()