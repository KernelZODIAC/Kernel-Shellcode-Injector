import os
import sys

def create_shellcode_header(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        hex_data = ', '.join(f'0x{byte:02x}' for byte in file_data)
        current_dir = os.getcwd()
        header_file_path = os.path.join(current_dir, 'shellcode.h')
        with open(header_file_path, 'w') as header_file:
            header_file.write('#pragma once\n\n')
            header_file.write(f'unsigned char shellcode[] = {{ {hex_data} }};\n')
        print(f'shellcode.h created: {header_file_path}')
    except Exception as e:
        print(f'Error: {e}')

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python script.py <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print(f'File not found: {file_path}')
        sys.exit(1)
    create_shellcode_header(file_path)
