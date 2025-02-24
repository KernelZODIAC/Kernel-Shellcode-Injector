# Kernel ShellCode Injector
# Overview

This project is a Windows x64 kernel driver (PoC) that enables shellcode injection into user-mode processes from the kernel.

# Tested system

- Windows 10 22h2 & Windows 11 24h2 x64.
# Information

- Use `shellcode-creator.py` to generate shellcode in the required format.
- Modify the target process as needed.

# Additional Sources

- `getssdt.h` is based on [TitanHide](https://github.com/mrexodia/TitanHide).
