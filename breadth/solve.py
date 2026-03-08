#!/usr/bin/env python3
"""
PicoCTF "breadth" Challenge Solution

Challenge: The in-development version (v1) had a bug where the function with
           the real flag compared against the wrong constant, preventing the
           flag from being printed.

Analysis:
- Both v1 and v2 contain the same flag: picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}
- In function fcnkKTQpF at offset 0x95040:

  v1 (buggy):
    mov qword [rsp+var_10], 0x41bc73e    # Store correct value
    mov rdx, qword [rsp+var_10]
    mov eax, 0xd037803a                  # WRONG: loads incorrect constant
    cmp rdx, rax                         # Compare: 0x41bc73e != 0xd037803a
    je loc_95060                         # Never jumps, flag never printed
    ret

  v2 (fixed):
    mov qword [rsp+var_10], 0x41bc73e    # Store correct value
    mov rax, qword [rsp+var_10]
    cmp rax, 0x41bc73e                   # CORRECT: compares same value
    je loc_95060                         # Jumps and prints flag
    ret

  loc_95060:
    lea rdi, [aPicoctfvndb2lu]           # Load flag string
    jmp j_puts                           # Print flag
"""

FLAG = "picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}"

if __name__ == "__main__":
    print(f"Flag: {FLAG}")
