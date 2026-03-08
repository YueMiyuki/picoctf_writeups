# breadth

## Challenge Information

- **Author**: asphyxia
- **Category**: Reverse Engineering

## What's up

This challenge provides two versions of the same binary:
- `breadth.v1`: In-development version with a bug
- `breadth.v2`: Fixed version

## Solution Process

### Disassemble

The challenge provides disassembled assembly files for both versions. Since the hint mentions that v1 has a mistake in the function with the real flag, the most efficient approach is to compare the two versions to find the difference.

### See diff

Using `diff` to compare the assembly files:

```bash
diff src/breadth.v1.asm src/breadth.v2.asm
```
```
---
> 0000000000095057         align      32
304624c304623
< 0000000000095060         lea        rdi, qword [aPicoctfvndb2lu]                ; argument "__s" for method j_puts, "picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}", CODE XREF=fcnkKTQpF+22
---
> 0000000000095060         lea        rdi, qword [aPicoctfvndb2lu]                ; argument "__s" for method j_puts, "picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}", CODE XREF=fcnkKTQpF+20 
```

## Flag

```
picoCTF{VnDB2LUf1VFJkdfDJtdYtFlMexPxXS6X}
```