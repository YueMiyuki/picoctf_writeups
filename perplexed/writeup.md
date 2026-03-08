# Perplexed

Binary reversing. Find the password. There's a `check` function at `0x401156` that does the validation.

## First look

```
$ ./perplexed
Enter the password: Eeeee
Wrong :(
```

The binary wants exactly 27 characters:

```asm
call       j_strlen
cmp        rax, 0x1b  ; 27
```

## What the check function does

Three 8-byte constants get loaded onto the stack:

```asm
movabs     rax, 0x617b2375f81ea7e1
movabs     rdx, 0xd269df5b5afc9db9
movabs     rax, 0xf467edf4ed1bfed2
```

They land at `var_50` (rbp-80), `var_48` (rbp-72), and `var_41` (rbp-65).

Here's the tricky part: `var_41` is at rbp-65, which overlaps `var_48` by one byte. When the code indexes through `[rbp+rax+var_50]`, it accesses 23 bytes total:
- Bytes 0--7: from var_50
- Bytes 8--15: from var_48
- Bytes 16--22: from var_41[1:7] (byte 0 of var_41 is never touched)

## The skip trick

There's a sneaky check at `loc_4011d6`:

```asm
loc_4011d6:
    cmp        dword [rbp+var_18], 0x0
    jne        loc_4011e0
    add        dword [rbp+var_18], 0x1    ; if 0, bump to 1
```

At the start of each inner loop iteration, if `var_18` is 0, it gets bumped to 1. This means password bit 7 (the MSB) is never checked -- the algorithm starts from bit 6 every time.

## Bit-by-bit comparison

Both sides extract bits MSB-first:

```asm
; data bit at position (7 - var_20)
mov        eax, 0x7
sub        eax, dword [rbp+var_20]
mov        edx, 0x1
mov        ecx, eax
shl        edx, cl                    ; 1 << (7 - var_20)

; password bit at position (7 - var_18)
mov        eax, 0x7
sub        eax, dword [rbp+var_18]
mov        edx, 0x1
shl        edx, cl                    ; 1 << (7 - var_18)
```

Then XOR to check equality -- if the bits differ, fail:

```asm
xor        eax, ecx
test       al, al
je         continue
return_fail
```

## Putting it together

The algorithm walks through 23 data bytes, 8 bits each (184 bits total). For each data bit, it writes into the password, but skips bit 7 of each password byte. That gives 7 usable bits per password byte, and 184 / 7 = 26.28 -- so 27 password bytes, with the last one partly filled.

```python
data_bytes = bytes([
    0xe1, 0xa7, 0x1e, 0xf8, 0x75, 0x23, 0x7b, 0x61,  # var_50
    0xb9, 0x9d, 0xfc, 0x5a, 0x5b, 0xdf, 0x69, 0xd2,  # var_48
    0xfe, 0x1b, 0xed, 0xf4, 0xed, 0x67, 0xf4          # var_41[1:]
])

password = bytearray(27)
pwd_idx = 0
pwd_bit = 0

for data_idx in range(23):
    for data_bit_pos in range(8):
        if pwd_bit == 0:
            pwd_bit = 1  # skip bit 7

        data_byte = data_bytes[data_idx]
        bit = (data_byte >> (7 - data_bit_pos)) & 1

        if bit:
            password[pwd_idx] |= (1 << (7 - pwd_bit))

        pwd_bit += 1
        if pwd_bit == 8:
            pwd_bit = 0
            pwd_idx += 1
```

Output:

```
7069636f4354467b306e335f6269375f34745f615f37696d337d00
picoCTF{0n3_bi7_4t_a_7im3}
```

## Flag

```
picoCTF{0n3_bi7_4t_a_7im3}
```