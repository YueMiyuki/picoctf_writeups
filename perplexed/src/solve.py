#!/usr/bin/env python3
"""
Solver for perplexed CTF challenge.

CRITICAL INSIGHT 1: At loc_4011d6, there's a trick:
  if var_18 == 0: var_18 += 1

CRITICAL INSIGHT 2: The data layout has an overlap!
  - var_50: rbp-80 (8 bytes)
  - var_48: rbp-72 (8 bytes)
  - var_41: rbp-65 (8 bytes, but starts 1 byte into var_48's range!)

When accessing byte [rbp+rax+var_50] with rax=0..22:
  - rax=0..7: var_50 bytes (offset 0-7)
  - rax=8..15: var_48 bytes (offset 0-7)
  - rax=16..22: var_41 bytes (offset 1-7, NOT offset 0-6!)

So the first byte of var_41 (0xd2 in little endian) is NEVER USED.
"""

# The three constants from the binary
data_vals = [
    0x617b2375f81ea7e1,
    0xd269df5b5afc9db9,
    0xf467edf4ed1bfed2
]

# Convert each to bytes (little endian)
data_0 = data_vals[0].to_bytes(8, 'little')  # var_50
data_1 = data_vals[1].to_bytes(8, 'little')  # var_48
data_2 = data_vals[2].to_bytes(8, 'little')  # var_41

print(f"var_50: {data_0.hex()}")
print(f"var_48: {data_1.hex()}")
print(f"var_41: {data_2.hex()}")

# The actual 23 bytes accessed by the algorithm:
# - Bytes 0-7: var_50[0-7]
# - Bytes 8-15: var_48[0-7]
# - Bytes 16-22: var_41[1-7] (first byte skipped!)
data_bytes = data_0 + data_1 + data_2[1:8]
print(f"\nActual data bytes (23): {data_bytes.hex()}")

PASSWORD_LENGTH = 27

# Initialize password bytes to 0
password_bytes = bytearray(PASSWORD_LENGTH)

var_14 = 0  # Password byte index
var_18 = 0  # Bit position in password byte

for var_1C in range(23):  # 23 data bytes
    for var_20 in range(8):  # 8 bits per data byte
        # THE TRICK: if var_18 == 0, increment it to 1
        if var_18 == 0:
            var_18 = 1

        # Data bit position (MSB first: 7, 6, 5, 4, 3, 2, 1, 0)
        data_bit_pos = 7 - var_20
        # Password bit position
        pwd_bit_pos = 7 - var_18

        # Extract data bit
        data_byte = data_bytes[var_1C]
        data_bit = (data_byte >> data_bit_pos) & 1

        # Set the password bit
        if data_bit:
            password_bytes[var_14] |= (1 << pwd_bit_pos)

        # Increment var_18, wrap at 8
        var_18 += 1
        if var_18 == 8:
            var_18 = 0
            var_14 += 1

password_hex = password_bytes.hex()
print(f"\nPassword (hex): {password_hex}")

# Verify with the EXACT algorithm from the binary
def verify(pwd_hex):
    pwd = bytes.fromhex(pwd_hex)
    if len(pwd) != 27:
        return False

    var_14 = 0
    var_18 = 0

    for var_1C in range(23):
        for var_20 in range(8):
            if var_18 == 0:
                var_18 = 1

            data_bit_pos = 7 - var_20
            pwd_bit_pos = 7 - var_18

            data_byte = data_bytes[var_1C]
            data_bit = (data_byte >> data_bit_pos) & 1

            pwd_byte = pwd[var_14]
            pwd_bit = (pwd_byte >> pwd_bit_pos) & 1

            if data_bit != pwd_bit:
                print(f"  Mismatch at var_1C={var_1C}, var_20={var_20}")
                return False

            var_18 += 1
            if var_18 == 8:
                var_18 = 0
                var_14 += 1

    return True

print(f"\n--- Verifying ---")
if verify(password_hex):
    print("[+] Password verified!")
    print(f"\nThe password is: {password_hex}")
    try:
        ascii_pwd = password_bytes.decode('ascii')
        print(f"ASCII: {ascii_pwd}")
    except:
        pass
else:
    print("[-] Verification failed!")

print(f"\nPassword bytes:")
for i, b in enumerate(password_bytes):
    char = chr(b) if 32 <= b <= 126 else '?'
    print(f"  [{i:2d}] = 0x{b:02x} ({char})")
