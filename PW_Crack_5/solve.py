import hashlib


def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join(
        chr(ord(secret_c) ^ ord(new_key_c))
        for (secret_c, new_key_c) in zip(secret, new_key)
    )


flag_enc = open("level5.flag.txt.enc", "rb").read()
correct_pw_hash = open("level5.hash.bin", "rb").read()

with open("dictionary.txt", "r") as f:
    for line in f:
        pw = line.strip()
        if hashlib.md5(pw.encode()).digest() == correct_pw_hash:
            print(f"Password: {pw}")
            print(f"Flag: {str_xor(flag_enc.decode(), pw)}")
            break
