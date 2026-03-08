# tic-tac

**Author:** Junias Bonou  
**Category:** Binary Exploitation

## What fucked up

The file is opened *before* the ownership check. Classic TOCTOU race condition.

## How
The SUID `txtreader` binary (src.cpp) does this:

1. `ifstream file(filename)` — opens the file with root privileges
2. `stat(filename, &statbuf)` — checks file ownership
3. If `st_uid == getuid()`, reads from the already-opened ifstream


So we can just use a symlink that points to `./flag.txt` so `ifstream`
opens the real flag. Then quickly swap the symlink to a user-owned dummy file before
`stat()` runs, so the ownership check passes. The flag contents are then read from the
already-opened file descriptor.

## Solve

`./src/solve.sh`

## Flag

```
picoCTF{ToctoU_!s_3a5y_2075872e}
```
