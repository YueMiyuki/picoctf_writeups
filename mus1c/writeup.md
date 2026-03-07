# mus1c

## Category
General Skills

## Difficulty
Medium

## Description
Lyrics written in Rockstar, an esoteric language where code looks like song lyrics. Execute the program and decode the output.

## What is that
The `lyrics.txt` file contained Rockstar code.
- Variable assignments use poetic number literals (word lengths = digits)
- "shout" outputs values (as ASCII if in range)
- "Put X into Y" assigns values
- "Knock X down" decrements, "Build X up" increments
- "with" adds, "without" subtracts, "times" multiplies

## Rockstar Language Basics

**Poetic Number Literals:**
Each word is a digit equal to its length (mod 10 for words > 10 chars):
- "a" = 1
- "CTFFFFFFF" = 9 (9 letters)
- "waitin" = 6
- "something" = 9
- "nothing" = 7
- "fun" = 3
- "important" = 9

## Python Script

See `solve.py`  
It is a minimal Rockstar interpreter that reads `lyrics.txt` and executes it. 
The interpreter collects all `shout` outputs as characters, joins them, and wraps in the flag format.

## Final Output
```
rrrocknrn0113r
-> Flag: picoCTF{rrrocknrn0113r}
```

## Flag
```
picoCTF{rrrocknrn0113r}
```