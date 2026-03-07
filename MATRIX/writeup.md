# MATRIX

**Category:** Reverse Engineering (Hard)  
**Author:** asphyxia

## What is that

TL;DR: A matrix maze, prints the flag when travelled to exit

## Disassemble

Opening this in Hopper, I spotted `sub_10de` in the main function. It allocates two 0x800-byte buffers (data stack and return stack), then runs a dispatch loop:

```asm
sub_10de:
    ; ... setup ...
    mov  edi, 0x800
    call j_malloc              ; data stack = malloc(0x800)
    mov  r13, rax

    mov  edi, 0x800
    call j_malloc              ; return stack = malloc(0x800)
    mov  r12, rax

    ; Load bytecode pointer
    lea  rax, [switch_table_201c+212]   ; 0x20f0 = bytecode start

    ; Store function pointers for I/O
    lea  rcx, [sub_1320]       ; getc wrapper
    lea  rax, [sub_1340]       ; putc wrapper

    ; Initialize IP (var_158) to 0
    xor  eax, eax
    mov  word [rsp+var_158], ax
```

The dispatch loop is tight:

```asm
loc_1178:
    mov  rsi, rbp              ; error
    mov  rdi, rbx              ; VM state pointer
    call sub_1350              ; execute one instruction
    test al, al
    jne  loc_1178              ; loop while return == 1
```

After the loop exits, it checks two values:
- `var_164` (error flag): if set, returns -1 (error/invalid opcode)
- `var_162` (exit code): if 0, opens and prints `flag.txt`

```asm
    cmp  byte [var_164], 0x0   ; error flag
    jne  loc_1215              ; → return -1

    cmp  word [var_162], 0x0   ; exit code from VM
    je   loc_11cc              ; → if 0, print flag!

loc_11cc:
    lea  rdi, [aHaveAFlag]     ; "Have a flag!"
    call j_puts
    lea  rdi, [aFlagtxt]       ; "flag.txt"
    call j_fopen
    ; ... reads and prints flag ...
```

To kick its ass, make the VM exit with code 0.

## Reverse Engineering the dispatch function

The dispatch function `sub_1350` reads one byte from the bytecode, then uses a switch table for opcodes 0x00-0x34, with if/else chains for higher opcodes.

### VM State Layout

From access patterns in the assembly:

```
struct VMState {
    void*   bytecode;      // [rbx+0x00] pointer to bytecode array
    uint16_t ip;           // [rbx+0x08] instruction pointer
    void*   data_sp;       // [rbx+0x10] data stack pointer (grows up)
    void*   return_sp;     // [rbx+0x18] return stack pointer (grows up)
    void*   getc_fn;       // [rbx+0x20] input function
    void*   putc_fn;       // [rbx+0x28] output function
};
```

### Fetch Cycle

```asm
sub_1350:
    mov  rbx, rdi                  ; rbx = VM state
    mov  rdi, [rdi]                ; rdi = bytecode pointer
    movzx eax, word [rbx+8]       ; eax = IP (16-bit)
    lea  ecx, [rax+1]             ; ecx = IP + 1
    mov  word [rbx+8], cx         ; pre-increment IP
    movzx eax, byte [rdi+rax]    ; al = opcode = bytecode[IP]
    cmp  al, 0x34
    ja   loc_1380                  ; handle high opcodes separately
    ; switch table dispatch for opcodes 0x00..0x34
    lea  rdx, [switch_table_201c]
    movsxd rax, dword [rdx+rax*4]
    add  rax, rdx
    jmp  rax
```

### Opcodes I Found

| Opcode | Name | Assembly Handler | Behavior |
|--------|------|------------------|----------|
| 0x00 | NOP | `loc_140b` | Returns 1 (continue) |
| 0x01 | EXIT | `loc_1428` | Sets error_flag=0, stores TOS as exit code |
| 0x10 | DUP | `loc_14c0` | `w = [sp-2]; [sp] = w; sp += 2` |
| 0x11 | DROP | `loc_1418` | `sp -= 2` |
| 0x12 | ADD | `loc_15a0` | `[sp-4] += [sp-2]; sp -= 2` |
| 0x13 | SUB | `loc_1450` | `[sp-4] -= [sp-2]; sp -= 2` |
| 0x14 | SWAP | `loc_1470` | Swap `[sp-4]` and `[sp-2]` |
| 0x20 | >R | `loc_1490` | Pop data stack, push to return stack |
| 0x21 | R> | `loc_14e0` | Pop return stack, push to data stack |
| 0x30 | JMP | `loc_1510` | `IP = pop()` |
| 0x31 | JZ | `loc_1530` | `addr = pop(); cond = pop(); if cond==0: IP=addr` |
| 0x32 | JNZ | `loc_1560` | Like JZ but jumps when cond != 0 |
| 0x33 | JN | `loc_13f0` | Jumps when cond < 0 (signed) |
| 0x34 | JLE | `loc_1580` | Jumps when cond <= 0 (signed) |

For high opcodes (handled via if/else after the switch table):

| Opcode | Name | Assembly | Behavior |
|--------|------|----------|----------|
| 0x80 XX | PUSH byte | `loc_15e0` | Sign-extend byte, push to stack |
| 0x81 LO HI | PUSH word | `loc_13b4` | Push 16-bit little-endian word |
| 0xC0 | READ | `loc_15c0` | Call getc, push result |
| 0xC1 | WRITE | after `loc_1380` | Pop value, call putc |

The PUSH byte handler sign-extends:

```asm
loc_15e0:                           ; opcode 0x80
    movzx ecx, cx                   ; cx = new IP (after opcode byte)
    add   edx, 0x2                  ; IP += 2 (skip opcode + operand)
    movsx cx, byte [rdi+rcx]       ; sign-extend operand byte
    jmp   loc_13be                  ; → push cx onto data stack
```

And the PUSH word handler reads two bytes:

```asm
    ; opcode 0x81
    movzx ecx, cx                   ; cx = IP after opcode
    add   edx, 0x3                  ; IP += 3
    movzx ecx, word [rdi+rcx]     ; load 16-bit word (little-endian)
    ; falls through to push
loc_13be:
    mov   rax, [rbx+0x10]          ; rax = data stack pointer
    mov   word [rbx+8], dx         ; update IP
    lea   rdx, [rax+2]
    mov   [rbx+0x10], rdx          ; sp += 2
    mov   word [rax], cx           ; *sp = value
```

It's basically Forth with two stacks (data + return).

## Extracting the Bytecode

The bytecode starts at address `0x20f0` in the ELF:

```asm
lea  rax, [switch_table_201c+212]   ; 0x201c + 0xD4 = 0x20f0
```

In Hopper, the bytecode shows up as raw `db` directives:

```asm
00000000000020f0  db  0x81    ; PUSH word
00000000000020f1  db  0x75    ;   0x0075 = 117
00000000000020f2  db  0x00
00000000000020f3  db  0x80    ; PUSH byte
00000000000020f4  db  0x00    ;   0
00000000000020f5  db  0x80    ; PUSH byte
00000000000020f6  db  0x0a    ;   '\n'
; ... more bytes ...
```

I wrote a quick parser to extract these from the `.asm` file:

```python
def extract_bytecode_from_asm(filename):
    bytecode = {}
    with open(filename) as f:
        for line in f:
            m = re.match(r'([0-9a-f]{16})\s+db\s+0x([0-9a-f]{2})', line.strip())
            if m:
                addr = int(m.group(1), 16)
                val = int(m.group(2), 16)
                bytecode[addr] = val
    return bytecode
```

This gives 1568 bytes of bytecode.

## Disassembling the Bytecode

With the opcode table mapped out, I wrote a disassembler. The first section pushes characters onto the stack in reverse, then calls a print-string

```
  0 (0x0000): PUSH 0x0075  ; 117 → jump target after printing
  3 (0x0003): PUSH 0       ; null terminator
  5 (0x0005): PUSH 10      ; '\n'
  7 (0x0007): PUSH 63      ; '?'
  9 (0x0009): PUSH 101     ; 'e'
 11 (0x000b): PUSH 118     ; 'v'
 ...                        ; "Welcome to the M A T R I X\nCan you make it out alive?\n"
113 (0x0071): PUSH 0x013b  ; address of print routine
116 (0x0074): JMP           ; call print
```

After printing, execution continues at offset 0x75 (117):

```
117 (0x0075): PUSH 1       ; initial X position
119 (0x0077): PUSH 1       ; initial Y position
121 (0x0079): PUSH 0       ; move counter / key count
```

## How to move???

Move with letters, not `wasd` - it's `udlr`

```
123 (0x007b): READ          ; read input char
124 (0x007c): DUP
125 (0x007d): PUSH 117     ; 'u'
127 (0x007f): SUB
128 (0x0080): PUSH 0x00a0  ; if char == 'u', goto 160
131 (0x0083): JZ
132 (0x0084): DUP
133 (0x0085): PUSH 100     ; 'd'
135 (0x0087): SUB
136 (0x0088): PUSH 0x00aa  ; if char == 'd', goto 170
139 (0x008b): JZ
140 (0x008c): DUP
141 (0x008d): PUSH 108     ; 'l'
143 (0x008f): SUB
144 (0x0090): PUSH 0x00b4  ; if char == 'l', goto 180
147 (0x0093): JZ
148 (0x0094): DUP
149 (0x0095): PUSH 114     ; 'r'
151 (0x0097): SUB
152 (0x0098): PUSH 0x00c0  ; if char == 'r', goto 192
155 (0x009b): JZ
156 (0x009c): PUSH 0x00fb  ; invalid input → death
159 (0x009f): JMP
```

Each direction handler tweaks the position.  
Stack layout is `[X, Y, count]`:

```
; 'u' handler (offset 160): Y -= 1
160: DROP            ; remove the input char
161: >R              ; save count to return stack
162: PUSH 1
164: SUB             ; Y = Y - 1
165: R>              ; restore count
166: PUSH 0x00cc     ; → continue to cell lookup
169: JMP

; 'd' handler (offset 170): Y += 1
170: DROP
171: >R
172: PUSH 1
174: ADD             ; Y = Y + 1
175: R>
176: PUSH 0x00cc
179: JMP

; 'l' handler (offset 180): X -= 1
180: DROP
181: >R              ; save count
182: >R              ; save Y
183: PUSH 1
185: SUB             ; X = X - 1
186: R>              ; restore Y
187: R>              ; restore count
188: PUSH 0x00cc
191: JMP

; 'r' handler (offset 192): X += 1
192: DROP
193: >R
194: >R
195: PUSH 1
197: ADD             ; X = X + 1
198: R>
199: R>
200: PUSH 0x00cc
203: JMP
```

## Jump Table

After movement, the code at offset 204 computes a cell index and jumps:

```
204 (0x00cc): >R              ; save count
205 (0x00cd): >R              ; save Y
206 (0x00ce): PUSH 0x00da    ; return address (218)
209 (0x00d1): R>              ; get Y
210 (0x00d2): DUP
211 (0x00d3): >R              ; save Y back
212 (0x00d4): PUSH 16         ; grid width
214 (0x00d6): PUSH 0x0147    ; multiply subroutine
217 (0x00d9): JMP             ; call multiply(Y, 16)
; returns to 218
218 (0x00da): SWAP
219 (0x00db): DUP
220 (0x00dc): >R
221 (0x00dd): ADD             ; Y*16 + X = cell index
222 (0x00de): R>
223 (0x00df): SWAP
224 (0x00e0): R>              ; restore Y
225 (0x00e1): SWAP
226 (0x00e2): R>              ; restore count
227 (0x00e3): SWAP
228 (0x00e4): >R              ; save count
229 (0x00e5): PUSH 0x00ef    ; return address (239)
232 (0x00e8): R>              ; get count
233 (0x00e9): PUSH 2          ; entry size shift
235 (0x00eb): PUSH 0x0161    ; power-of-2 multiply subroutine
238 (0x00ee): JMP             ; call: count * 4 (shift left 2)
; returns to 239
239 (0x00ef): PUSH 0x007b    ; loop-back address (READ)
242 (0x00f2): SWAP
243 (0x00f3): PUSH 0x0174    ; jump table base (offset 372)
246 (0x00f6): ADD             ; table_base + index*4
247 (0x00f7): JMP             ; jump into the cell!
```

This computes `jump_target = 0x174 + (Y*16 + X) * 4` and jumps there.

## Decode

Starting at offset 372 (0x174), each maze cell is a 4-byte entry. Two patterns:

**Wall cell** (death - "You were eaten by a grue"):
```
81 fb 00 30    →  PUSH 0x00fb; JMP   (jumps to death message)
```

**Passable cell** (pops return address, loops back to input):
```
30 00 00 00    →  JMP; NOP; NOP; NOP  (jumps to the stacked 0x007b)
```

**Locked door (Maybe?)(A cell)** - jumps to 0x0574 which decrements count (or kills if 0):
```
81 74 05 30    →  PUSH 0x0574; JMP

; At 0x0574:
    >R               ; save return address
    DUP              ; duplicate count
    PUSH 0x00fb      ; death address
    JZ               ; if count == 0, die
    PUSH 1
    SUB              ; count -= 1
    R>
    JMP              ; return
```

**Key pickup (B cell)** - jumps to 0x057f which increments count:
```
81 7f 05 30    →  PUSH 0x057f; JMP

; At 0x057f:
    >R               ; save return address
    PUSH 1
    ADD              ; count += 1
    R>
    JMP              ; return
```

**Exit cell** - at index 254 (position 14, 15):
```
81 85 05 30    →  PUSH 0x0585; JMP

; At 0x0585:
    DROP; DROP; DROP; DROP    ; clean up stack
    ; prints "You made it!" message
    PUSH 0
    EXIT                       ; exit code 0 → flag!
```

Parsing all 256 entries (16x16 grid) is not that hard. The jump table starts at bytecode offset 372 (0x174). Each cell is exactly 4 bytes. Cell at position `(x, y)` lives at offset `372 + (y*16 + x) * 4`. Just read each 4-byte entry and classify it by pattern:

```python
def extract_maze(code):
    TABLE_START = 372  # 0x174
    ENTRY_SIZE = 4

    # Determine maze dimensions from the bytecode
    # The table runs until some known end point
    maze = {}
    max_index = (len(code) - TABLE_START) // ENTRY_SIZE

    for i in range(max_index):
        offset = TABLE_START + i * ENTRY_SIZE
        if offset + 4 > len(code):
            break

        entry = code[offset:offset+4]

        if entry[0] == 0x81 and entry[3] == 0x30:
            addr = struct.unpack('<H', entry[1:3])[0]
            if addr == 0x00fb:
                maze[i] = 'W'  # wall/death
            elif addr == 0x0574:
                maze[i] = 'A'  # special A
            elif addr == 0x057f:
                maze[i] = 'B'  # special B
            else:
                maze[i] = f'?{addr:04x}'
        elif entry[0] == 0x30 and entry[1:4] == b'\x00\x00\x00':
            maze[i] = '.'  # passable
        else:
            maze[i] = f'X({entry.hex()})'

    return maze

```

The `0x30 0x00 0x00 0x00` pattern works because the code pushes `0x007b` (the READ loop address) onto the stack right before jumping into the table. A bare `JMP` pops that address and returns to the input loop. The three `0x00` bytes after it are NOPs that pad the entry to 4 bytes.

This gives the grid:

```
Grid size: 16x19
   0: |################|
   1: |#     B# #B  # #|
   2: |####A### ### # #|
   3: |#          # # #|
   4: |## # ##### # A #|
   5: |#  # #B  # # # #|
   6: |# ## ### # # # #|
   7: |# #      # # # #|
   8: |# # ###### # # #|
   9: |# #        # # #|
  10: |# ### ###### # #|
  11: |#   #  A  #  # #|
  12: |# ###  #  # #  #|
  13: |# #   ### # #A##|
  14: |# #    #  A #  #|
  15: |##############?#|
  16: |????????????????|
  17: |????????????????|
  18: |????????????????|

Unknown/special cells:
  (14,15) idx=254: type=?0585, raw=81850530, bytes=[129, 133, 5, 48]
  (0,16) idx=256: type=X(201081fb), raw=201081fb, bytes=[32, 16, 129, 251]
  (1,16) idx=257: type=X(00318001), raw=00318001, bytes=[0, 49, 128, 1]
  (2,16) idx=258: type=X(13213020), raw=13213020, bytes=[19, 33, 48, 32]
  (3,16) idx=259: type=X(80011221), raw=80011221, bytes=[128, 1, 18, 33]
  (4,16) idx=260: type=X(30111111), raw=30111111, bytes=[48, 17, 17, 17]
  (5,16) idx=261: type=X(1181ce05), raw=1181ce05, bytes=[17, 129, 206, 5]
  (6,16) idx=262: type=X(8000800a), raw=8000800a, bytes=[128, 0, 128, 10]
  (7,16) idx=263: type=X(80218074), raw=80218074, bytes=[128, 33, 128, 116]
  (8,16) idx=264: type=X(80698020), raw=80698020, bytes=[128, 105, 128, 32]
  (9,16) idx=265: type=X(80658064), raw=80658064, bytes=[128, 101, 128, 100]
  (10,16) idx=266: type=X(8061806d), raw=8061806d, bytes=[128, 97, 128, 109]
  (11,16) idx=267: type=X(80208075), raw=80208075, bytes=[128, 32, 128, 117]
  (12,16) idx=268: type=X(806f8079), raw=806f8079, bytes=[128, 111, 128, 121]
  (13,16) idx=269: type=X(8020802c), raw=8020802c, bytes=[128, 32, 128, 44]
  (14,16) idx=270: type=X(8073806e), raw=8073806e, bytes=[128, 115, 128, 110]
  (15,16) idx=271: type=X(806f8069), raw=806f8069, bytes=[128, 111, 128, 105]
  (0,17) idx=272: type=X(80748061), raw=80748061, bytes=[128, 116, 128, 97]
  (1,17) idx=273: type=X(806c8075), raw=806c8075, bytes=[128, 108, 128, 117]
  (2,17) idx=274: type=X(80748061), raw=80748061, bytes=[128, 116, 128, 97]
  (3,17) idx=275: type=X(80728067), raw=80728067, bytes=[128, 114, 128, 103]
  (4,17) idx=276: type=X(806e806f), raw=806e806f, bytes=[128, 110, 128, 111]
  (5,17) idx=277: type=X(8043813b), raw=8043813b, bytes=[128, 67, 129, 59]
  (6,17) idx=278: type=X(013081f8), raw=013081f8, bytes=[1, 48, 129, 248]
  (7,17) idx=279: type=X(00300000), raw=00300000, bytes=[0, 48, 0, 0]
  (8,17) idx=280: type=X(011b033b), raw=011b033b, bytes=[1, 27, 3, 59]
  (9,17) idx=281: type=X(48000000), raw=48000000, bytes=[72, 0, 0, 0]
  (10,17) idx=282: type=X(08000000), raw=08000000, bytes=[8, 0, 0, 0]
  (11,17) idx=283: type=X(5ce9ffff), raw=5ce9ffff, bytes=[92, 233, 255, 255]
  (12,17) idx=284: type=X(7c000000), raw=7c000000, bytes=[124, 0, 0, 0]
  (13,17) idx=285: type=X(0ceaffff), raw=0ceaffff, bytes=[12, 234, 255, 255]
  (14,17) idx=286: type=X(d0000000), raw=d0000000, bytes=[208, 0, 0, 0]
  (15,17) idx=287: type=X(5cebffff), raw=5cebffff, bytes=[92, 235, 255, 255]
  (0,18) idx=288: type=X(64000000), raw=64000000, bytes=[100, 0, 0, 0]
  (1,18) idx=289: type=X(5cecffff), raw=5cecffff, bytes=[92, 236, 255, 255]
  (2,18) idx=290: type=X(a4000000), raw=a4000000, bytes=[164, 0, 0, 0]
  (3,18) idx=291: type=X(7cecffff), raw=7cecffff, bytes=[124, 236, 255, 255]
  (4,18) idx=292: type=X(bc000000), raw=bc000000, bytes=[188, 0, 0, 0]
  (5,18) idx=293: type=X(8cecffff), raw=8cecffff, bytes=[140, 236, 255, 255]
  (6,18) idx=294: type=X(0c010000), raw=0c010000, bytes=[12, 1, 0, 0]
  (7,18) idx=295: type=X(2cefffff), raw=2cefffff, bytes=[44, 239, 255, 255]
  (8,18) idx=296: type=X(84010000), raw=84010000, bytes=[132, 1, 0, 0]
  (9,18) idx=297: type=X(9cefffff), raw=9cefffff, bytes=[156, 239, 255, 255]
  (10,18) idx=298: type=X(cc010000), raw=cc010000, bytes=[204, 1, 0, 0]

# Looks ugly, but working anyway, idc
```

## Solving

Standard shortest-path with state `(x, y, keys)`. B cells give a key, A cells consume one (and block if you have none). BFS:

```python

def solve_maze(maze, grid_width=16):
    from collections import deque

    start = (1, 1, 0)
    queue = deque([(start, [])])
    visited = {start}

    directions = {
        'u': (0, -1),
        'd': (0, 1),
        'l': (-1, 0),
        'r': (1, 0),
    }

    while queue:
        (x, y, keys), path = queue.popleft()

        for move, (dx, dy) in directions.items():
            nx, ny = x + dx, y + dy
            idx = ny * grid_width + nx

            if idx not in maze:
                continue

            cell = maze[idx]
            if cell == 'W':
                continue  # wall

            new_keys = keys
            if cell == 'A':
                if keys <= 0:
                    continue  # would die
                new_keys = keys - 1
            elif cell == 'B':
                new_keys = keys + 1

            state = (nx, ny, new_keys)
            if state in visited:
                continue
            visited.add(state)

            new_path = path + [move]

            if cell not in ('W', '.', 'A', 'B'):
                print(f"Found special cell at ({nx}, {ny}), index={idx}, type={cell}, keys={new_keys}")
                print(f"Path: {''.join(new_path)}")
                return new_path, cell, (nx, ny)

            queue.append((state, new_path))

    print("No path found!")
    return None, None, None
```

## Step 9: Verification

Running the BFS

nc mars.picoctf.net 31259
< Welcome to the M A T R I X
< Can you make it out alive?
> rrrrrlllllrrrrrl...rrddddddddlddrd
< Congratulations, you made it!
< Have a flag!
< picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}


## Answer

```
rrrrrlrlrlrlrllddddddlddrrddrrrdrddrruuuruuuuuuurrddddddddlddrd
```

Flag: `picoCTF{y0uv3_3sc4p3d_th3_m4ze...f0r_n0w-hYkq2D9PmrA5GpEq}`