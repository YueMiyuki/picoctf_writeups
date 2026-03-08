"""
MATRIX CTF solver - disassembles and analyzes a custom stack-based VM bytecode.

VM architecture (from reverse engineering the x86 binary):
  State: bytecode_ptr, IP (16-bit), data_stack, return_stack, getc_fn, putc_fn
  Stack: 16-bit words, grows upward

Opcodes:
  0x00: NOP
  0x01: EXIT  - pop result, set exit_code = result
  0x10: DUP   - duplicate TOS
  0x11: DROP  - pop TOS
  0x12: ADD   - pop a, pop b, push(b+a) as 16-bit
  0x13: SUB   - pop a, pop b, push(b-a) as 16-bit
  0x14: SWAP  - swap top two
  0x20: >R    - pop from data stack, push to return stack
  0x21: R>    - pop from return stack, push to data stack
  0x30: JMP   - pop addr, set IP = addr
  0x31: JZ    - pop addr, pop cond; if cond == 0, IP = addr
  0x32: JNZ   - pop addr, pop cond; if cond != 0, IP = addr
  0x33: JN    - pop addr, pop cond; if cond < 0 (signed), IP = addr
  0x34: JLE   - pop addr, pop cond; if cond <= 0 (signed), IP = addr
  0x80 XX:     PUSH sign_extend(XX)
  0x81 LO HI:  PUSH word (little-endian)
  0xC0: READ  - getc(), push result
  0xC1: WRITE - pop, putc(value)
"""

import re
import struct
import sys


def simulate(code, input_str):
    """Simulate the VM with given input to verify."""
    ip = 0
    data_stack = []
    ret_stack = []
    output = []
    input_pos = 0

    def push(v):
        data_stack.append(v & 0xFFFF)

    def pop():
        return data_stack.pop()

    def signed16(v):
        v = v & 0xFFFF
        return v - 0x10000 if v >= 0x8000 else v

    for _ in range(500000):
        if ip >= len(code):
            break
        op = code[ip]

        if op == 0x00:
            ip += 1
        elif op == 0x01:
            result = pop() if data_stack else 0
            print(f"EXIT code={result}")
            print(f"Output: {''.join(output)}")
            return result
        elif op == 0x10:
            push(data_stack[-1]); ip += 1
        elif op == 0x11:
            pop(); ip += 1
        elif op == 0x12:
            a, b = pop(), pop(); push(b + a); ip += 1
        elif op == 0x13:
            a, b = pop(), pop(); push(b - a); ip += 1
        elif op == 0x14:
            a, b = pop(), pop(); push(a); push(b); ip += 1
        elif op == 0x20:
            ret_stack.append(pop()); ip += 1
        elif op == 0x21:
            push(ret_stack.pop()); ip += 1
        elif op == 0x30:
            ip = pop()
        elif op == 0x31:
            addr, cond = pop(), pop()
            ip = addr if cond == 0 else ip + 1
        elif op == 0x32:
            addr, cond = pop(), pop()
            ip = addr if cond != 0 else ip + 1
        elif op == 0x33:
            addr, cond = pop(), pop()
            ip = addr if signed16(cond) < 0 else ip + 1
        elif op == 0x34:
            addr, cond = pop(), pop()
            ip = addr if signed16(cond) <= 0 else ip + 1
        elif op == 0x80:
            push(struct.unpack('b', bytes([code[ip+1]]))[0]); ip += 2
        elif op == 0x81:
            push(struct.unpack('<H', code[ip+1:ip+3])[0]); ip += 3
        elif op == 0xC0:
            if input_pos < len(input_str):
                push(ord(input_str[input_pos])); input_pos += 1
            else:
                push(0xFF)
            ip += 1
        elif op == 0xC1:
            output.append(chr(pop() & 0xFF)); ip += 1
        else:
            print(f"INVALID 0x{op:02x} at IP={ip}")
            break

    print(f"Output: {''.join(output)}")
    return -1


def extract_bytecode_from_asm(filename):
    """Extract raw bytecode bytes from Hopper-style disassembly."""
    bytecode = {}
    with open(filename) as f:
        for line in f:
            # 00000000000020f0         db  0x81 ; '.'
            m = re.match(r'([0-9a-f]{16})\s+db\s+0x([0-9a-f]{2})', line.strip())
            if m:
                addr = int(m.group(1), 16)
                val = int(m.group(2), 16)
                bytecode[addr] = val
    return bytecode

def build_bytecode_array(bytecode_dict, start_addr):
    """Build contiguous bytecode array from address->byte dict."""
    if not bytecode_dict:
        return b''
    max_addr = max(bytecode_dict.keys())
    result = bytearray()
    addr = start_addr
    while addr <= max_addr and addr in bytecode_dict:
        result.append(bytecode_dict[addr])
        addr += 1
    return bytes(result)

def disassemble(code, start=0):
    """Disassemble VM bytecode, return list of (offset, instruction_str)."""
    instructions = []
    ip = start
    while ip < len(code):
        op = code[ip]
        if op == 0x00:
            instructions.append((ip, "NOP"))
            ip += 1
        elif op == 0x01:
            instructions.append((ip, "EXIT"))
            ip += 1
        elif op == 0x10:
            instructions.append((ip, "DUP"))
            ip += 1
        elif op == 0x11:
            instructions.append((ip, "DROP"))
            ip += 1
        elif op == 0x12:
            instructions.append((ip, "ADD"))
            ip += 1
        elif op == 0x13:
            instructions.append((ip, "SUB"))
            ip += 1
        elif op == 0x14:
            instructions.append((ip, "SWAP"))
            ip += 1
        elif op == 0x20:
            instructions.append((ip, ">R"))
            ip += 1
        elif op == 0x21:
            instructions.append((ip, "R>"))
            ip += 1
        elif op == 0x30:
            instructions.append((ip, "JMP"))
            ip += 1
        elif op == 0x31:
            instructions.append((ip, "JZ"))
            ip += 1
        elif op == 0x32:
            instructions.append((ip, "JNZ"))
            ip += 1
        elif op == 0x33:
            instructions.append((ip, "JN"))
            ip += 1
        elif op == 0x34:
            instructions.append((ip, "JLE"))
            ip += 1
        elif op == 0x80:
            if ip + 1 >= len(code):
                instructions.append((ip, f"PUSH_B ??? (truncated)"))
                ip += 1
                break
            val = struct.unpack('b', bytes([code[ip+1]]))[0]
            if 0x20 <= code[ip+1] <= 0x7e:
                instructions.append((ip, f"PUSH {val}  ; '{chr(code[ip+1])}'"))
            else:
                instructions.append((ip, f"PUSH {val}"))
            ip += 2
        elif op == 0x81:
            if ip + 2 >= len(code):
                instructions.append((ip, f"PUSH_W ??? (truncated)"))
                ip += 1
                break
            val = struct.unpack('<H', code[ip+1:ip+3])[0]
            instructions.append((ip, f"PUSH 0x{val:04x}  ; {val}"))
            ip += 3
        elif op == 0xC0:
            instructions.append((ip, "READ"))
            ip += 1
        elif op == 0xC1:
            instructions.append((ip, "WRITE"))
            ip += 1
        else:
            instructions.append((ip, f"INVALID 0x{op:02x}"))
            ip += 1
    return instructions

def extract_maze(code):
    """
    Extract the maze from the jump table.

    The jump table starts at offset 372 (0x174). Each entry is 4 bytes.
    Index = Y*16 + X. Starting position is (1, 1).

    Entry types (4-byte patterns):
    - 0x81 LL HH 0x30: PUSH addr; JMP → addr determines cell type
      - addr 0x00fb (251): wall/death ("eaten by a grue")
      - addr 0x0574 (1396): special target A
      - addr 0x057f (1407): special target B
    - 0x30 0x00 0x00 0x00: JMP; NOP*3 → passable (pops return addr, continues)
    """
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


def solve_maze(maze, grid_width=16):
    """BFS to find path through the maze from (1,1) to any exit cell.

    A cells decrement key count (need key > 0, else die).
    B cells increment key count.
    Need to track (x, y, keys) state.
    """
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


def main():
    bytecode_dict = extract_bytecode_from_asm("matrix.asm")

    # Hopper disassembled
    START_ADDR = 0x20f0
    code = build_bytecode_array(bytecode_dict, START_ADDR)
    print(f"Extracted {len(code)} bytes of bytecode starting at 0x{START_ADDR:x}")

    instructions = disassemble(code)
    for offset, instr in instructions:
        print(f"  {offset:4d} (0x{offset:04x}): {instr}")

    maze = extract_maze(code)

    grid_width = 16
    max_y = max(idx // grid_width for idx in maze.keys()) + 1
    max_x = max(idx % grid_width for idx in maze.keys()) + 1

    # maze grid
    print(f"Grid size: {max_x}x{max_y}")
    for y in range(max_y):
        row = ""
        for x in range(max_x):
            idx = y * grid_width + x
            cell = maze.get(idx, '?')
            if cell == 'W':
                row += '#'
            elif cell == '.':
                row += ' '
            elif cell in ('A', 'B'):
                row += cell
            elif (x, y) == (1, 1):
                row += 'S'
            else:
                row += '?'
        print(f"  {y:2d}: |{row}|")

    print("\nUnknown/special cells:")
    for idx in sorted(maze.keys()):
        cell = maze[idx]
        if cell not in ('W', '.', 'A', 'B'):
            x, y = idx % grid_width, idx // grid_width
            offset = 372 + idx * 4
            raw = code[offset:offset+4]
            print(f"  ({x},{y}) idx={idx}: type={cell}, raw={raw.hex()}, bytes={list(raw)}")

    start_idx = 1 * grid_width + 1
    print(f"\nStart: (1, 1), index={start_idx}")

    # Solve
    path, goal_type, goal_pos = solve_maze(maze, grid_width)

    if path:
        solution = ''.join(path)
        print(f"\nSolution: {solution}")
        print(f"Length: {len(path)} moves")


if __name__ == "__main__":
    main()
