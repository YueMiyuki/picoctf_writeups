#!/usr/bin/env python3
"""
MT19937 state recovery from 624 randrange(sys.maxsize) outputs.

Each output is 63 bits = two 32-bit MT words. The second word loses its
LSB (>> 1), so odd-indexed MT state values have a 1-bit ambiguity.
We resolve these using even-twist constraints: each even twist step links
two odd unknowns, forming a constraint graph we propagate over.
"""
import random
import sys

def temper(x):
    y = x & 0xFFFFFFFF
    y ^= (y >> 11)
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= (y >> 18)
    return y

def untemper(y):
    y &= 0xFFFFFFFF
    y ^= y >> 18
    y ^= (y << 15) & 0xEFC60000
    tmp = y
    for _ in range(3):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = y ^ ((tmp << 7) & 0x9D2C5680)
    tmp = y
    tmp = y ^ (tmp >> 11)
    y = y ^ (tmp >> 11)
    return y & 0xFFFFFFFF

def twist(state):
    s = list(state)
    for i in range(624):
        y = (s[i] & 0x80000000) | (s[(i + 1) % 624] & 0x7FFFFFFF)
        s[i] = s[(i + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
    return s

def recover_state(boundaries):
    assert len(boundaries) >= 624

    # Split 624 boundaries into two halves (period 1 and period 2).
    # p1 gives us the pre-twist MT state, p2 gives twist output constraints.
    p1_w0, p1_w1s = [], []
    p2_w0, p2_w1s = [], []
    for i in range(312):
        p1_w0.append(boundaries[i] & 0xFFFFFFFF)
        p1_w1s.append((boundaries[i] >> 32) & 0x7FFFFFFF)
        p2_w0.append(boundaries[312 + i] & 0xFFFFFFFF)
        p2_w1s.append((boundaries[312 + i] >> 32) & 0x7FFFFFFF)

    # Even MT indices: fully known from p1_w0.
    # Odd MT indices: two candidates (LSB=0 or LSB=1) from p1_w1s.
    mt_even = {}
    mt_odd_candidates = {}

    for i in range(312):
        mt_even[2 * i] = untemper(p1_w0[i])
        w1s = p1_w1s[i]
        mt_odd_candidates[2 * i + 1] = (untemper(w1s << 1), untemper((w1s << 1) | 1))

    # Twist at even position i links two odd indices: j1=i+1, j2=(i+397)%624.
    # The twisted output must equal untemper(p2_w0[i//2]).
    #
    # For i < 228: j2 = i+397 > i, so j2 is still the original (not yet twisted).
    #   -> each constraint links two unknowns with original values. 114 disjoint pairs.
    # For i >= 228: j2 = i-227 < i, already twisted. Need simulated twist state.
    #   -> handled in a second pass after propagation.

    choice = {}  # odd_index -> 0 or 1

    # Pass 1: resolve pairs using pre-twist constraints (i_even < 228)
    for i_even in range(0, 228, 2):
        j1 = i_even + 1
        j2 = (i_even + 397) % 624

        msb_i = mt_even[i_even] & 0x80000000
        expected_twisted = untemper(p2_w0[i_even // 2])

        c0_j1, c1_j1 = mt_odd_candidates[j1]
        c0_j2, c1_j2 = mt_odd_candidates[j2]

        valid = []
        for b1 in [0, 1]:
            for b2 in [0, 1]:
                val_j1 = c0_j1 if b1 == 0 else c1_j1
                val_j2 = c0_j2 if b2 == 0 else c1_j2

                y = msb_i | (val_j1 & 0x7FFFFFFF)
                tw = val_j2 ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)

                if tw == expected_twisted:
                    valid.append((b1, b2))

        if len(valid) == 1:
            b1, b2 = valid[0]
            assert choice.get(j1, b1) == b1, f"Conflict at {j1}"
            assert choice.get(j2, b2) == b2, f"Conflict at {j2}"
            choice[j1] = b1
            choice[j2] = b2
        elif len(valid) == 2:
            if j1 in choice:
                for b1, b2 in valid:
                    if b1 == choice[j1]:
                        choice[j2] = b2
                        break
            elif j2 in choice:
                for b1, b2 in valid:
                    if b2 == choice[j2]:
                        choice[j1] = b1
                        break
        elif len(valid) == 0:
            print(f"  bad constraint at i={i_even} j1={j1} j2={j2}")

    print(f"  pass 1: {len(choice)}/312 odd bits resolved")

    # Propagate until stable
    changed = True
    iteration = 0
    while changed:
        changed = False
        iteration += 1
        for i_even in range(0, 228, 2):
            j1 = i_even + 1
            j2 = (i_even + 397) % 624
            if j1 in choice and j2 in choice:
                continue

            msb_i = mt_even[i_even] & 0x80000000
            expected_twisted = untemper(p2_w0[i_even // 2])
            c0_j1, c1_j1 = mt_odd_candidates[j1]
            c0_j2, c1_j2 = mt_odd_candidates[j2]

            valid = []
            for b1 in [0, 1]:
                for b2 in [0, 1]:
                    val_j1 = [c0_j1, c1_j1][b1]
                    val_j2 = [c0_j2, c1_j2][b2]
                    y = msb_i | (val_j1 & 0x7FFFFFFF)
                    tw = val_j2 ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
                    if tw == expected_twisted:
                        valid.append((b1, b2))

            if j1 in choice:
                for b1, b2 in valid:
                    if b1 == choice[j1] and j2 not in choice:
                        choice[j2] = b2
                        changed = True
            elif j2 in choice:
                for b1, b2 in valid:
                    if b2 == choice[j2] and j1 not in choice:
                        choice[j1] = b1
                        changed = True

    print(f"  propagation: {len(choice)}/312 after {iteration} rounds")

    # Pass 2: simulate in-place twist, use it to resolve remaining unknowns.
    mt = [0] * 624
    for idx in range(624):
        if idx % 2 == 0:
            mt[idx] = mt_even[idx]
        else:
            if idx in choice:
                mt[idx] = mt_odd_candidates[idx][choice[idx]]
            else:
                mt[idx] = mt_odd_candidates[idx][0]  # guess, may fix later

    # Simulate the in-place twist
    state = [None] * 624
    for i in range(624):
        if i < 623:
            nv = mt[(i + 1) % 624]
        else:
            nv = state[0]

        target = (i + 397) % 624
        if target < i:
            xv = state[target]
        else:
            xv = mt[target]

        y = (mt[i] & 0x80000000) | (nv & 0x7FFFFFFF)
        state[i] = xv ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)

    # Now use twist outputs at i >= 228 to pin down remaining odd bits
    for i_even in range(228, 624, 2):
        j1 = i_even + 1 if i_even < 623 else 0
        j2 = (i_even + 397) % 624

        expected_twisted = untemper(p2_w0[i_even // 2])

        if j1 in choice and j1 != 0:
            continue
        if j1 == 0:
            continue
        c0_j1, c1_j1 = mt_odd_candidates[j1]
        msb_i = mt_even[i_even] & 0x80000000

        for b1 in [0, 1]:
            val_j1 = [c0_j1, c1_j1][b1]
            y = msb_i | (val_j1 & 0x7FFFFFFF)
            xv = state[j2]
            tw = xv ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            if tw == expected_twisted:
                if j1 not in choice:
                    choice[j1] = b1
                    mt[j1] = val_j1
                    state[i_even] = tw
                break

    print(f"  pass 2: {len(choice)}/312 resolved")

    # Finalize
    for idx in range(624):
        if idx % 2 == 1 and idx in choice:
            mt[idx] = mt_odd_candidates[idx][choice[idx]]

    return mt


def predict_after(mt_state, n_consumed, count=1):
    genrand_consumed = n_consumed * 2
    periods = genrand_consumed // 624
    remainder = genrand_consumed % 624

    state = list(mt_state)
    for _ in range(periods):
        state = twist(state)

    idx = remainder
    results = []
    for _ in range(count):
        if idx >= 624:
            state = twist(state)
            idx = 0
        w0 = temper(state[idx]); idx += 1
        if idx >= 624:
            state = twist(state)
            idx = 0
        w1 = temper(state[idx]); idx += 1
        results.append(w0 | ((w1 >> 1) << 32))
    return results


def boundary_str(val):
    return f"==============={val:019d}=="


if __name__ == '__main__':
    for seed in [42, 0, 1, 99999, 123456789, 7777, 31337]:
        random.seed(seed)
        actual = [random.randrange(sys.maxsize) for _ in range(750)]
        mt = recover_state(actual[:624])
        predicted = predict_after(mt, 624, count=76)
        correct = sum(1 for i in range(76) if predicted[i] == actual[624 + i])
        print(f"Seed {seed}: {correct}/76 period-3 predictions")
        print()
