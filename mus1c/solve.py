import re
from pathlib import Path

PRONOUNS = {"it", "he", "she", "they", "them", "ze", "hir", "xe", "xem", "ve", "ver"}


def poetic_number(words):
    digits = []
    for word in words.split():
        word = re.sub(r"[^a-zA-Z]", "", word)
        if word:
            digits.append(len(word) % 10)
    result = 0
    for d in digits:
        result = result * 10 + d
    return result


def run(lyrics_path):
    lines = Path(lyrics_path).read_text().splitlines()
    variables = {}
    last_assigned = None
    output = []

    def norm(name):
        return name.strip().lower()

    def get_var(name):
        n = norm(name)
        if n in PRONOUNS:
            n = last_assigned
        return variables.get(n, 0)

    def set_var(name, value):
        nonlocal last_assigned
        n = norm(name)
        if n in PRONOUNS:
            n = last_assigned
        variables[n] = int(value)
        last_assigned = n

    def eval_expr(expr):
        expr = expr.strip()
        for op, fn in [
            (" without ", lambda a, b: a - b),
            (" with ", lambda a, b: a + b),
            (" times ", lambda a, b: a * b),
            (" of ", lambda a, b: a * b),
        ]:
            idx = expr.lower().find(op)
            if idx != -1:
                left = expr[:idx]
                right = expr[idx + len(op) :]
                return fn(eval_expr(left), eval_expr(right))
        return get_var(expr)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Expand 's contractions (e.g. "Pico's" → "Pico is")
        line = re.sub(r"(\w+)'s\b", r"\1 is", line)
        lower = line.lower()

        # shout / say / whisper → output as ASCII char
        if lower.startswith(("shout ", "say ", "whisper ")):
            expr = line.split(None, 1)[1]
            output.append(chr(int(eval_expr(expr))))
            continue

        # Put <expr> into <var>
        m = re.match(r"(?i)put\s+(.+?)\s+into\s+(.+)", line)
        if m:
            set_var(m.group(2), eval_expr(m.group(1)))
            continue

        # Knock <var> down[, down...]
        m = re.match(r"(?i)knock\s+(.+?)\s+down(.*)", line)
        if m:
            count = 1 + m.group(2).lower().count("down")
            set_var(m.group(1), get_var(m.group(1)) - count)
            continue

        # Build <var> up[, up...]
        m = re.match(r"(?i)build\s+(.+?)\s+up(.*)", line)
        if m:
            count = 1 + m.group(2).lower().count("up")
            set_var(m.group(1), get_var(m.group(1)) + count)
            continue

        # Poetic number literal: <var> is/was/are/were <words>
        m = re.match(r"(.+?)\s+(?:is|was|are|were)\s+(.+)", line, re.IGNORECASE)
        if m:
            set_var(m.group(1), poetic_number(m.group(2)))
            continue

    return "".join(output)


if __name__ == "__main__":
    result = run(Path(__file__).parent / "lyrics.txt")
    print(f"picoCTF{{{result}}}")
