# kanade M0 — Capture Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable the author to capture PS Remote Play network traffic from
their own console, extract TLS session keys from Sony's official PS Remote
Play app via Frida hooks, and decrypt the captured TLS layer in Wireshark.
This produces license-clean PCAP fixtures that the spec team can use to
derive `specs/*.md` for M1 onward.

**Architecture:** Three independent pieces working together:

1. **`tools/extract-keylog/`** — Frida JavaScript hook that attaches to PS
   Remote Play on macOS, captures TLS session keys at handshake completion,
   writes them to a file in `SSLKEYLOGFILE` format.
2. **Capture workflow** — documented `tcpdump` invocation that records LAN
   UDP + TCP traffic to a PCAP file.
3. **Analysis workflow** — documented Wireshark setup that loads the PCAP
   + SSLKEYLOG file and displays decrypted TLS payloads.

UDP-transport decryption (the encrypted post-TLS UDP stream that carries
video/audio) is **deferred to a post-M3 follow-up**: it requires the
crypto module implementation, which doesn't exist yet. M0 ships TLS-layer
decryption only.

**Tech Stack:**
- [Frida](https://frida.re) — dynamic instrumentation for the TLS hook
- [bats-core](https://github.com/bats-core/bats-core) — bash test framework
- `tcpdump`, Wireshark/`tshark` — capture and analysis (already installed)
- macOS as the primary target (PS Remote Play for macOS); plan documents
  Android fallback notes for future work

**Out of scope for M0:**
- UDP transport decryption (depends on M3 crypto impl)
- Windows / Linux platform support for `extract-keylog` (Mac only for now)
- Automatic packet inspection / parsing (humans + Wireshark do this in M1+)
- Any Rust code — M0 is bash + JavaScript only

**Definition of done:** Running the documented workflow against the
author's own PS5 + PS Remote Play.app on macOS produces a PCAP file in
`tools/captured/` that, when opened in Wireshark with the generated
SSLKEYLOG file, shows decrypted HTTPS registration traffic.

**Risk acknowledgment:** Sony may have added anti-instrumentation that
blocks Frida from attaching to PS Remote Play. If this happens, the M0
plan switches to the documented fallback (mitmproxy + cert-pinning bypass
via a planted CA). See Task 13 (contingency).

---

## File structure

Files to create (all paths relative to repo root):

| File | Responsibility |
|------|---------------|
| `tools/.gitignore` | Ignore `tools/captured/*` (private fixtures) |
| `tools/captured/.gitkeep` | Keep the directory in git, ignore contents |
| `tools/README.md` | Top-level capture + analysis workflow |
| `tools/extract-keylog/README.md` | Tool-specific docs, usage, troubleshooting |
| `tools/extract-keylog/extract-keylog.sh` | Bash launcher: validates args, invokes Frida |
| `tools/extract-keylog/hooks.js` | Frida JS: hook PS Remote Play's TLS layer, write SSLKEYLOG |
| `tools/extract-keylog/validate-keylog.sh` | Verify keylog file conforms to SSLKEYLOGFILE format |
| `tools/extract-keylog/tests/test_wrapper.bats` | bats tests for the bash launcher |
| `tools/extract-keylog/tests/test_validate_keylog.bats` | bats tests for the validator |
| `tools/extract-keylog/tests/fixtures/valid_keylog.txt` | Example well-formed keylog (synthetic) |
| `tools/extract-keylog/tests/fixtures/invalid_keylog.txt` | Example malformed keylog |
| `tools/RESEARCH.md` | Notes from binary inspection (Task 4): which TLS library, hook targets |

---

## Tasks

### Task 1: Scaffold the `tools/` directory + gitignore

**Files:**
- Create: `tools/.gitignore`
- Create: `tools/captured/.gitkeep`

- [ ] **Step 1: Create the `tools/` directory tree**

```bash
mkdir -p tools/captured tools/extract-keylog/tests/fixtures
```

- [ ] **Step 2: Write the gitignore**

Create `tools/.gitignore`:

```gitignore
# All captured PCAPs and keylog files are private fixtures.
# Capture mode artifacts must NEVER be committed.
captured/*
!captured/.gitkeep
```

- [ ] **Step 3: Add the `.gitkeep` placeholder**

```bash
touch tools/captured/.gitkeep
```

- [ ] **Step 4: Verify git sees what we expect**

Run: `git status tools/`
Expected output includes:

```
tools/.gitignore
tools/captured/.gitkeep
```

And NOT:

```
tools/captured/(anything else)
```

- [ ] **Step 5: Commit**

```bash
git add tools/.gitignore tools/captured/.gitkeep
git commit -S -m "chore(tools): scaffold capture fixtures directory with gitignore"
```

---

### Task 2: Install Frida and bats-core locally

These are runtime prerequisites for the tool and its tests. Neither is
currently installed on the author's machine (checked at plan-writing time:
`which frida` and `which bats` both not found).

**Files:** none modified.

- [ ] **Step 1: Install Frida CLI via Homebrew**

Run: `brew install frida`

Expected:
```
==> Installing frida
... (output)
🍺  /usr/local/Cellar/frida/<version>: ... files
```

- [ ] **Step 2: Verify Frida is callable**

Run: `frida --version`
Expected: a version string like `16.x.x`.

- [ ] **Step 3: Install bats-core via Homebrew**

Run: `brew install bats-core`

- [ ] **Step 4: Verify bats is callable**

Run: `bats --version`
Expected: `Bats X.X.X`.

- [ ] **Step 5: No commit — environment setup only.**

Note: if Homebrew is not available, fall back to manual install per each
tool's README. Do not commit lockfiles for system-level tooling.

---

### Task 3: Frida feasibility check against PS Remote Play

Before writing any hooks, prove that Frida can attach to PS Remote Play
on macOS. If it cannot, the plan switches to the mitmproxy fallback
(Task 13).

**Files:** none — this is a manual verification step that produces
research notes for Task 4.

- [ ] **Step 1: Install PS Remote Play for macOS if not present**

Download from Sony's official site (the only license-clean source).
Verify: `ls "/Applications/PS Remote Play.app"`.

- [ ] **Step 2: Launch PS Remote Play and leave it at the login screen**

Don't sign in yet — just confirm the app starts.

- [ ] **Step 3: List running processes Frida can see**

Run: `frida-ps -U | grep -i remote`

Expected: a line like `12345  RemotePlay` showing the running app's PID
and name. Note the exact process name — it'll be needed in Task 5.

- [ ] **Step 4: Attempt a no-op attach**

Run: `frida -p <PID-from-step-3> -e 'console.log("attached")'`

Expected: the string `attached` is printed and Frida exits cleanly.

**If the attach fails** (e.g., "Failed to attach: unexpected error
occurred while interacting with the target process"):

- Try with sudo (TCC permissions): `sudo frida -p <PID> -e 'console.log("ok")'`
- Try after granting Terminal full disk access in System Settings →
  Privacy & Security → Full Disk Access
- If still failing, document the exact error and skip to Task 13
  (contingency: mitmproxy).

- [ ] **Step 5: Document findings**

Create `tools/RESEARCH.md` with what you observed:

```markdown
# Capture-tooling research notes

## Frida feasibility (Task 3)

- Date attempted: YYYY-MM-DD
- PS Remote Play version: X.Y.Z
- Frida version: X.Y.Z
- Process name: `<exact name from frida-ps>`
- Attach succeeded: yes / no
- Notes: <what worked, what didn't, any system prompts>
```

- [ ] **Step 6: Commit the research notes**

```bash
git add tools/RESEARCH.md
git commit -S -m "docs(tools): record Frida feasibility findings against PS Remote Play"
```

---

### Task 4: Identify PS Remote Play's TLS library

The Frida hook needs to know what to hook. macOS apps commonly use one of:

- **Apple Network.framework** (modern, opaque, hard to hook)
- **Apple Secure Transport** (older, easier — has `SSLHandshake`, `SSLRead`, `SSLWrite`)
- **BoringSSL / OpenSSL** statically linked (most hookable — `SSL_read`, `SSL_write`, `SSL_new`)

**Files:**
- Modify: `tools/RESEARCH.md`

- [ ] **Step 1: Inspect the app bundle for linked libraries**

Run: `otool -L "/Applications/PS Remote Play.app/Contents/MacOS/RemotePlay" | head -40`

Look for one of:
- `/System/Library/Frameworks/Security.framework/Versions/A/Security` → Secure Transport / Network.framework
- `libssl.*.dylib` or embedded BoringSSL → OpenSSL-family
- Nothing TLS-specific in the output → TLS code is statically linked into the main binary

- [ ] **Step 2: If statically linked, look for telltale strings**

Run: `strings "/Applications/PS Remote Play.app/Contents/MacOS/RemotePlay" | grep -iE 'boringssl|openssl|mbedtls|gnutls' | head`

This often surfaces the version banner of the embedded TLS library, even
when it's not in the dynamic load list.

- [ ] **Step 3: List exported symbols (if any)**

Run: `nm -gU "/Applications/PS Remote Play.app/Contents/MacOS/RemotePlay" | grep -iE 'SSL_|TLS_' | head -30`

If you see symbols like `_SSL_read`, `_SSL_write`, `_SSL_CTX_new` →
BoringSSL or OpenSSL is statically linked. These are the hook targets.

- [ ] **Step 4: Document findings in RESEARCH.md**

Add a section:

```markdown
## TLS library identification (Task 4)

- otool linked frameworks: <copy relevant lines>
- Strings hits: <e.g., "BoringSSL b0e35e26...">
- Symbol hits: <e.g., SSL_read, SSL_write found via nm>
- Conclusion: <BoringSSL statically linked / Secure Transport / Network.framework / etc.>
- Hook strategy: <see Task 5>
```

- [ ] **Step 5: Commit**

```bash
git add tools/RESEARCH.md
git commit -S -m "docs(tools): identify PS Remote Play TLS library"
```

---

### Task 5: Write the Frida hook (`hooks.js`)

The hook implementation depends on the TLS library identified in Task 4.
This task gives the BoringSSL / OpenSSL variant in full because that's
the most common for cross-platform Sony apps. If Task 4 reveals
Network.framework, adapt accordingly (the structure of the hook stays
the same, only the function names change).

**Files:**
- Create: `tools/extract-keylog/hooks.js`

- [ ] **Step 1: Write the hook skeleton**

Create `tools/extract-keylog/hooks.js`:

```javascript
// Frida hook: extract TLS session keys from PS Remote Play.
//
// Strategy: intercept the BoringSSL/OpenSSL function that the application
// calls to install the keylog callback, or wrap SSL_CTX_set_keylog_callback
// directly to capture every line written to the SSLKEYLOGFILE format.
//
// Output: writes one line per key event to stdout in standard
// SSLKEYLOGFILE format (Wireshark-compatible).
//
// Reference: https://datatracker.ietf.org/doc/html/draft-thomson-tls-keylogfile

'use strict';

function log(line) {
    // SSLKEYLOGFILE lines start with a key type, e.g.:
    //   CLIENT_RANDOM <hex> <hex>
    //   CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex> <hex>
    //   SERVER_HANDSHAKE_TRAFFIC_SECRET <hex> <hex>
    //   CLIENT_TRAFFIC_SECRET_0 <hex> <hex>
    //   SERVER_TRAFFIC_SECRET_0 <hex> <hex>
    //   EXPORTER_SECRET <hex> <hex>
    console.log(line);
}

function attachHook() {
    // SSL_CTX_set_keylog_callback signature:
    //   void SSL_CTX_set_keylog_callback(SSL_CTX *ctx,
    //                                     void (*cb)(const SSL *ssl, const char *line));
    //
    // We install our own callback that logs every line. This is the
    // canonical way to extract keys from BoringSSL/OpenSSL since 1.1.1.

    const setKeylogCb = Module.findExportByName(null, 'SSL_CTX_set_keylog_callback');
    if (setKeylogCb === null) {
        send({type: 'fatal', message:
            'SSL_CTX_set_keylog_callback not exported. ' +
            'Check tools/RESEARCH.md for library type.'});
        return;
    }

    const cb = new NativeCallback(function (ssl, linePtr) {
        log(linePtr.readCString());
    }, 'void', ['pointer', 'pointer']);

    // Wrap every SSL_CTX_new so we install our callback on each context.
    const sslCtxNew = Module.findExportByName(null, 'SSL_CTX_new');
    if (sslCtxNew === null) {
        send({type: 'fatal', message: 'SSL_CTX_new not exported'});
        return;
    }

    Interceptor.attach(sslCtxNew, {
        onLeave: function (retval) {
            const ctx = retval;
            if (!ctx.isNull()) {
                new NativeFunction(setKeylogCb, 'void',
                                   ['pointer', 'pointer'])(ctx, cb);
                send({type: 'info', message: 'installed keylog cb on SSL_CTX ' + ctx});
            }
        }
    });

    send({type: 'info', message: 'hooks installed'});
}

attachHook();
```

- [ ] **Step 2: Lint the file syntax**

Run: `node --check tools/extract-keylog/hooks.js`
Expected: no output (syntax OK). If `node` is not installed, skip — the
Frida runtime will surface any syntax errors at attach time.

- [ ] **Step 3: Commit**

```bash
git add tools/extract-keylog/hooks.js
git commit -S -m "feat(tools): add Frida hook for TLS keylog extraction"
```

---

### Task 6: Write the bash launcher (TDD)

The launcher validates arguments, locates the target process, and invokes
Frida with the hook script. It writes captured keys to a file the user
chooses.

**Files:**
- Create: `tools/extract-keylog/extract-keylog.sh`
- Create: `tools/extract-keylog/tests/test_wrapper.bats`

- [ ] **Step 1: Write the failing test**

Create `tools/extract-keylog/tests/test_wrapper.bats`:

```bash
#!/usr/bin/env bats

setup() {
    WRAPPER="$BATS_TEST_DIRNAME/../extract-keylog.sh"
}

@test "exits non-zero when no output file given" {
    run "$WRAPPER"
    [ "$status" -ne 0 ]
    [[ "$output" == *"Usage:"* ]]
}

@test "exits non-zero when frida is missing" {
    run env PATH="/usr/bin:/bin" "$WRAPPER" /tmp/keylog.txt
    [ "$status" -ne 0 ]
    [[ "$output" == *"frida not found"* ]]
}

@test "prints help with --help" {
    run "$WRAPPER" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"Usage:"* ]]
}
```

- [ ] **Step 2: Run tests, confirm they fail**

Run: `bats tools/extract-keylog/tests/test_wrapper.bats`
Expected: 3 failures — script does not yet exist.

- [ ] **Step 3: Implement the launcher**

Create `tools/extract-keylog/extract-keylog.sh`:

```bash
#!/usr/bin/env bash
# extract-keylog.sh — attach Frida to PS Remote Play, capture TLS keys.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_JS="$SCRIPT_DIR/hooks.js"
APP_NAME_DEFAULT="RemotePlay"

usage() {
    cat <<EOF
Usage: $0 <output-keylog-file> [app-name]

Attach Frida to the running PS Remote Play app, capture TLS session keys
in SSLKEYLOGFILE format, and write them to <output-keylog-file>.

Arguments:
  <output-keylog-file>   Path to write the SSLKEYLOG output (e.g.,
                         tools/captured/2026-05-17.keylog)
  [app-name]             Process name to attach to (default: $APP_NAME_DEFAULT)

The app must already be running. Ctrl-C to stop capture.

Example:
  $0 tools/captured/session.keylog
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

if [ $# -lt 1 ]; then
    usage >&2
    exit 1
fi

OUT_FILE="$1"
APP_NAME="${2:-$APP_NAME_DEFAULT}"

if ! command -v frida >/dev/null 2>&1; then
    echo "Error: frida not found in PATH" >&2
    echo "Install with: brew install frida" >&2
    exit 1
fi

if [ ! -f "$HOOKS_JS" ]; then
    echo "Error: hooks.js not found at $HOOKS_JS" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT_FILE")"

echo "Attaching to '$APP_NAME', writing keylog to $OUT_FILE"
echo "Press Ctrl-C to stop."

# Frida prints hook output (one keylog line per print) to stdout.
# We tee that to OUT_FILE.
frida -n "$APP_NAME" -l "$HOOKS_JS" --runtime=v8 -q | tee "$OUT_FILE"
```

- [ ] **Step 4: Make it executable**

```bash
chmod +x tools/extract-keylog/extract-keylog.sh
```

- [ ] **Step 5: Run tests, confirm they pass**

Run: `bats tools/extract-keylog/tests/test_wrapper.bats`
Expected: 3 passes.

- [ ] **Step 6: Commit**

```bash
git add tools/extract-keylog/extract-keylog.sh tools/extract-keylog/tests/test_wrapper.bats
git commit -S -m "feat(tools): add bash launcher for Frida keylog extraction (TDD)"
```

---

### Task 7: Write the keylog format validator (TDD)

The validator confirms a generated keylog file is well-formed
SSLKEYLOGFILE before fixtures get used. Catches silent failures where
Frida runs but extracts nothing useful.

**Files:**
- Create: `tools/extract-keylog/validate-keylog.sh`
- Create: `tools/extract-keylog/tests/test_validate_keylog.bats`
- Create: `tools/extract-keylog/tests/fixtures/valid_keylog.txt`
- Create: `tools/extract-keylog/tests/fixtures/invalid_keylog.txt`

- [ ] **Step 1: Create the fixture files**

Create `tools/extract-keylog/tests/fixtures/valid_keylog.txt`:

```
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
SERVER_HANDSHAKE_TRAFFIC_SECRET 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
```

Create `tools/extract-keylog/tests/fixtures/invalid_keylog.txt`:

```
this is not a keylog file
just some random text
CLIENT_RANDOM short
```

- [ ] **Step 2: Write the failing tests**

Create `tools/extract-keylog/tests/test_validate_keylog.bats`:

```bash
#!/usr/bin/env bats

setup() {
    VALIDATOR="$BATS_TEST_DIRNAME/../validate-keylog.sh"
    VALID="$BATS_TEST_DIRNAME/fixtures/valid_keylog.txt"
    INVALID="$BATS_TEST_DIRNAME/fixtures/invalid_keylog.txt"
}

@test "accepts a well-formed keylog" {
    run "$VALIDATOR" "$VALID"
    [ "$status" -eq 0 ]
}

@test "rejects a malformed keylog" {
    run "$VALIDATOR" "$INVALID"
    [ "$status" -ne 0 ]
    [[ "$output" == *"invalid"* ]] || [[ "$output" == *"malformed"* ]]
}

@test "rejects an empty file" {
    EMPTY=$(mktemp)
    run "$VALIDATOR" "$EMPTY"
    rm -f "$EMPTY"
    [ "$status" -ne 0 ]
}

@test "rejects when file does not exist" {
    run "$VALIDATOR" /tmp/this-does-not-exist.txt
    [ "$status" -ne 0 ]
}
```

- [ ] **Step 3: Run tests, confirm they fail**

Run: `bats tools/extract-keylog/tests/test_validate_keylog.bats`
Expected: 4 failures.

- [ ] **Step 4: Implement the validator**

Create `tools/extract-keylog/validate-keylog.sh`:

```bash
#!/usr/bin/env bash
# validate-keylog.sh — verify a file conforms to SSLKEYLOGFILE format.
#
# Format reference:
#   https://datatracker.ietf.org/doc/html/draft-thomson-tls-keylogfile
#
# A valid line is:  <LABEL> <hex-client-random> <hex-secret>
# where LABEL is one of CLIENT_RANDOM, CLIENT_HANDSHAKE_TRAFFIC_SECRET,
# SERVER_HANDSHAKE_TRAFFIC_SECRET, CLIENT_TRAFFIC_SECRET_0,
# SERVER_TRAFFIC_SECRET_0, EARLY_TRAFFIC_SECRET, EXPORTER_SECRET, RSA.
# Comment lines beginning with # and blank lines are allowed.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <keylog-file>" >&2
    exit 1
fi

FILE="$1"

if [ ! -f "$FILE" ]; then
    echo "Error: file not found: $FILE" >&2
    exit 1
fi

if [ ! -s "$FILE" ]; then
    echo "Error: file is empty: $FILE" >&2
    exit 1
fi

VALID_LABELS='CLIENT_RANDOM|CLIENT_HANDSHAKE_TRAFFIC_SECRET|SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0|EARLY_TRAFFIC_SECRET|EXPORTER_SECRET|RSA'

# Pattern: <label> <hex>+ <hex>+
# Hex strings must be at least 16 chars (8 bytes) — anything shorter is
# almost certainly a malformed line.
LINE_RE="^(${VALID_LABELS}) [0-9a-fA-F]{16,} [0-9a-fA-F]{16,}$"

bad=0
total=0
while IFS= read -r line || [ -n "$line" ]; do
    # Skip blank lines and comments.
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue
    total=$((total + 1))
    if ! [[ "$line" =~ $LINE_RE ]]; then
        echo "invalid line: $line" >&2
        bad=$((bad + 1))
    fi
done < "$FILE"

if [ "$total" -eq 0 ]; then
    echo "Error: no key lines found in $FILE (only blanks/comments)" >&2
    exit 1
fi

if [ "$bad" -gt 0 ]; then
    echo "Error: $bad malformed line(s) out of $total" >&2
    exit 1
fi

echo "OK: $total valid key line(s)"
```

- [ ] **Step 5: Make it executable**

```bash
chmod +x tools/extract-keylog/validate-keylog.sh
```

- [ ] **Step 6: Run tests, confirm they pass**

Run: `bats tools/extract-keylog/tests/test_validate_keylog.bats`
Expected: 4 passes.

- [ ] **Step 7: Commit**

```bash
git add tools/extract-keylog/validate-keylog.sh \
        tools/extract-keylog/tests/test_validate_keylog.bats \
        tools/extract-keylog/tests/fixtures/valid_keylog.txt \
        tools/extract-keylog/tests/fixtures/invalid_keylog.txt
git commit -S -m "feat(tools): add keylog format validator (TDD)"
```

---

### Task 8: Write tool-level README

**Files:**
- Create: `tools/extract-keylog/README.md`

- [ ] **Step 1: Write the README**

Create `tools/extract-keylog/README.md`:

```markdown
# extract-keylog

Frida-based TLS keylog extractor for Sony's PS Remote Play app on macOS.

## What it does

Attaches to the running PS Remote Play process, hooks BoringSSL/OpenSSL's
`SSL_CTX_set_keylog_callback`, and writes every TLS session key event to
a file in standard `SSLKEYLOGFILE` format. Wireshark can then decrypt the
captured TLS traffic.

## Prerequisites

- macOS with Frida installed: `brew install frida`
- Sony's PS Remote Play.app installed in `/Applications/`
- bats-core for tests: `brew install bats-core`

## Usage

1. Launch PS Remote Play and leave it at the login screen.
2. In a terminal, start capture:

```bash
./extract-keylog.sh ../captured/2026-05-17-registration.keylog
```

3. Now perform the action you want to capture (sign in, register a
   console, start a session, etc.).
4. Press Ctrl-C to stop. The keylog file is written.

5. Validate the captured file:

```bash
./validate-keylog.sh ../captured/2026-05-17-registration.keylog
```

Expected: `OK: N valid key line(s)`.

## Use with Wireshark

1. Open the PCAP captured separately (see `../README.md` for `tcpdump`).
2. Wireshark → Preferences → Protocols → TLS.
3. Set "(Pre)-Master-Secret log filename" to the keylog file you just
   captured.
4. The TLS payloads in the capture will now decrypt.

## Tests

```bash
bats tests/
```

## Troubleshooting

- **`frida-ps -U | grep -i remote` returns nothing**: app not running.
- **`Failed to attach`**: Frida needs Terminal to have Full Disk Access
  (System Settings → Privacy & Security → Full Disk Access).
- **`SSL_CTX_set_keylog_callback not exported`**: PS Remote Play may have
  switched TLS library or stripped exports. Re-do Task 4 of the M0 plan
  and adjust `hooks.js`.
- **App crashes on attach**: anti-instrumentation. See contingency plan
  in M0 Task 13 (mitmproxy fallback).
```

- [ ] **Step 2: Commit**

```bash
git add tools/extract-keylog/README.md
git commit -S -m "docs(tools): add extract-keylog README"
```

---

### Task 9: Write the top-level capture workflow README

**Files:**
- Create: `tools/README.md`

- [ ] **Step 1: Write the README**

Create `tools/README.md`:

```markdown
# tools/

Capture-derivation tooling for kanade. **Not for distribution** — this is
the author's local capture workflow only.

These tools support **Capture mode** (per `docs/superpowers/specs/
2026-05-17-kanade-clean-room-design.md` §8.4). They are forbidden from
referencing chiaki/chiaki-ng source.

## Contents

- `extract-keylog/` — Frida hook for TLS key extraction. See its README.
- `captured/` — Local fixtures (gitignored). Captured PCAPs and keylog
  files live here.
- `RESEARCH.md` — Notes from binary inspection of PS Remote Play
  (TLS library identification, hook strategy).

## End-to-end capture workflow (macOS)

Capturing a registration exchange against your own PS5:

### 1. Identify your network interface

```bash
ifconfig | grep -B1 "inet 192" | grep "flags="
```

Most likely `en0` (Wi-Fi) or `en1` (Ethernet). Note the name.

### 2. Start tcpdump (in a dedicated terminal)

```bash
sudo tcpdump -i en0 \
    -w "tools/captured/$(date +%Y-%m-%d-%H%M)-registration.pcap" \
    -s 0 \
    'host <YOUR-PS5-IP>'
```

Replace `<YOUR-PS5-IP>` with the PS5's LAN IP (visible in PS5 Settings
→ Network → Connection Status).

### 3. Start extract-keylog (in another terminal)

```bash
cd tools/extract-keylog
./extract-keylog.sh "../captured/$(date +%Y-%m-%d-%H%M)-registration.keylog"
```

### 4. Perform the action in PS Remote Play

Open PS Remote Play, sign in, register your PS5 (enter the PIN your
console displays).

### 5. Stop both captures

Ctrl-C in each terminal.

### 6. Validate

```bash
ls -la tools/captured/
./tools/extract-keylog/validate-keylog.sh tools/captured/<keylog-file>
```

### 7. Open in Wireshark

- File → Open → select the `.pcap` file.
- Edit → Preferences → Protocols → TLS → set keylog file.
- TLS payloads now decrypt.

## What this enables (and what it doesn't, yet)

**Enabled by M0:** TLS-layer decryption of all HTTPS traffic between
PS Remote Play and the console (registration, control channel setup).

**Not yet enabled:** Decryption of post-TLS UDP transport (the bulk of
streaming traffic — video, audio, controller). The UDP transport uses
keys derived from messages exchanged over the TLS-protected control
channel. Once M3 ships the crypto + transport implementation, a
follow-up `decrypt-pcap` tool can apply those derivation rules to
decrypt captured UDP offline.

## Clean-room reminder

Files captured here are evidence used to derive `specs/*.md`. They are
your own data, captured against your own console, and they remain local
(see `.gitignore`). Do not commit captures containing your PSN account
identifiers or session keys.
```

- [ ] **Step 2: Commit**

```bash
git add tools/README.md
git commit -S -m "docs(tools): add top-level capture workflow README"
```

---

### Task 10: End-to-end smoke validation (cleartext discovery)

The first validation milestone: capture a discovery exchange (UDP
broadcast, no TLS, no keys needed). If this works, the basic capture
workflow is proven.

**Files:** none committed (the resulting PCAP stays in `tools/captured/`,
which is gitignored).

- [ ] **Step 1: Verify the PS5 is on and in standby or active**

If standby, the console responds to discovery probes.

- [ ] **Step 2: Start tcpdump filtering on the discovery port**

In one terminal:

```bash
sudo tcpdump -i en0 -w tools/captured/smoke-discovery.pcap -s 0 \
    'port 9302 or port 987'
```

- [ ] **Step 3: Trigger discovery from another terminal**

```bash
# Send a UDP probe to the broadcast address.
# Payload doesn't have to be valid yet — we just want any traffic.
echo -n "PROBE" | nc -u -w1 -b <BROADCAST-IP> 9302
```

Note: `<BROADCAST-IP>` is e.g. `192.168.1.255` for `192.168.1.0/24`.

- [ ] **Step 4: Or trigger via PS Remote Play "Search for console"**

PS Remote Play.app → "Manually register" → "Search". This sends real
discovery probes.

- [ ] **Step 5: Stop tcpdump (Ctrl-C)**

- [ ] **Step 6: Inspect**

```bash
tshark -r tools/captured/smoke-discovery.pcap | head -20
```

Expected: at least one UDP packet to/from the console's IP.

- [ ] **Step 7: Document outcome in RESEARCH.md**

Append:

```markdown
## End-to-end smoke (Task 10)

- Date: YYYY-MM-DD
- Captured: tools/captured/smoke-discovery.pcap (size: X bytes, Y packets)
- Outcome: discovery exchange visible / not visible
- Notes: <anything unusual>
```

- [ ] **Step 8: Commit the documentation update**

```bash
git add tools/RESEARCH.md
git commit -S -m "docs(tools): record M0 smoke test outcome"
```

---

### Task 11: End-to-end validation (TLS-decrypted registration)

The second validation milestone: capture and decrypt an actual TLS-
encrypted registration exchange. This proves the entire workflow
(capture + keylog + Wireshark) works end to end.

**Files:** none committed (captures stay local).

- [ ] **Step 1: Start both tcpdump and extract-keylog (see tools/README.md §1-5)**

Use a meaningful filename like `tools/captured/m0-validation-registration.pcap`
and matching `.keylog`.

- [ ] **Step 2: Perform PS5 registration via PS Remote Play**

Sign in, register the PS5, enter the PIN displayed on the console.

- [ ] **Step 3: Stop captures**

- [ ] **Step 4: Validate keylog**

```bash
./tools/extract-keylog/validate-keylog.sh tools/captured/m0-validation-registration.keylog
```

Expected: `OK: N valid key line(s)` with N ≥ 1.

- [ ] **Step 5: Decrypt in Wireshark**

Open the PCAP in Wireshark. Configure TLS keylog file. Filter:
`tls and ip.addr == <PS5-IP>`.

Expected: TLS payloads visible as decoded application data. If the
console runs a custom protocol over TLS, the bytes will be opaque but
visible (not encrypted-noise opaque).

- [ ] **Step 6: Document outcome**

Update `tools/RESEARCH.md`:

```markdown
## TLS decryption validation (Task 11)

- Date: YYYY-MM-DD
- TLS handshake captured: yes / no
- Keys extracted: N
- Wireshark decryption successful: yes / no
- Notes: <what's visible after decryption>
```

- [ ] **Step 7: Commit**

```bash
git add tools/RESEARCH.md
git commit -S -m "docs(tools): record TLS decryption validation outcome"
```

---

### Task 12: Update the design spec to mark M0 done

**Files:**
- Modify: `docs/superpowers/specs/2026-05-17-kanade-clean-room-design.md`

- [ ] **Step 1: Add an M0 status note to §10 (Milestones)**

Find the M0 entry in the §10 Mermaid `flowchart` and add a brief status
note immediately after the flowchart code block. Insert:

```markdown
**Status:**
- M0: ✅ Complete (YYYY-MM-DD). See `docs/superpowers/plans/2026-05-17-kanade-m0-capture-tooling.md`.
  Tools in `tools/extract-keylog/`. Cleartext discovery captures validated.
  TLS-decrypted registration validated. UDP transport decryption deferred
  to post-M3 follow-up.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-05-17-kanade-clean-room-design.md
git commit -S -m "docs(spec): mark M0 (capture tooling) complete"
```

---

### Task 13: Contingency — mitmproxy fallback (only if Frida fails)

**Execute this task only if Task 3 or Task 5 fails because Frida cannot
attach or hook PS Remote Play.** Otherwise skip to Task 14.

**Files (if executed):**
- Create: `tools/extract-keylog-mitm/`
- Create: `tools/extract-keylog-mitm/README.md`
- Create: `tools/extract-keylog-mitm/setup-mitmproxy.sh`
- Modify: `tools/RESEARCH.md`

- [ ] **Step 1: Document why Frida failed**

In `tools/RESEARCH.md`, expand the "Frida feasibility" section with the
exact failure mode (anti-instrumentation, code signing rejection, etc.).

- [ ] **Step 2: Install mitmproxy**

```bash
brew install mitmproxy
```

- [ ] **Step 3: Plant mitmproxy's CA in macOS keychain**

Per mitmproxy docs:
<https://docs.mitmproxy.org/stable/concepts-certificates/>

- [ ] **Step 4: Bypass certificate pinning in PS Remote Play**

This may require Frida (yes, the same Frida) for the cert-pinning
bypass alone — pinning bypass is a much smaller hook than full TLS key
extraction and may work even when key extraction is blocked.

- [ ] **Step 5: Configure macOS to route PS Remote Play through the proxy**

```bash
# Add proxy settings for the active network service:
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080
```

- [ ] **Step 6: Run mitmproxy and capture decrypted traffic**

```bash
mitmproxy --mode regular -w tools/captured/$(date +%Y-%m-%d-%H%M)-mitm.flows
```

- [ ] **Step 7: Document the fallback workflow in a new README**

Create `tools/extract-keylog-mitm/README.md` with the equivalent of
Task 8's README but for the mitm flow.

- [ ] **Step 8: Commit**

```bash
git add tools/extract-keylog-mitm/ tools/RESEARCH.md
git commit -S -m "feat(tools): mitmproxy fallback for TLS interception"
```

---

### Task 14: Final M0 commit + release

**Files:** verify all M0 commits are landed.

- [ ] **Step 1: Verify the file tree matches the plan**

Run: `find tools -type f | sort`

Expected (at minimum):
```
tools/.gitignore
tools/README.md
tools/RESEARCH.md
tools/captured/.gitkeep
tools/extract-keylog/README.md
tools/extract-keylog/extract-keylog.sh
tools/extract-keylog/hooks.js
tools/extract-keylog/tests/fixtures/invalid_keylog.txt
tools/extract-keylog/tests/fixtures/valid_keylog.txt
tools/extract-keylog/tests/test_validate_keylog.bats
tools/extract-keylog/tests/test_wrapper.bats
tools/extract-keylog/validate-keylog.sh
```

- [ ] **Step 2: Run all bats tests**

```bash
bats tools/extract-keylog/tests/
```

Expected: all tests pass.

- [ ] **Step 3: Verify shellcheck cleanliness (optional but recommended)**

```bash
shellcheck tools/extract-keylog/*.sh
```

Expected: no errors. Warnings about info-level style are fine.

- [ ] **Step 4: Push to origin**

```bash
git push origin main
```

- [ ] **Step 5: Tag the milestone**

```bash
git tag -s -a m0-capture-tooling -m "M0: capture tooling complete"
git push origin m0-capture-tooling
```

---

## Definition of done (M0)

All of these must be true:

- [ ] `tools/extract-keylog/extract-keylog.sh` exists, passes its bats tests
- [ ] `tools/extract-keylog/validate-keylog.sh` exists, passes its bats tests
- [ ] `tools/extract-keylog/hooks.js` attaches to PS Remote Play on macOS
      and produces SSLKEYLOG output (or the documented mitmproxy fallback
      from Task 13 works in its place)
- [ ] An end-to-end registration capture has been performed once and the
      TLS layer decrypts in Wireshark (documented in `tools/RESEARCH.md`)
- [ ] `tools/README.md` documents the full workflow
- [ ] `docs/superpowers/specs/...` updated with M0 status

UDP transport decryption is explicitly **not** part of M0; it lands as a
follow-up after M3.
