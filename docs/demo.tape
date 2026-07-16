# Mycroft demo — regenerate the GIF with:  vhs docs/demo.tape
# Prerequisite: run from the repo root after `cargo build --release`.
# Produces docs/demo.gif. See https://github.com/charmbracelet/vhs

Output docs/demo.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 820
Set Padding 20
Set TypingSpeed 40ms

# --- hidden setup: put `mycroft` on PATH, work in a scratch dir with a sample scan
Hide
Type `export PATH="$PWD/target/release:$PATH"; FIX="$PWD/fixtures/nuclei/findings.jsonl"; cd "$(mktemp -d)"; cp "$FIX" scan.jsonl; clear`
Enter
Show

Type "mycroft init --name acme-q3 --client 'ACME Corp'"
Enter
Sleep 1.2s

Type "mycroft scope add 10.0.0.0/24 --type cidr"
Enter
Sleep 700ms
Type "mycroft scope add 10.0.0.53 --kind out --type cidr"
Enter
Sleep 900ms

# guard verdicts (dry-run) — allow, exclude, default-deny
Type "mycroft scope check 10.0.0.10"
Enter
Sleep 1.2s
Type "mycroft scope check 10.0.0.53"
Enter
Sleep 1.2s

# normalize an existing scan into findings
Type "mycroft import --tool nuclei scan.jsonl"
Enter
Sleep 1.2s
Type "mycroft findings"
Enter
Sleep 2s

# one client-ready report + tamper-evident audit check
Type "mycroft report"
Enter
Sleep 1.8s
Type "mycroft verify"
Enter
Sleep 2s
