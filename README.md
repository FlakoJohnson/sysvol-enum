# sysvol-gpo-enum

Pure Go SYSVOL/GPO enumerator. Connects via SMB + LDAP, walks GPO directories, and parses policy files for misconfigurations and credential exposure. Single static binary, no Python, no impacket.

## Install

Download a prebuilt binary from [Releases](https://github.com/FlakoJohnson/sysvol-gpo-enum/releases) or build from source:

```bash
git clone https://github.com/FlakoJohnson/sysvol-gpo-enum
cd sysvol-gpo-enum
go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum .
```

Cross-compile for Windows:

```bash
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o sysvol-gpo-enum.exe .
```

## Usage

```bash
# Password
./sysvol-gpo-enum -u jsmith -p 'Password1' -d corp.local dc01.corp.local

# Pass-the-hash
./sysvol-gpo-enum -u jsmith -H aad3b435:fc525c9dc4a... -d corp.local dc01

# Kerberos (KRB5CCNAME must be set)
./sysvol-gpo-enum -u jsmith -k -d corp.local dc01

# SOCKS5 proxy + JSON output
./sysvol-gpo-enum -u jsmith -p 'P@ss' -d corp.local dc01 -proxy socks5h://127.0.0.1:1080 -o report.json

# Show all GPOs including clean ones
./sysvol-gpo-enum -u jsmith -p 'P@ss' -d corp.local dc01 --all -v
```

### Flags

| Flag | Description |
|------|-------------|
| `-u` | Username |
| `-p` | Password |
| `-d` | Domain FQDN (e.g. `corp.local`) |
| `-H` | LM:NT hashes for pass-the-hash |
| `-k` | Kerberos auth (reads `KRB5CCNAME`) |
| `-dc-ip` | DC IP if target arg is a hostname |
| `-proxy` | SOCKS5 proxy URL |
| `-o` | JSON output file |
| `--all` | Include GPOs with no findings |
| `-v` | Verbose output |

## What It Finds

| Severity | Examples |
|----------|---------|
| CRITICAL | cpassword in Groups/Drives/Tasks XML (MS14-025), AutoLogon plaintext password |
| HIGH | Password complexity disabled, lockout disabled, AutoLogon username, hardcoded script creds |
| MEDIUM | Weak min password length (<12), interesting Registry.pol entries |
| INFO | Privilege assignments, script commands, mapped drive usernames |

Parses: `GptTmpl.inf`, `Registry.pol`, `Groups.xml`, `Drives.xml`, `ScheduledTasks.xml`, `.ps1/.bat/.cmd/.vbs/.js`

## Evasion

- `crypto/rand` throughout — no predictable patterns
- Random jitter (50–350ms) between SMB calls
- Random Windows-style workstation name in NTLM negotiate
- Single static binary — no runtime dependencies
- Native SOCKS5 support
