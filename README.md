# CounterCraft

A modular, open-source host auditing engine for **defensive** security use:
detecting supply-chain compromise, unauthorized system-level telemetry,
insecure UEFI/platform configuration, hidden persistence, and coprocessor/
out-of-band management exposure on your own machine.

CounterCraft is a Python 3.10+ CLI, installed as two console scripts --
`countercraft` and the short alias `cc` (both run the identical tool).
Every auditor is independent, degrades gracefully when a dependency or
elevated privilege is unavailable, and reports through one shared JSON +
CLI scoring engine.

## Architecture

```
pyproject.toml       PEP 621 packaging: [project.scripts] installs `countercraft` + `cc`
requirements.txt     pip-install convenience mirror of pyproject's optional-dependencies
countercraft/
  __init__.py         exposes __version__ (sourced from config.py)
  config.py           global constants: version, app name/aliases, default paths, severity weights
  cli.py              argparse CLI: `audit` (default) and `baseline save` subcommands
  mocks.py            offline fixture registry for --mock/--dry-run (TPM, CHIPSEC, ME, efivars, ...)
  core/
    base.py            BaseAuditor interface every auditor implements
    models.py          Finding / ModuleResult / AuditReport dataclasses, Severity enum
    reporter.py         JSON export engine + rich/plain-text terminal UI
    diff.py            State Baseline & Differential Engine (TPM PCRs / root CAs / kernel modules / EFI boot vars)
    utils.py           subprocess wrapper, privilege detection, platform helpers, mock-mode toggle
  modules/
    uefi_platform.py    Secure Boot, SPI write-protect, SMM lock (CHIPSEC + fallbacks)
    firmware_integrity.py  Firmware image extraction, hashing, baseline diff
    network.py          Passive outbound traffic + DNS-bypass detection
    persistence.py       Startup items / kernel modules / scheduled tasks
    tpm_auditor.py       TPM 2.0 PCR readout + baseline drift detection
    dma_auditor.py       IOMMU (VT-d/AMD-Vi) / Kernel DMA Protection
    me_auditor.py        Intel ME / AMD PSP state + AMT out-of-band probe
    ca_auditor.py        Root CA store scrutiny + UEFI dbx inspection
  utils/
    logger.py           centralized logging, every line tagged `[countercraft]`
    security.py          privilege-aware remediation messages + output sanitization
  resources/
    default_whitelist.yaml   sample network whitelist
tests/
  conftest.py           shared fixtures: mock-mode auto-reset, TPM/dmesg/EFI-variable sample data
  test_auditors.py       cross-cutting tests over every registered auditor
  test_*.py              per-module parsing/behavior tests
reports/                JSON report output (created on first run)
baselines/              saved TPM/firmware baselines, and the combined state baseline
```

Every auditor returns a `ModuleResult` containing zero or more `Finding`s,
each tagged `CRITICAL` / `WARNING` / `INFO`. The reporting engine
(`countercraft/core/reporter.py`) aggregates these into a JSON file and a
CLI summary table (via `rich` if installed, plain text otherwise) with an
overall weighted risk score.

> **Note on module identifiers:** each auditor's `.name` (shown in the CLI
> and JSON report) matches its file: `uefi_platform`, `firmware_integrity`,
> `network`, `persistence`, `tpm`, `dma`, `me`, `ca`.

## What requires elevation

| Check | Needs root/Administrator? |
|---|---|
| CHIPSEC SPI write-protect / SMM lock bit checks | **Yes** |
| Secure Boot state / PK/KEK/db/dbx read | No (read-only OS query) |
| Firmware image extraction & hashing | No (operates on a file you already dumped) |
| Dumping firmware with `flashrom` in the first place | **Yes** (not done by CounterCraft) |
| scapy packet capture (network module) | **Yes** (falls back to unprivileged `psutil` polling) |
| Full driver/service enumeration | Partial -- some fields hidden unprivileged |
| TPM PCR read (`tpm2_pcrread`) | Usually no (device-group permissions) |
| IOMMU/dmesg check | Partial -- `dmesg` may be root-restricted; falls back to `journalctl` |
| Intel ME mode / AMD PSP driver presence | No |
| AMT port probe | No |
| CA store enumeration / dbx read | No (Windows dbx byte read needs `SeSystemEnvironmentPrivilege`, implied by Administrator) |

Auditors never abort the whole run because one check needs elevation --
that check is skipped or degraded and clearly labeled as such in its
finding, with a remediation hint (e.g. "re-run elevated"). Where a command
is *known* to require elevation, `countercraft.utils.security.run_privileged`
skips attempting it entirely when unprivileged and returns a specific
message (what's missing and how to fix it) instead of a raw OS permission
error; `countercraft.utils.security.describe_missing_binary` does the same
for a missing external tool, naming the package to install where known.

## Dry-run / mock mode

Every check can run against synthetic data instead of real hardware/OS
state, via `--mock` (alias `--dry-run`) on either subcommand:

```bash
countercraft --all --mock
countercraft baseline save --mock
```

In mock mode, `which()`/`run_command()`/`run_powershell()`/`is_elevated()`
are all redirected through the fixture registry in `countercraft/mocks.py`
-- no real subprocess is ever invoked, no root/Administrator is required,
and no TPM, CHIPSEC driver, or ME/PSP hardware needs to be present. This is
the single interception point in `countercraft/core/utils.py`; individual
modules don't know mock mode exists. The fixtures are a deliberate mix of
clean and flagged results (an unsigned kernel module, a disabled SMM lock
bit, a Superfish-style root CA, a listening AMT port) so a `--mock` run
exercises -- and demonstrates -- the full severity range, not just the
all-clear path. Useful for demos, CI smoke tests, and developing/testing
on hardware that doesn't have a TPM or CHIPSEC-supported chipset.

## State baseline & differential audit

Beyond the per-artifact TPM/firmware baselines below, CounterCraft can
snapshot four broader trust-chain indicators -- TPM PCRs, installed root
CAs, loaded kernel modules, and EFI boot manager variables -- and flag
anything that changed since a saved baseline, with high-visibility
`CRITICAL`/`WARNING` findings appended to the normal report as a
`baseline_diff` module:

```bash
# Save a baseline once, on a known-good system (default path: baselines/baseline.json)
countercraft baseline save

# On later runs, compare against it
countercraft audit --all --diff
# or a specific baseline path:
countercraft audit --all --diff baselines/baseline.json
```

Each category is only compared when *both* the baseline and the current
run actually collected data for it -- a collection failure (no TPM this
boot, running unprivileged, non-UEFI system) is reported as a skipped
comparison, never as "everything in the baseline was removed". See
`countercraft/core/diff.py` for the full collection/comparison logic.

## Quick start

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux/macOS: source .venv/bin/activate
pip install -e ".[full,dev]"
```

This installs the `countercraft` and `cc` commands into the venv (via
`pyproject.toml`'s `[project.scripts]`). `python -m countercraft` works
identically without installing, if you'd rather not.

Run everything (uses `--all` implicitly when no module flags are given):

```bash
countercraft
# or, equivalently:
cc
```

Run specific modules:

```bash
cc --audit-uefi --audit-tpm --audit-ca
```

Run elevated for the checks that need it (recommended for a full audit):

```bash
# Linux/macOS
sudo cc --all

# Windows (from an elevated PowerShell/terminal)
cc --all
```

Firmware integrity, against a dumped image:

```bash
# 1. Dump SPI flash (requires root + a supported programmer)
sudo flashrom -p internal -r image.bin

# 2. Save a trusted baseline once, on a known-good system
cc --save-firmware-baseline baselines/firmware.json --firmware-image image.bin

# 3. On later runs, diff against it
cc --audit-firmware --firmware-image image.bin --firmware-baseline baselines/firmware.json
```

TPM PCR baseline, similarly:

```bash
cc --save-tpm-baseline baselines/tpm.json
cc --audit-tpm --tpm-baseline baselines/tpm.json
```

Passive network capture for 60 seconds against a custom whitelist:

```bash
cc --audit-network --network-duration 60 --network-whitelist my_whitelist.yaml
```

CA store check with a Mozilla-derived fingerprint reference list and a
specific dbx revocation-hash expectation:

```bash
cc --audit-ca --mozilla-ca-list mozilla_fingerprints.json --expected-dbx-hashes advisory_hashes.json
```

Full flag reference:

```bash
cc --help
cc baseline --help
```

Gate CI/scripts on findings of a given severity:

```bash
cc --all --fail-on critical   # exit code 1 if any CRITICAL finding exists
```

## Output

Every run writes a JSON report (default `reports/countercraft_report.json`)
with the full finding list and metadata, and (unless `--no-table`) prints a
CLI summary table like:

```
CounterCraft - Audit Summary
Host: mybox    OS: Linux 6.8.0 (...)
Risk Score: 145   CRITICAL: 1  WARNING: 6  INFO: 12

## uefi_platform
   [CRITICAL] Secure Boot disabled
              UEFI Secure Boot is disabled, allowing unsigned bootloaders...
   ...
```

Progress and diagnostic messages (`running: X ...`, elevation notices,
errors) go to stderr through the centralized logger
(`countercraft/utils/logger.py`), each line tagged `[countercraft]` --
easy to grep for or filter out when piping the CLI summary elsewhere.

## External tools CounterCraft integrates with

None of these are pip-installable; install via your OS package manager.
Every auditor works without them, at reduced fidelity (see each auditor's
`INFO`-level "not available" findings for exactly what was skipped).

| Tool | Used by | Purpose |
|---|---|---|
| [CHIPSEC](https://github.com/chipsec/chipsec) | uefi_platform | Register-level SPI/SMM checks (needs its kernel driver) |
| `mokutil` | uefi_platform | Linux Secure Boot state fallback |
| [UEFITool](https://github.com/LongSoft/UEFITool) (`UEFIExtract`) | firmware_integrity | Preferred firmware image extractor |
| `binwalk` | firmware_integrity | Fallback extractor |
| `flashrom` | (you, manually) | Dumping the SPI image CounterCraft then analyzes |
| [osquery](https://osquery.io/) (`osqueryi`) | persistence | Cross-platform startup/task/module queries |
| [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) (`tpm2_pcrread`) | tpm | PCR readout, Linux and Windows (via TBS) |
| [intelmetool](https://github.com/coreboot/coreboot/tree/master/util/intelmetool) | me | Intel ME HAP-bit/mode detail on Linux |
| `openssl` (CLI) | ca | CA store enumeration on Linux |

## Running the tests

```bash
pip install -e ".[dev]"
pytest -q
```

`tests/conftest.py` provides shared fixtures (mock-mode auto-reset between
every test, sample TPM/dmesg/EFI-variable payloads);
`tests/test_auditors.py` sweeps every registered auditor for the shared
contract (subclasses `BaseAuditor`, has a stable name, runs cleanly under
`--mock`); everything else targets the pure-parsing logic in each module
(PCR output parsing, EFI signature list decoding, IOMMU dmesg heuristics,
path classification, CHIPSEC output classification, etc.), the `--mock`
fixture registry, the diff engine's snapshot comparison logic, output
sanitization and privilege-remediation messaging, and a handful of
CLI-level end-to-end runs in `--mock` mode -- none of it requires root, a
TPM, or any of the external tools above.

## Extending CounterCraft

Every auditor subclasses `countercraft.core.base.BaseAuditor`, sets `name`
/ `description` / `requires_root`, and implements `audit()`, calling
`self.add_finding(title, severity, description, remediation=..., **metadata)`
for each observation. The base class handles privilege gating, timing, and
turning an unhandled exception into a recorded `ModuleResult.error` instead
of crashing the whole run -- a new auditor needs no changes anywhere else
except registering itself in `countercraft/modules/__init__.py` and adding
a `--audit-*` flag in `countercraft/cli.py`.

## Known limitations

- `persistence`'s path classifier does not resolve legacy DOS 8.3 short
  paths (`C:\PROGRA~2\...`) to their long form, so a legitimate vendor tool
  installed under a short-path alias may show as a `WARNING` needing manual
  review rather than being auto-cleared.
- `ca` does not ship a bundled Mozilla CA list or specific
  BlackLotus/Baton-Drop dbx revocation hashes -- supply them yourself via
  `--mozilla-ca-list` / `--expected-dbx-hashes` from the authoritative
  source, since bundling a point-in-time copy would go stale and become
  actively misleading.
- `me` cannot read the Intel HAP bit / ME operating mode on
  Windows without Intel's own MEInfo tool (not automated here); AMD PSP
  detail beyond driver presence is Linux-only in this build.
- `network`'s DNS-bypass detection (flagging a destination IP
  that was never preceded by a local DNS lookup) requires the scapy/Npcap
  capture path; the unprivileged `psutil` fallback can only see connection
  state, not DNS traffic.
- `core.diff`'s EFI boot variable collector uses a coarse per-entry hash
  (via `bcdedit /enum firmware` on Windows, raw efivarfs bytes on Linux)
  rather than fully parsing `UEFI_LOAD_OPTION` structures -- it reliably
  detects *that* an entry was added/removed/changed, not what specific
  field changed within it; cross-reference with `efibootmgr`/`bcdedit`
  directly to see the actual entry contents.
- `--mock` intercepts every subprocess-based check and the direct EFI
  variable reads used for Secure Boot keys and dbx, but not anything a
  module might read directly from the filesystem/network outside those
  paths -- if you add a new auditor that reads OS state some other way,
  give it a mock-mode branch too (see `uefi_platform._read_efivar` or
  `me_auditor._probe_amt_ports` for the pattern).
- The repository checkout folder on disk is not required to be named
  `countercraft` -- the package name (importable as `countercraft`, and
  installed as the `countercraft`/`cc` commands) is independent of
  whatever directory you cloned it into.
