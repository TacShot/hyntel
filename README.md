# Hyntel — Rust Security Audit CLI

The Rust CLI is the replacement runtime for Hyntel. The historical Python implementation remains in Git history and source for migration traceability; Rust is the supported entry point.

## Build and run
```sh
cargo build --release
cargo test
cargo run -- --interactive
```

No-argument execution opens an interactive terminal workflow. Automation examples:
```sh
cargo run -- --target-os auto --scan-apps --scan-logs --verify-ad --include-cves
cargo run -- --target-os linux --format json --no-export
cargo run -- --target-os windows --verify-ad --report-dir ./reports
```

## Features
- Linux, macOS, and Windows baseline configuration checks
- Optional application and process inventory with heuristic process indicators
- Optional last-24-hour security log/event collection
- Optional Active Directory/domain membership, discovery, trust, and client configuration diagnostics
- Optional NIST NVD CVE enrichment for failed configuration findings
- TXT, JSON, and CSV report bundle; enabled scan results appear in all applicable outputs
- Human-reviewable remediation plan; no remediation is executed automatically
- Interactive CLI and non-interactive flags

## Limitations
Host checks are best-effort and may require platform utilities or elevated privileges. Linux SSH checks inspect the main sshd_config file and do not fully resolve Include/Match semantics. Application inventory is package-manager based; CVE associations are contextual and are not proof of exploitability. Log collection is bounded to the previous 24 hours and can be restricted by permissions. AD checks are diagnostics, not a full domain-controller health assessment. Process indicators are heuristics, not malware verdicts. Validate on real hosts for each supported OS before production use.

## Security
Commands are invoked without shell interpolation except command discovery. Remediation is never run automatically. Use only on systems you are authorized to assess.
