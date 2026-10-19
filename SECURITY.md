# Security policy

## Reporting a vulnerability

Report privately through [GitHub Security Advisories](https://github.com/immutex/pi-ghidra/security/advisories/new).
Do not open a public issue for a vulnerability.

Include the affected version, the action and request shape, and the smallest
reproduction you can share. You will get an acknowledgement, an assessment, and a
fix or mitigation plan.

## Threat model

pi-ghidra runs Ghidra's headless analyzer over files chosen by the agent. Ghidra
parses those files with native components, so a hostile binary is untrusted input to
Ghidra itself.

What this package does:

- Runs each request in a disposable JVM and kills the process tree on timeout or
  cancellation.
- Keeps requests and responses in files instead of shell arguments or stdout.
- Caps list pages, memory reads, patches, search scans, response size, and tool output.
- Rejects cache paths with characters that break Ghidra project paths or Windows
  command wrappers.
- Serializes access per artifact with a lock directory.
- Never modifies the source binary; patches apply to the cached project.

What it does not do:

- It is not an OS sandbox. Ghidra runs with your user privileges.
- It does not scan or sanitize the binary before analysis.
- It does not expose arbitrary Java/Python execution, arbitrary project paths, or a
  network listener.

Analyze untrusted or hostile files in a disposable VM or container with no sensitive
data mounted.

## Supported versions

The latest published minor version receives security fixes. Older versions may be
asked to upgrade before a fix is backported.
