# Security Policy

## Reporting a vulnerability

Email **johnnypicklespartners@gmail.com** with details and, where relevant, a
proof of concept. A machine-readable copy of this contact lives at
[`/.well-known/security.txt`](public/.well-known/security.txt).

Please report privately and give us a reasonable chance to fix an issue before
any public disclosure.

## Security model in one line

WhisperFox is zero-knowledge: messages are encrypted in the browser and never
reach the server, which stores no message content. A full server or KV breach
therefore exposes **no messages** — see the "Security model and limits" section
of the [README](README.md) for the full threat model, including the deliberate
best-effort limits (burn-after-read, self-destruct) and the stolen-root-material
analysis.
