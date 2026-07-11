# Security Policy

## Experimental status

SentinelDB is an **experimental V0/V1 prototype**. It has not undergone a
third-party security audit or load testing, and it makes no compliance
claims (GDPR, KVKK, PCI, or otherwise). Do not treat it as a production
security boundary or as a substitute for database-level access controls,
encryption at rest/in transit, or a compliance program. See
[docs/threat-model.md](docs/threat-model.md) for a fuller breakdown of
what is and is not protected.

By using SentinelDB you accept that it is provided without any
security or compliance warranty (see [LICENSE](LICENSE) — provided "AS
IS", no warranty of any kind).

## Supported versions

Only the **latest tagged V0 release** receives any security attention.
Older tags and untagged commits on `main` are not supported. There is no
long-term-support branch at this stage of the project.

| Version                    | Supported |
|-----------------------------|-----------|
| Latest tagged `v0.x` release | Yes       |
| Anything older               | No        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue or pull request for a
suspected vulnerability, and please do not disclose exploit details
publicly before the maintainer has had a chance to review and respond.

Preferred method: use **GitHub's private vulnerability reporting**, if
enabled on this repository — go to the **Security** tab of
[gkurcaloglu/SentinelDB](https://github.com/gkurcaloglu/SentinelDB) and
select **Report a vulnerability**. This opens a private draft advisory
visible only to the maintainer.

If private vulnerability reporting is not available on this repository,
open a minimal, **non-sensitive** issue (e.g. "Security contact
requested — no public details") asking the maintainer to open a private
communication channel. Do not include exploit details, proof-of-concept
payloads, or sensitive data in that initial issue.

When reporting, please include (once a private channel is established):

- affected version/commit
- a description of the issue and its potential impact
- reproduction steps or a minimal proof of concept, if you have one

## No security or compliance warranty

SentinelDB is provided without any warranty, express or implied,
including any warranty of fitness for a particular security or
compliance purpose (see [LICENSE](LICENSE)). Reported issues will be
reviewed on a best-effort basis; there is no guaranteed response time or
service-level agreement.

## Do not use the current release as a production security boundary

As documented in [README.md](README.md#v1-limitations-be-aware-of-these-before-using-this-anywhere-real)
and [docs/threat-model.md](docs/threat-model.md), the current release:

- ships as a **plaintext development-mode tool** (no TLS termination);
- enforces firewall rules via exact-phrase text matching, not a real SQL
  parser, and is relatively easy to bypass by a motivated client;
- masks only explicitly configured columns via exact column-name match,
  with no automatic PII discovery or classification.

Do not point SentinelDB at a production database or rely on it as your
only or primary control against data exfiltration or destructive
queries.
