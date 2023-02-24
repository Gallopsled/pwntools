# Security Policy

## Supported Versions

| Version       | Supported          |
| ------------- | ------------------ |
| latest dev    | :white_check_mark: |
| latest beta   | :white_check_mark: |
| latest stable | :white_check_mark: |
| anything else | :x: |

## Reporting a Vulnerability

The aim of pwntools is exploiting software vulnerabilities, which is an unusual position, but it nevertheless can have its own security issues.
Especially that an attacker (=re-victim) is usually not prepared to be attacked back (by the re-attacker).

The first question to ask yourself is: is this an actual vulnerability?
- can it be triggered by a re-attacker (malicious honeypot pretending to be a vulnerable service)?
- does it impact the attacker (=re-victim)?
- is it serious?
  * *availability: medium* means *at least* exhausting RAM or disk space of the attacker (=re-victim)
  * *confidentiality: medium* means *at least* reading the filesystem of the attacker (=re-victim)
  * *integrity: medium* means *at least* performing uncontrolled actions or data corruption on behalf of the attacker (=re-victim)
  * if crucial for some sophisticated exploit chain, it is always serious
  * `safe_eval` bypasses **are** serious.
  * an example of what was **kind of** serious: [#1732](https://github.com/Gallopsled/pwntools/pull/1732)
- can it be fixed without compromising on Pwntools' usability?

If at least one of the answers is no, then this is NOT a vulnerability, so just file a bug report or feature request, without the weird confidential disclosure dance.

Just e-mail the maintainers.  Arusekk is the one that is currently the most excited to fix vulnerabilities.
Or create a CTF task!  Prove a point the good old hacker way!
