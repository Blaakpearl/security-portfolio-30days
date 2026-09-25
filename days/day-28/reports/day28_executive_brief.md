# Day 28 — Executive Brief
## Who Attacked Us and What They'll Do Next
**NovaCrest Capital Group | Board & Executive Distribution**
**Classification:** TLP:RED — C-Suite and Legal Counsel Only
**Prepared by:** V. Willis, CISSP — Security Operations
**Date:** 2026-06-28

---

## What We Now Know About the Attacker

Through open-source intelligence investigation, we have built a detailed
picture of the group that attacked NovaCrest. We are calling them FIN-NC-001.
Here is what we know about them:

**They are professional, experienced, and financially motivated.** This is
not a random attack. NovaCrest was deliberately selected based on its size
($4.2B AUM) and publicly visible technology footprint. The group has attacked
at least three other financial services firms in 2026 alone — a UK private
equity firm, a European asset manager, and a US hedge fund — all in the same
$2–5B AUM range.

**They escalate their demands with each victim.** The UK firm was charged $2.1M.
The European firm $2.6M. The hedge fund $3.1M. NovaCrest's demand of $4.2M
follows the exact same formula — approximately 0.1% of our reported AUM.
They did their research before setting the ransom.

**One of the four previous victims paid.** The US hedge fund negotiated and paid
approximately $2M (35% below asking price) in May 2026. The attacker promptly
removed the victim's data from their public leak site, as promised. This tells
us the attacker honors the terms of payment — which is the most dangerous
kind of criminal to deal with.

**Two victims did not pay and had their data published.** The UK private equity
firm's 67 GB of client data was published publicly. The European firm's 42 GB
followed. Both firms then faced regulatory consequences on top of the breach itself.

---

## The June 22 Deadline

Our ransom deadline is **June 22, 2026 at 06:14 UTC**. The attacker has posted
our name on their leak site on the dark web. Based on their demonstrated behavior
with the UK and EU firms, if we do not pay, they will publish the approximately
293 MB of client and trading data they exfiltrated before deploying the ransomware.

**Our recommendation is not to pay.** Our reasons:

1. We have a viable backup from June 13 that allows us to recover without a decryptor
2. Payment would likely require OFAC review (LockBit-affiliated groups are sanctioned)
3. Payment is not guaranteed to prevent publication — only their word, and we have limited leverage
4. The FBI has obtained LockBit decryption infrastructure through Operation Cronos; there is a path to recovery that doesn't fund the attacker

**The data publication risk is real and requires a parallel response track** —
client notification, regulatory preparation, and legal strategy — regardless
of payment decision.

---

## What We Found About Their Infrastructure

We identified six domains the attackers have used across their four known
campaigns. Every domain was registered 8 days before the corresponding attack.
We have shared all of these with our financial sector intelligence partners
(FS-ISAC) so other firms can block them.

We also identified a second C2 server (the system they used to control their
malicious software inside our network) that was not previously known. This
has been shared with the FBI.

Most importantly: **the attacker's systems have remained visible for over
three months without them being shut down.** This is consistent with using
hosting providers in Panama/Netherlands that deliberately ignore law enforcement
requests. The FBI is aware; international coordination is required for takedown.

---

## Their Next Target

Based on the pattern: approximately 50 days after our phishing email was
delivered on June 14, the group is likely to begin targeting their next victim.
That points to approximately **early August 2026**.

Their next target will likely be another US or European investment management
firm with $5–6B AUM, targeted with a conference-related email — either a real
upcoming industry event or a fabricated one using familiar names.

We have produced an early warning checklist that has been shared with FS-ISAC
and the FBI. If the attacker registers their next phishing domain in the
coming weeks, financial sector firms will have 6+ days of advance warning
before the first email is sent — unlike NovaCrest, which had no warning.

---

## The Three Most Important Actions Right Now

1. **Engage FBI:** We have provided them a full intelligence package. Active
   cooperation maximizes our chance of recovering encrypted files through
   Operation Cronos and supports any future prosecution.

2. **Client outreach strategy:** Legal counsel and the CISO should align on
   the notification timeline. The SEC 72-hour clock for material cybersecurity
   incidents has already run. We need to get ahead of the June 22 deadline
   rather than respond to it.

3. **Delete the two remaining backdoors:** Our security team identified two
   active backdoors the attacker placed in our cloud environment. Until these
   are deleted, the attacker retains access to our AWS infrastructure.
   This should have happened 48 hours ago. It must happen today.

---

*Day 28 — Executive Brief | NovaCrest Capital Group*
*V. Willis, CISSP | For questions, contact the CISO directly*
