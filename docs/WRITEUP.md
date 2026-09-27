# Building an AI agent that caught a real BEC — and why my first version failed

*By Harikishore Karunanithi*

## The problem

A Microsoft 365 account got compromised. The evidence was ~40 MB across ~30
files — Entra interactive/non-interactive sign-ins, the Unified Audit Log
(thousands of rows, each a fat JSON blob), and message-trace exports. You can't
paste that into a chat window, and clicking through it by hand takes a day.

I wanted to see how close an AI system could get to a human analyst's
root-cause analysis — so I built **BlueCell**, a local pipeline that ingests
raw multi-source logs and reasons over them. Then I graded it against a real,
independent forensic RCA of the same incident.

## Version 1 was confidently wrong

My first build was fast and passed all its tests. It ingested the logs,
correlated events, mapped them to MITRE ATT&CK, and produced a verdict.

On the real compromise, it said: **"likely benign — failed-login noise."**

That is the worst possible answer. It's a **false negative on a genuine
breach.** If a SOC trusted it, they'd have closed a real account-takeover.

Two things caused it, and neither was glamorous:

1. **The "AI agents" weren't reasoning — they were `if/else`.** I'd wrapped
   fixed Python rules in an agent structure and called it AI. The only rule that
   fired was "failed login → brute force," so the tool literally could not see
   the actual attack.
2. **The parser threw away the signal.** The real attack lived in fields my
   parser ignored — the sign-in "Original transfer method" (device-code flow),
   and Unified Audit Log operations like `MailItemsAccessed`, `New-InboxRule`,
   and `Send`. If the evidence never reaches the analyst, no analyst — human or
   AI — can find the attack.

## What fixed it

**1. Make the agents actually reason.** I moved the analysis to model-driven
agents (a Lead DFIR analyst + a Tier-2 reviewer) that read a distilled evidence
brief and return a structured verdict and storyline. Python's job shrank to two
things: assembling the brief, and checking the answer.

**2. Surface the real signal.** I wrote a Unified Audit Log parser and enriched
the sign-in parser so device-code flow, device registration, mailbox access,
and inbox rules become first-class events mapped to ATT&CK (T1078, T1114,
T1564.008, T1566…).

**3. Ground everything.** An LLM will happily invent an IP or a hash. So after
the model writes anything, BlueCell extracts every IP / domain / hash /
technique it cited and verifies each against the actual logs. Anything not in
the evidence is flagged **UNVERIFIED**. A prompt *asks* the model not to
hallucinate; this *enforces* it.

## The result

On the same real logs, the model-driven agents returned **likely-malicious
(0.78 confidence)** and independently reconstructed:

- **Initial access:** device-code-flow sign-ins from two US hosting IPs, tied to
  two attacker-registered device IDs.
- **Persistence / evasion:** a `New-InboxRule` created from the attacker device.
- **Collection:** thousands of `MailItemsAccessed` events on the mailbox.
- **Impact:** outbound sends from the mailbox.

…and it honestly listed what the logs **don't** prove (the original phishing
lure) — which matched the "NOT PROVEN" sections of the human forensic RCA.

## The honest takeaways

- **An "AI SOC analyst" is only as good as the evidence you feed it.** Most of
  the work was parsing and distillation, not prompting.
- **The tool is not smarter than the model — it *is* the model.** Its value is
  the engineering around it: scale, normalization, grounding, repeatability.
  For a few logs that fit in a chat, just use the chat.
- **Grounding is non-optional** for anything security-facing. Confident wrong
  answers are more dangerous than "I don't know."
- **Ship the failure story.** v1 being wrong is the most useful part of this
  project.

Code (MIT), with the full commit history showing the arc from the broken v1 to
the grounded, model-driven version: [link]

---

### Shorter version for a LinkedIn post

> I built an AI system to investigate a real Microsoft 365 account compromise
> from 40 MB of raw Entra + audit logs. My first version confidently called a
> genuine breach "benign noise." 😬
>
> Fixing that taught me more than any tutorial:
>
> 1/ My "AI agents" were actually just if/else rules in a trench coat. They
> couldn't see the attack because they weren't reasoning — they were matching.
>
> 2/ The parser was throwing away the exact signal that mattered: device-code
> flow sign-ins, Unified Audit Log operations (MailItemsAccessed, New-InboxRule,
> Send). No evidence in → no attack found.
>
> 3/ LLMs hallucinate IOCs. So I added a grounding step that fact-checks every
> IP/hash/domain the model cites against the actual logs and flags anything it
> invented.
>
> After the rebuild, the model-driven agents reconstructed the whole chain —
> device-code initial access, attacker device registration, a hidden inbox rule,
> mass mailbox access, outbound phishing — and matched an independent forensic
> RCA, including honestly flagging what the logs *couldn't* prove.
>
> Biggest lesson: an AI analyst is only as good as the evidence you feed it, and
> "confidently wrong" is the most dangerous output in security. Grounding isn't
> optional.
>
> Repo (MIT), including the broken v1 in the commit history so you can see the
> whole arc 👇
>
> #DFIR #DetectionEngineering #SOC #MITREATTACK #LLM #AIsecurITY #BEC
