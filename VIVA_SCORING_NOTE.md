# Risk-Scoring Model — Viva Study Note (plain English)

A note to learn from. For every design choice it says **what I did**, **why**, and
**which reference backs it + what that reference actually said**.

---

## 1. The one-line summary (say this first)

> "Each incident gets a score from 0 to 100, built from three parts — how far the
> attack went (breadth), whether it hit the dangerous stages (milestones), and how
> fast it happened (velocity). The score is then placed into a severity band so an
> operator knows what to deal with first. Every part has a clear reason and a source,
> so the score can be explained, not just trusted."

**The formula:**
```
risk = (phases ÷ 5) × 50        → breadth    (0–50)
     + 15 if exploitation       → milestone
     + 15 if persistence        → milestone
     + 15 if command & control  → milestone
     + velocity bonus           → (0–10)
   clamped to a maximum of 100

Bands: 80+ Critical · 60–79 High · 40–59 Medium · below 40 Low
```

---

## 2. Breadth — "how far along the attack got" (up to 50 points)

**What I did:** Count how many of the five kill-chain phases the campaign reached, and
give it 10 points per phase. This is the biggest single part of the score.

**Why:** An attack that only scanned is far less serious than one that scanned, broke
in, and set up a backdoor. More phases completed = closer to a full compromise. Since
detecting that progression is the whole point of the engine, it gets the most weight.

**Reference — Hutchins, Cloppert & Amin (2011), the Cyber Kill Chain paper.**
What it actually says: an intrusion is a *chain* of steps (reconnaissance → delivery →
exploitation → … → actions on objectives), and the attacker has to get through every
link to succeed — break any one link and the attack fails. So the further down the
chain the attacker is, the more of that chain they have completed and the more dangerous
they are. That is exactly why I reward more phases, and reward them the most.

---

## 3. Milestones — "did it hit the dangerous stages" (15 points each)

**What I did:** Add a fixed 15-point bonus for reaching **exploitation**, **persistence**,
or **command and control**. Reconnaissance and delivery get *no* bonus.

**Why:** The phases are not equally dangerous. Scanning and delivery happen all the time
and on their own prove little. But exploitation means code actually ran, persistence
means the attacker set up to survive a reboot, and command and control means there is a
live remote channel into the machine. Those three are the "real damage" markers, so they
deserve extra weight. This makes the score *depth-aware*, not just a phase count.

**Reference — MITRE ATT&CK (2023).**
What it actually says: it is a knowledge base of real attacker behaviour, and it defines
each tactic as an attacker goal — Execution = "trying to run malicious code," Persistence
= "trying to keep their foothold" (it even lists Startup-folder/Run-key persistence,
T1547.001, which is exactly what my capture caught), and Command and Control = "trying to
communicate with the compromised system to control it." So MITRE confirms these three are
distinct, serious objectives — which is why I single them out for a bonus.

---

## 4. Velocity — "how fast the attack happened" (up to 10 points)

**What I did:** Give 10 points if the whole campaign finished within an hour, 7 within
six hours, 4 within a day, and 1 if it took longer.

**Why:** The faster an attack unfolds, the less time a defender has to react, so a fast
attack is more urgent. Speed is treated as a risk signal.

**Reference (the principle) — McQueen et al. (2006) and Leversage & Byres (2008),
the "time-to-compromise" research.**
What they actually say: they measure *how long* it takes an attacker to compromise a
system and treat that time as a security/risk metric — a shorter time-to-compromise means
higher risk. This is the academic basis for using attack speed in a score. (Leversage &
Byres is a peer-reviewed IEEE paper; McQueen et al. is a peer-reviewed Springer chapter.)

**Reference (the real-world numbers) — CrowdStrike (2026) and Mandiant (2026).**
What they actually say: CrowdStrike's 2026 report measured the average "breakout time"
(how fast an intruder spreads from the first machine) at about **29 minutes**, fastest
**27 seconds**. Mandiant's M-Trends 2026 puts median "dwell time" at about **14 days**.
I use these to show the sub-hour top band is realistic — real attacks really do move in
minutes.

> **If the examiner asks "why is your demo always velocity = 10?"**
> Say: the demo *replays* a two-day attack in a few minutes so it can be shown live, so
> the timestamps are compressed and velocity maxes out. In the real captured timeline the
> attack spanned ~2 days, which would score velocity = 4 (score ~96). The maximum in the
> demo is a presentation artefact, not a flaw in the model.

---

## 5. Banding — "turn the number into Low/Medium/High/Critical"

**What I did:** Map the 0–100 score to four bands: 80+ Critical, 60–79 High, 40–59
Medium, below 40 Low.

**Why:** A raw number means little to a busy operator; a band tells them what to act on
first. Because every incident has at least two phases, nothing can score below 20, so in
practice Low is 21–39.

**Reference — CVSS v3.1 (FIRST, 2019) and NIST SP 800-61 Rev.2 (2012).**
What they actually say: CVSS, the industry-standard vulnerability score, does two things
I copy — it builds a score from weighted parts, and it then maps the number to qualitative
bands (None / Low / Medium / High / Critical). NIST 800-61 says incidents should be
*prioritised by impact* into tiers, not handled first-come-first-served. Together they are
the precedent for scoring-then-banding for triage.
*(Note: 800-61 Rev.2 was withdrawn in April 2025 for a newer Rev.3; it was the guide in
force when this method was designed, so it is still a valid citation — just know that.)*

---

## 6. Prioritising incidents by risk

**What I did:** After scoring, incidents are ordered highest-risk first.

**Why:** So the worst thing is at the top of the operator's screen.

**Reference — NIST SP 800-30 Rev.1 (2012), the risk-assessment guide.**
What it actually says: risk is a combination of *likelihood* and *impact*, and risks
should be prioritised so responders address the most serious first. That backs ranking
incidents by score.

---

## 7. The big idea behind the whole engine

**What I did:** Collapse many raw, separate alerts into one scored incident per campaign.

**Why:** A SIEM throws out hundreds of individual alerts; an SME operator can't read them
all. Grouping them into one scored story is what makes the output usable.

**Reference — Valeur et al. (2004) and Mirheidari et al. (2018), alert-correlation research.**
What they actually say: Valeur et al. (peer-reviewed IEEE journal) show that correlating
alerts gives "a more succinct and high-level view" by *reducing and abstracting* many
alerts into fewer meaningful ones. Mirheidari et al. (a survey) note that attacks are
multi-step activities carried out over several phases, which is why reconstructing them
across phases makes sense. Together they justify the engine's core job.

---

## 8. The honest limitation (say it before they ask — it earns marks)

> "The weights — 50 for breadth, 15 per milestone, 10 for velocity — are expert-assigned,
> not learned from data. I chose that on purpose: every part has a stated reason and
> threshold, so the score can be decomposed and explained to an operator, and reproduced
> exactly. A machine-learned score might be more tuned, but it would be a black box, which
> is wrong for a tool whose output may be used as evidence."

This is already stated as a limitation in Section 4.7 of the thesis.

---

## 9. Two worked examples (memorise — they prove it's not just counting phases)

- **Recon + Delivery, over 48 hours** → breadth 20, no milestone, velocity 1 = **21 → Low.**
- **Recon + Command & Control, within 30 minutes** → breadth 20, +15 milestone, velocity 10
  = **45 → Medium.**

Both are two-phase incidents, but the second is scored higher because it reached a
dangerous stage *and* moved fast. That shows the model reacts to *depth and speed*, not
just the number of phases.
