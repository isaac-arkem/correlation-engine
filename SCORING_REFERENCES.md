# Risk-Scoring Model — Supporting References

Every component of the correlation engine's risk score (`src/lib/correlation/score.ts`)
is grounded in an established framework or industry dataset. This document maps each
design decision to its source, for citation in the thesis.

**The formula**

```
risk = breadth (0–50)  +  milestones (0–45)  +  velocity (0–10)   → clamped to 100

breadth    = (phaseCount / 5) × 50
milestones = 15·[has exploitation] + 15·[has persistence] + 15·[has C2]
velocity   = 10 (≤1h) | 7 (≤6h) | 4 (≤24h) | 1 (>24h)

severity: ≥80 critical · ≥60 high · ≥40 medium · else low
```

---

## Design decision → citation

| Design decision | Justified by |
|---|---|
| Model the attack as sequential kill-chain phases; more phases = deeper compromise (**breadth**, 50 pts) | Hutchins, Cloppert & Amin (2011) |
| Weight **exploitation / persistence / C2** as "danger achieved" milestones (+15 each) | MITRE ATT&CK — TA0002 / TA0003 / TA0011 |
| Compose severity from weighted factors, then band it (0–100 → Low…Critical) | FIRST CVSS v3.1 |
| Prioritise incidents by a combination of likelihood and impact | NIST SP 800-30 Rev.1 |
| Band incidents into severity tiers for triage | NIST SP 800-61 Rev.2 |
| Treat attack **speed** as a risk factor; sub-hour = highest urgency (**velocity**, 10 pts) | CrowdStrike 2026 GTR "breakout time"; Mandiant M-Trends 2026 "dwell time" |
| Core premise: correlate many raw alerts into one campaign, cutting false positives | Valeur et al. (2004); Alert Correlation Survey (2018) |

---

## Full references — with pinpoint locations

Each entry names the exact section/page where the supporting statement appears, so the
citation can be verified directly against the primary source.

1. **Hutchins, E. M., Cloppert, M. J., & Amin, R. M. (2011).** *Intelligence-Driven
   Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion
   Kill Chains.* Leading Issues in Information Warfare & Security Research, 1(1), 1–14.
   Lockheed Martin.
   - **p.4** — lists and defines the seven kill-chain phases (reconnaissance →
     weaponization → delivery → exploitation → installation → command and control →
     actions on objectives); the 5 implemented phases are its detectable subset.
   - **p.4** — the sentence noting it is a "chain" because any one deficiency interrupts
     the entire process: the adversary must complete every phase to succeed. → justifies
     **breadth** (more phases completed = closer to full compromise) as the largest weight.
   - **Abstract, p.1** — in this model defenders mitigate the *threat* component of risk,
     not just vulnerability. → supports scoring the campaign rather than isolated alerts.
   - PDF: https://securityandtechnology.org/wp-content/uploads/2020/07/lm-white-paper-intel-driven-defense.pdf

2. **MITRE ATT&CK — Enterprise Tactics** (definition is the one-line statement at the top
   of each tactic page).
   - **Execution (TA0002)** — adversary trying to run malicious code → *exploitation* phase.
   - **Persistence (TA0003)** — adversary trying to *maintain their foothold*; the page
     lists Boot or Logon Autostart Execution → **Registry Run Keys / Startup Folder
     (T1547.001)**, matching the captured `Startup\WindowsUpdate.exe` implant.
   - **Command and Control (TA0011)** — adversary trying to communicate with compromised
     systems to control them.
   - https://attack.mitre.org/tactics/TA0002/ · /TA0003/ · /TA0011/

3. **FIRST — Common Vulnerability Scoring System v3.1 Specification.**
   - **§1.1 / §1.2** — the Base score is derived from two sub-scores: Exploitability and
     Impact. → precedent for composing a score from weighted factors.
   - **§5, Table 14** — qualitative severity bands: None 0.0 · Low 0.1–3.9 · Medium
     4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0. → precedent for mapping a numeric score
     to Low/Medium/High/Critical.
   - **§1 (Introduction)** — CVSS outputs indicate *severity*; broader factors (e.g.
     monetary loss) are stated to be "outside the scope of CVSS." (The spec does NOT say
     "severity, not risk" in those exact words — cite as the scope exclusion in §1.)
   - https://www.first.org/cvss/v3.1/specification-document

4. **NIST SP 800-30 Rev.1 — Guide for Conducting Risk Assessments.**
   - Risk = combination of likelihood and impact, prioritised (often via a matrix) for
     response. Grounds the "score-and-prioritise incidents" premise.
   - https://csrc.nist.gov/pubs/sp/800/30/r1/final

5. **NIST SP 800-61 Rev.2 — Computer Security Incident Handling Guide.**
   - §3.2.6 (Incident Prioritization) — prioritise by functional impact, information
     impact and recoverability. → supports banding incidents into severity tiers.
   - https://csrc.nist.gov/pubs/sp/800/61/r2/final

6. **CrowdStrike 2026 Global Threat Report** (breakout time).
   - Reports average eCrime breakout time **29 minutes (2025)**, fastest observed
     **27 seconds**, down from **48 minutes (2024)**. → empirical basis that full
     attacks routinely complete in under an hour, justifying the sub-hour top velocity band.
   - https://www.crowdstrike.com/en-us/press-releases/2026-crowdstrike-global-threat-report/

7. **Mandiant M-Trends 2026** (dwell time).
   - Global median dwell time **14 days (2025)**, up from 11 days (2024) — complementary
     evidence that detection speed is a recognised, measured metric (the slower an
     intrusion is caught, the more kill-chain phases it completes).
   - https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025

8. **Valeur, F., Vigna, G., Kruegel, C., & Kemmerer, R. A. (2004).** *A Comprehensive
   Approach to Intrusion Detection Alert Correlation.* IEEE Transactions on Dependable
   and Secure Computing, 1(3), 146–169. DOI: 10.1109/TDSC.2004.21.
   - **Abstract** — defines alert correlation as providing "a more succinct and high-level
     view of occurring or attempted intrusions"; results show the components achieve
     "alert reduction and abstraction." → direct support for collapsing many raw alerts
     into one incident (the engine's core premise).
   - https://iseclab.org/publications/valeur2004a_comprehensive/

9. **Alert Correlation Algorithms: A Survey and Taxonomy (2018).** arXiv:1811.00921.
   - Notes most attacks are sequential activities carried out over many phases → supports
     multi-stage reconstruction.
   - https://arxiv.org/pdf/1811.00921

---

## Before citing

- All figures and pinpoint locations were verified against the primary sources on
  **2026-10-27**. The two vendor reports are the only ones that change: cite them by
  the exact edition named here so your numbers stay internally consistent —
  **CrowdStrike 2026 GTR (29 min / 27 s, down from 48 min in 2024)** and
  **Mandiant M-Trends 2026 (14-day median dwell, 2025)**. If a newer edition appears
  before the viva, update both figures together.
- Quote the primary sources directly in the thesis; the paraphrases here are navigation
  aids, not substitutes for the original wording.
- In defence, the velocity band is a **design choice grounded in these datasets**, not a
  claim derived from them: the sources establish that real attacks complete in minutes,
  which is why the engine treats a fast, compressed campaign as the highest-urgency band.

---

## Thesis-ready — Harvard (matches `Isaac_Kusi_finalthesis.docx`)

Your thesis uses **Harvard author–date**: in-text `(Author, Year)`, two authors
`(A & B, Year)`, three+ `(A et al., Year)`, multiple sources separated by `;`, and
org-as-author `(Elastic, 2025)`. Reference list uses `and` before the last author, `(Year).`,
`pp.` for page ranges, and `Available at: URL (Accessed: date).` for web sources.

### Already in your reference list — just cite in-text (do NOT re-add)

| Formula part | In-text citation |
|---|---|
| breadth (more phases = deeper compromise) | `(Hutchins et al., 2011)` |
| milestones (exploitation / persistence / C2) | `(MITRE, 2023)` |

### In-text citations to insert, by clause

Drop each into the sentence where that part of the score is introduced in Chapter 3/4:

- **breadth** → `(Hutchins et al., 2011)`
- **milestones** → `(MITRE, 2023)`
- **compose score from weighted factors, then band 0–100 into Low–Critical** → `(FIRST, 2019; NIST, 2012b)`
- **prioritise / score incidents (likelihood × impact)** → `(NIST, 2012a)`
- **velocity (speed as a risk factor; sub-hour = top urgency)** → `(CrowdStrike, 2026; Mandiant, 2026)`
- **core premise: collapse many raw alerts into one scored incident** → `(Valeur et al., 2004; Mirheidari et al., 2018)`

### New entries to paste into the REFERENCES list (alphabetical by surname)

```
CrowdStrike (2026) 2026 Global Threat Report. CrowdStrike, Inc. Available at: https://www.crowdstrike.com/en-us/global-threat-report/ (Accessed: 27 October 2026).

FIRST (2019) Common Vulnerability Scoring System version 3.1: Specification document. Forum of Incident Response and Security Teams. Available at: https://www.first.org/cvss/v3.1/specification-document (Accessed: 27 October 2026).

Mandiant (2026) M-Trends 2026. Mandiant (Google Cloud). Available at: https://cloud.google.com/security/resources/m-trends (Accessed: 27 October 2026).

Mirheidari, S.A., Arshad, S. and Jalili, R. (2018). Alert correlation algorithms: A survey and taxonomy, arXiv preprint arXiv:1811.00921. Available at: https://arxiv.org/abs/1811.00921 (Accessed: 27 October 2026).

NIST (2012a) Guide for Conducting Risk Assessments (NIST Special Publication 800-30 Revision 1). National Institute of Standards and Technology. Available at: https://doi.org/10.6028/NIST.SP.800-30r1 (Accessed: 27 October 2026).

NIST (2012b) Computer Security Incident Handling Guide (NIST Special Publication 800-61 Revision 2). National Institute of Standards and Technology. Available at: https://doi.org/10.6028/NIST.SP.800-61r2 (Accessed: 27 October 2026).

Valeur, F., Vigna, G., Kruegel, C. and Kemmerer, R.A. (2004). A comprehensive approach to intrusion detection alert correlation, IEEE Transactions on Dependable and Secure Computing, 1(3), pp. 146–169.
```

> **Note on NIST year-letters:** both NIST publications are dated 2012, so Harvard
> distinguishes them with `2012a` (800-30) and `2012b` (800-61). Keep the same letters
> in-text and in the list. If you already cite another NIST 2012 source elsewhere,
> renumber all NIST 2012 letters in order of first appearance.
