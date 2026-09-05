# GCTU-SIEM Multi-Stage Attack Correlation Engine — Complete Technical Specification

*A self-contained reference document describing the design, algorithms, rules, formulas, data model
and evaluation methodology of the correlation engine. Written to support thesis writing.*

Source location: `src/lib/correlation/` (10 modules, 2 source adapters, 3 test suites — ~1,270 LOC
of engine code plus ~550 LOC of unit tests).

---

## 1. Research Problem and Contribution

### 1.1 The problem

A baseline SIEM built on the ELK stack (Elasticsearch, Logstash, Kibana) with Suricata as the
network IDS evaluates **detection rules against individual events**. Each rule is stateless — it
inspects one log line in isolation and has no memory of any other event.

Consequently, when an adversary executes a **multi-stage campaign** — reconnaissance scan →
payload delivery → command execution → persistence installation → command-and-control channel —
the baseline SIEM emits *hundreds of disconnected alerts*. A human analyst must manually reconstruct
the relationship between those alerts to realise they constitute **one coordinated attack**, not
hundreds of unrelated issues. This is the well-known *alert fatigue* problem, and it is acute for
Small and Medium Enterprises (SMEs) that lack a dedicated 24/7 SOC.

### 1.2 The contribution

The correlation engine is the **original contribution** of this work; the ELK stack and Suricata are
assembled, off-the-shelf infrastructure that provide collection and single-event detection only.

The engine:

1. **Normalises** heterogeneous telemetry from three sources into a single event schema.
2. **Classifies** each event into a Cyber Kill Chain phase using source-specific rules.
3. **Correlates** events by (attacker IP, victim IP) pair, normalising bidirectional traffic and
   merging IP-less endpoint telemetry into the primary campaign.
4. **Elevates** any group spanning ≥ 2 distinct kill-chain phases into a *multi-stage incident*.
5. **Scores** each incident 0–100 on a weighted breadth + milestone + velocity model, mapping to a
   four-level severity scale.
6. **Narrates** each incident in plain English so a non-expert SME operator can act on it.

Net effect: hundreds of raw alerts collapse into a handful of prioritised, self-describing incidents.

### 1.3 Kill-chain scope and justification

The engine implements **five of the seven** phases of the Lockheed Martin Cyber Kill Chain:

```
reconnaissance → delivery → exploitation → persistence → command_and_control
```

Two phases are deliberately excluded, and the exclusion is defensible in the thesis:

| Excluded phase | Justification |
|---|---|
| **Weaponization** | Occurs offline on the attacker's own machine; produces no network or endpoint telemetry that any sensor in the lab can observe. |
| **Actions on Objectives** | Detecting exfiltration/impact reliably requires Data Loss Prevention (DLP) integration, which is outside the declared scope. |

Note a naming decision: the engine uses *persistence* (MITRE ATT&CK terminology) where Lockheed
Martin says *Installation* — these are treated as synonyms and normalised to `persistence` at the
persistence layer (see §7.1).

---

## 2. System Architecture

### 2.1 Four-stage pipeline

```
   ┌─────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
   │ 1. INGEST   │ → │ 2. CLASSIFY  │ → │ 3. CORRELATE │ → │ 4. SCORE +   │
   │  (parse.ts) │   │ (classify.ts)│   │(correlate.ts)│   │  PERSIST     │
   └─────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
         ↑                   ↑                                     ↓
   EventSource        auto-detect.ts                        Supabase (Postgres)
   (File | ES)        (config inference)                  runs / events / incidents
```

### 2.2 Module inventory

| File | LOC | Responsibility |
|---|---|---|
| `types.ts` | 68 | The `NormalizedEvent`, `Incident`, `EventSource` contracts and DB row shapes |
| `config.ts` | 34 | Cached correlation config: attacker IPs, victim IPs, C2 ports |
| `phase-vocab.ts` | 48 | Canonical phase vocabulary shared by persistence and ground truth |
| `ground-truth.ts` | 186 | Declared expected campaigns: validation, loading, comparison |
| `auto-detect.ts` | 82 | Statistical inference of attacker/victim/C2 config from the data itself |
| `detect.ts` | 52 | Log-format auto-detection (Suricata EVE vs Windows Security vs PowerShell) |
| `parse.ts` | 279 | Parsers + normalisers for the three log formats; noise filtering |
| `classify.ts` | 201 | Kill-chain phase classification rules |
| `correlate.ts` | 191 | **Core algorithm**: grouping, multi-stage detection, summary generation |
| `score.ts` | 76 | Risk scoring formula and severity thresholds |
| `persist.ts` | 240 | Batched persistence, run lifecycle, canonical vocabulary normalisation |
| `run.ts` | 176 | CLI orchestration script with per-stage instrumentation |
| `sources/fileSource.ts` | 31 | `EventSource` adapter for offline log files (demo/experiment mode) |
| `sources/elasticsearchSource.ts` | 164 | `EventSource` adapter querying `filebeat-*` / `winlogbeat-*` |

### 2.3 The `EventSource` abstraction

The engine is decoupled from its data source by a one-method interface:

```ts
interface EventSource {
  getSecurityEvents(range?: { from?: string; to?: string }): Promise<NormalizedEvent[]>;
}
```

Two implementations exist:

- **`FileSource`** — parses Suricata `eve.json`, Windows Security CSV and PowerShell Operational
  CSV in parallel (`Promise.all`), concatenates and sorts by timestamp. Used for the controlled
  experiment and for user file uploads in the web UI.
- **`ElasticsearchSource`** — the *designed architecture path*. Issues two bounded queries
  (`size: 10000`) against `filebeat-*` and `winlogbeat-*`, pre-filtering server-side to only
  attack-relevant records, then maps ES `_source` documents into the identical `NormalizedEvent`
  shape.

**Thesis point:** because both adapters return the same normalised shape, the classification,
correlation and scoring logic is *provably source-independent*. The same algorithm validated on
offline forensic logs runs unmodified against a live ELK deployment. This is an internal-validity
argument worth making explicitly.

Elasticsearch server-side pre-filters:

- `filebeat-*`: `event_type ∈ {alert, http, smb, ssh, anomaly}` OR (`event_type = flow` AND
  src/dest port ∈ {4444, 5555}).
- `winlogbeat-*`: `event.code ∈ {4104, 4624, 4625, 4798}` — where 4104 (PowerShell script block
  logging) is routed to the `powershell` source and the rest to `windows_security`.

---

## 3. Stage 1 — Ingestion and Normalisation

### 3.1 The unified event schema

Every input record, regardless of origin, becomes a `NormalizedEvent`:

```ts
interface NormalizedEvent {
  source: 'suricata' | 'windows_security' | 'powershell';
  eventTime: string;        // ISO 8601 — the single join key across sources
  eventType?: string;       // Suricata: alert | http | smb | flow | anomaly | ...
  eventId?: number;         // Windows: 4624 | 4625 | 4798 | 4104
  srcIp?: string;  destIp?: string;
  srcPort?: number; destPort?: number;
  proto?: string;
  signature?: string;       // Suricata alert.signature
  category?: string;        // Suricata alert.category / Windows Task Category
  message?: string;         // Windows/PowerShell message body (truncated)
  killChainPhase?: string;  // assigned in Stage 2
  raw?: unknown;            // full original record, retained for deep inspection
}
```

The **design rationale** worth stating in the thesis: heterogeneous telemetry cannot be correlated
until it shares a vocabulary. Normalisation to a common schema — with ISO-8601 time as the universal
ordering key and IP pairs as the universal join key — is the precondition for cross-source
correlation. Retaining `raw` means no information is lost by normalisation; behavioural rules
(§4.2) reach back into `raw` for TCP state and packet counts.

### 3.2 Format auto-detection (`detect.ts`)

Given uploaded text plus filename, `detectLogTypeFromText()` returns
`suricata | windows_security | powershell | unknown`:

1. **JSON path** — if filename ends `.json` or the first non-empty line starts `{` or `[`:
   - JSON Lines: parse the first line; if it has both `event_type` and `timestamp` → Suricata EVE.
   - JSON Array: if the text chunk contains `"event_type"` and `"timestamp"` → Suricata EVE.
2. **CSV path** — if the header row contains both `date and time` and `event id` (case-insensitive),
   it is a Windows event export. Because Windows Security and PowerShell exports share an identical
   header, the discriminator is the **Source column value in the first five data rows**:
   `powershell` → PowerShell; `microsoft-windows-security` or `security` → Windows Security.
3. **Filename fallback** — if data rows are inconclusive, a filename containing `powershell` or `ps`
   → PowerShell; otherwise default to Windows Security.
4. Anything else → `unknown`.

### 3.3 Suricata EVE parsing (`parseSuricataEve`)

- **Dual format support.** The file head is inspected: a leading `[` triggers whole-file
  `JSON.parse` (array format); otherwise the file is streamed line-by-line through
  `readline.createInterface` with `crlfDelay: Infinity`. Streaming matters because production
  `eve.json` files are large; the array path is a convenience for exported/pretty-printed samples.
- **Malformed lines are skipped silently** (per-line `try/catch`) so one corrupt record cannot abort
  a run — a robustness property worth noting.
- **`stats` events are dropped** (`SKIP_EVENT_TYPES`); they are Suricata's own telemetry, not
  security events.
- **Time-range filtering** applied at parse time via lexicographic ISO-8601 comparison
  (`timestamp < range.from`), which is valid because ISO-8601 sorts lexicographically.
- **Field mapping**: `alert.signature` → `signature`, `alert.category` → `category`, plus the
  5-tuple (src/dest IP, src/dest port, proto). The entire record is kept in `raw`.

### 3.4 Noise reduction: the flow filter (`isAttackRelevantFlow`)

Flow records dominate Suricata output by volume and are overwhelmingly benign. A flow record is
**retained only if** one of these holds:

1. Source or destination port is a **known C2 port** (from config), OR
2. Source or destination port is a **known infrastructure port**:
   `INFRA_PORTS = {445 (SMB), 135 (RPC EPM), 139 (NetBIOS), 3389 (RDP), 5985/5986 (WinRM)}`, OR
3. Both endpoints are **known hosts** AND the flow exhibits a **scan signature**:
   - `tcp.state === 'syn_sent'` AND `flow.pkts_toclient === 0` (unanswered SYN — closed/filtered
     port probe), OR
   - `tcp.state === 'closed'` AND `pkts_toserver ≤ 2` AND `pkts_toclient ≤ 2` (an immediately
     torn-down connection — an open-port probe with no payload exchange).

Everything else is discarded before classification. This is a **precision-oriented design decision**:
it trades a small recall risk (a stealthy low-and-slow flow on an unmonitored port could be missed)
for a large reduction in the candidate set and in false-positive pressure downstream. The run script
reports exactly how many flows were suppressed, so the trade-off is quantifiable in the results
chapter.

### 3.5 Windows Security and PowerShell CSV parsing

Both use `csv-parse` streaming with `bom: true` (Windows Event Viewer exports carry a UTF-8 BOM),
`relax_column_count: true` and `skip_empty_lines: true`. A notable trick:

```ts
columns: (headers: string[]) => [...headers, 'Message']
```

An extra virtual `Message` column is appended because Windows exports place the free-text message
body in an unheadered trailing field.

**Timestamp handling** (`parseDDMMYYYY`): Windows exports use `dd/MM/yyyy HH:mm:ss`, which is
ambiguous with US ordering and does not sort lexicographically. The parser uses `date-fns` to parse
`dd/MM/yyyy HH:mm:ss`, falls back to `dd/MM/yyyy HH:mm`, and re-emits `yyyy-MM-dd'T'HH:mm:ss`. If
both parses fail, the raw string is passed through unchanged. This conversion is what makes
cross-source temporal ordering possible at all.

**Windows Security extraction** — three regexes mine the message body:

| Field | Pattern | Note |
|---|---|---|
| `srcIp` | `/Source Network Address:\s*([^\s\r\n]+)/` | literal `-` mapped to `undefined` |
| `accountName` | `/Account Name:\s*([^\s\r\n]+)/` | stored in `raw` |
| `processName` | `/Process Name:\s*([^\s\r\n]+)/` | stored in `raw` |

Message truncation: 500 chars for Windows Security, 1000 chars for PowerShell (script blocks are
longer and the extra length carries classification-relevant content).

---

## 4. Stage 2 — Kill-Chain Phase Classification (`classify.ts`)

`classifyPhase(event)` dispatches on `event.source`. An event that matches no rule is left
**unclassified (`undefined`)** and is *excluded from correlation entirely* — a conservative,
precision-favouring choice.

### 4.1 Configuration primitives

Four helpers underpin every rule:

- `isKnownAttacker(ip)` / `isKnownVictim(ip)` — membership in the configured lists.
- `isKnownPair(a, b)` — true if `{a,b}` is an attacker/victim pair **in either direction**. This is
  the mechanism that unifies outbound attack traffic with inbound reverse-shell callbacks.
- `isC2Port(port)` — membership in the configured C2 port set.

### 4.2 Suricata rules (`classifySuricata`), in evaluation order

**Rule 1 — C2 ports, gated on established data transfer.**
If dest or src port is a C2 port AND the endpoints are a known pair:
- If `eventType === 'flow'`: read `raw.flow.pkts_toserver + pkts_toclient`.
  **If > 4 → `command_and_control`; otherwise → `reconnaissance`.**
- Any non-flow event type on a C2 port between known hosts → `command_and_control`.

*This is one of the most defensible rules in the engine and deserves discussion in the thesis.* A
naive "traffic on port 4444 = C2" rule mislabels every SYN probe from an `nmap` sweep as an
established C2 channel, since a port scan touches 4444 like every other port. The packet-count gate
(> 4 packets ≈ beyond a bare TCP handshake, i.e. actual payload exchange) distinguishes
**probing a port** from **using a channel**, materially improving precision on the recon phase.

**Rule 2 — SMB enumeration.** `eventType === 'smb'` between a known pair → `reconnaissance`
(share/service enumeration).

**Rule 3 — Alerts.**
1. Signature substring match against `SCAN_SIGNATURES` =
   `{scan, nmap, portscan, port scan, network scan, icmpv4 unknown code, ping}` → `reconnaissance`.
2. Category substring match against `RECON_CATEGORIES` =
   `{attempted-recon, network scan, misc activity, generic protocol command decode}` →
   `reconnaissance`.
3. Any alert attacker→victim → `reconnaissance`.
4. Any alert victim→attacker **on a non-C2 port** → `reconnaissance` (the C2-port exclusion prevents
   stealing events that Rule 1 should own).

**Rule 4 — HTTP delivery.** For `eventType === 'http'`:
- Between a known pair → `delivery`.
- **Between any hosts**, if `raw.http.url` contains `.exe`, `.ps1` or `.bat` → `delivery`. This is
  the only rule that fires outside the configured host pair, on the reasoning that fetching an
  executable payload is intrinsically suspicious regardless of who does it.

**Rule 5 — Flow scan patterns.** For attacker→victim flows, using `raw.tcp.state` and
`raw.flow.pkts_*`:
- `syn_sent` with `pkts_toclient === 0` → `reconnaissance`.
- `closed` with `pkts_toserver ≤ 2` and `pkts_toclient ≤ 2` → `reconnaissance`.

**Rule 6 — Anomalies.** `eventType === 'anomaly'` between a known pair → `command_and_control`
(protocol anomalies between the compromised hosts are treated as covert-channel indicators).

### 4.3 PowerShell rules (`classifyPowerShell`)

Case-insensitive substring match on the message body. **Persistence is checked before exploitation**
— ordering is deliberate, because a persistence command is also an executed command, and the more
specific, higher-severity phase must win.

`PERSISTENCE_MARKERS` (16 markers):
`windowsupdate`, `currentversion\run`, `currentversion/run`, `schtasks`, `new-service`,
`set-itemproperty`, `startup`, `hklm\software\microsoft\windows\currentversion`, `reg add`,
`new-scheduledtask`

`EXPLOITATION_MARKERS` (grouped by intent):
- *Host/user enumeration*: `get-process`, `get-localuser`, `get-nettcpconnection`,
  `get-ciminstance`, `net user`, `net localgroup`, `whoami`, `systeminfo`, `win32_startupcommand`
- *Obfuscation / download-cradle*: `encodedcommand`, `invoke-expression`, `iex(`, `iex (`,
  `invoke-webrequest`, `downloadstring`, `downloadfile`, `bypass`
- *Known offensive tooling*: `meterpreter`, `shellcode`, `mimikatz`, `powerview`, `bloodhound`,
  `reverse`

### 4.4 Windows Security rules (`classifyWindowsSecurity`)

| Event ID | Meaning | Assigned phase | Rationale |
|---|---|---|---|
| 4624 | Successful logon | `exploitation` | Valid-accounts access achieved on the target |
| 4625 | Failed logon | `reconnaissance` | Credential probing / brute-force attempt |
| 4798 | User's local group membership enumerated | `exploitation` | Post-access privilege discovery |

All other event IDs → unclassified.

### 4.5 Batch classification

`classifyAll(events)` mutates each event in place, counts successful assignments, and logs
`"[classify] X/Y events assigned a kill-chain phase"`. **The X/Y ratio is a directly reportable
experimental metric**: it quantifies classification coverage over the captured telemetry.

---

## 5. Stage 3 — Correlation (`correlate.ts`) — the core algorithm

### 5.1 Formal statement

Let `E` be the set of normalised events and `φ(e)` the kill-chain phase of event `e`.

1. **Filter**: `E' = { e ∈ E : φ(e) ≠ ⊥ }` — retain only phase-tagged events.
2. **Direction-normalising key**: for a Suricata event with both IPs, define

   ```
   π(e) = (attacker, victim)  if {src,dest} is a configured attacker/victim pair,
                              ordered attacker→victim regardless of packet direction
        = (src, dest)         otherwise
        = ⊥                   for endpoint events with no IPs
   ```
3. **Group**: `G_k = { e ∈ E' : π(e) = k }` for each distinct key `k`.
4. **Endpoint merge**: all events with `π(e) = ⊥` are appended to the *primary group*
   `G_(attackerIps[0], victimIps[0])`.
5. **Order**: each `G_k` sorted ascending by `eventTime`.
6. **Multi-stage predicate**: `G_k` becomes an incident **iff** `|{ φ(e) : e ∈ G_k }| ≥ 2`.
7. **Score and rank**: each incident scored by §6 and the incident list sorted by descending risk.

### 5.2 Direction normalisation — why it matters

C2 traffic is **bidirectional**: the victim calls back to the attacker's listener, so the reverse
shell appears in Suricata as `victim → attacker` while the initial scan appears as
`attacker → victim`. A naive `(src, dest)` grouping key would split one campaign into **two
unrelated groups**, each possibly single-phase and therefore each *invisible* to the multi-stage
predicate. `getDirectedPair()` resolves this: when the two endpoints match the configured
attacker/victim roles in either order, the key is always emitted as attacker→victim.

For hosts outside the configured pair, direction falls back to `(srcIp, destIp)` — the engine still
groups unknown-host traffic, it simply cannot assert roles.

This behaviour is directly covered by the unit test
*"normalises bidirectional traffic into one incident"*.

### 5.3 Endpoint event merging — the cross-source join

Windows Security and PowerShell events carry **no network IP addresses**; they are host-local
telemetry. This is the fundamental obstacle to network↔endpoint correlation. The engine resolves it
with a **role-based attribution heuristic**: such events executed on the victim machine and
therefore belong to the same campaign as the network traffic targeting it, so they are merged into
the primary attacker→victim group.

This merge is what makes the *exploitation* and *persistence* phases reachable at all — those phases
are detected **exclusively** from endpoint telemetry (PowerShell markers and Windows event IDs),
while *reconnaissance*, *delivery* and *command_and_control* come from network telemetry. **The
engine therefore cannot report a full five-phase campaign without cross-source correlation working
correctly**, which is a strong argument for the necessity of the contribution and a good framing for
the results chapter.

Stated limitation for the thesis (a reviewer will ask): the merge attaches *all* IP-less endpoint
events to the *single* primary pair. In a multi-victim environment this over-attributes endpoint
activity. A production extension would key endpoint events by hostname/agent ID resolved to an IP
via asset inventory. The heuristic is sound for the single-victim controlled lab, and its
boundary should be stated as future work.

### 5.4 The ≥ 2 phase threshold

A group with only one distinct phase is **not** elevated to an incident. Rationale: a scan alone is
a routine, low-value alert that the baseline SIEM already reports adequately; the engine's value is
specifically in recognising *progression across phases*. This threshold is the operational
definition of "multi-stage" and is the single knob that controls the precision/recall balance of
incident generation. Groups suppressed by this rule are counted in the evaluation view (§8) as
`suppressed`, so the threshold's effect is measurable rather than assumed.

### 5.5 Natural-language summary generation

Phases are sorted into canonical kill-chain order:

```ts
PHASE_ORDER = [reconnaissance, delivery, exploitation, persistence, command_and_control]
```

and each is mapped to an operator-facing verb phrase:

| Phase | Verb phrase |
|---|---|
| `reconnaissance` | "scanned" |
| `delivery` | "delivered a payload to" |
| `exploitation` | "executed PowerShell enumeration/exploitation on" |
| `persistence` | "established persistence on" |
| `command_and_control` | "opened a C2 channel with" |

Composition:
- Single phase: `Host {attacker} {action} {victim}.`
- Multiple: `Host {attacker} {a₁, a₂, …}, then {aₙ} {victim} — a coordinated multi-stage attack.`

Worked example (all five phases):

> *Host 192.168.64.2 scanned, delivered a payload to, executed PowerShell
> enumeration/exploitation on, established persistence on, then opened a C2 channel with
> 192.168.64.3 — a coordinated multi-stage attack.*

**Thesis framing:** this is deterministic template-based natural-language generation, not an LLM.
That matters — the output is reproducible, auditable and free of hallucination risk, which is the
appropriate property for a security artefact presented as evidence. It directly addresses the SME
usability requirement: the operator needs no kill-chain expertise to understand the finding.

### 5.6 Instrumentation

Every run logs the funnel:

```
[correlate] {phased} phased events → {groups} groups → {incidents} multi-stage incidents
```

This three-number reduction chain is the headline quantitative result of the study.

### 5.7 Emitted incident record

```ts
interface Incident {
  attackerIp, victimIp: string;
  firstSeen, lastSeen: string;        // ISO-8601 campaign window
  phasesDetected: string[];           // sorted in kill-chain order
  phaseCount: number;
  eventCount: number;
  riskScore: number;                  // 0–100
  severity: 'low' | 'medium' | 'high' | 'critical';
  summary: string;                    // generated narrative
  events: NormalizedEvent[];          // full evidence chain, time-ordered
}
```

---

## 6. Stage 4 — Risk Scoring (`score.ts`)

### 6.1 The formula

```
risk = clamp(  (phaseCount / TOTAL_PHASES) × 50        ← BREADTH   (0–50)
             + 15 · 1[exploitation ∈ phases]           ← MILESTONE (0 or 15)
             + 15 · 1[persistence   ∈ phases]          ← MILESTONE (0 or 15)
             + 15 · 1[command_and_control ∈ phases]    ← MILESTONE (0 or 15)
             + velocityBonus,                          ← VELOCITY  (0–10)
             0, 100 )
```

with `TOTAL_PHASES = 5`, and the result rounded to the nearest integer.

### 6.2 The three components explained

**Breadth (0–50 points, 50% of the ceiling).** `phaseCount / 5 × 50` = **10 points per distinct
phase**. This measures *how far along the kill chain* the adversary progressed. It is the largest
single component because progression across phases is precisely what the engine exists to detect.

**Milestone weights (0–45 points, 3 × 15).** Not all phases are equally dangerous, so three carry an
extra flat 15:

| Phase | +15 rationale |
|---|---|
| `exploitation` | Arbitrary **code execution** has been achieved on the target |
| `persistence` | The attacker **intends to remain** across reboots — the incident is no longer transient |
| `command_and_control` | An **active remote control channel** exists — the attacker is operating live |

`reconnaissance` and `delivery` receive **no** milestone bonus: scanning is ubiquitous background
noise and delivery alone does not imply successful execution. So the model is *depth-aware*, not
merely a phase count.

**Velocity (0–10 points).** Computed from the campaign duration
`durationHours = (t_last − t_first) / 3,600,000 ms`, using the **chronologically sorted** group
(`correlate.ts` sorts before calling `scoreRisk`, so `events[0]`/`events[n−1]` are genuinely first
and last):

| Duration | Bonus | Interpretation |
|---|---|---|
| ≤ 1 hour | **10** | Automated/scripted attack; almost no human response window |
| ≤ 6 hours | **7** | Fast, actively driven campaign |
| ≤ 24 hours | **4** | Same-day campaign |
| > 24 hours | **1** | Slow/low-and-slow; more time to respond |
| fewer than 2 events | **0** | Duration undefined — guard against divide-by-nothing |

Justification: response urgency is inversely proportional to attack speed. A campaign completing all
five phases in ten minutes leaves no time for human triage and must be surfaced above an equivalent
campaign that unfolded over a week.

### 6.3 Severity mapping

| Risk score | Severity |
|---|---|
| ≥ 80 | **critical** |
| 60 – 79 | **high** |
| 40 – 59 | **medium** |
| < 40 | **low** |

### 6.4 Worked calculations

These are exactly the cases asserted in `score.test.ts` — reproduce them in the thesis as a scoring
walkthrough.

**(a) Full 5-phase campaign completed in 30 minutes — the lab scenario**
```
breadth      = 5/5 × 50 = 50
exploitation = 15
persistence  = 15
C2           = 15
velocity     = 10        (0.5 h ≤ 1 h)
raw total    = 105 → clamp(105, 0, 100) = 100  →  CRITICAL
```
The clamp is load-bearing: the un-clamped maximum is 105, so any complete fast campaign saturates
at 100. This is intentional — beyond "complete campaign, executed fast" there is no further
discrimination to make.

**(b) Reconnaissance + delivery only, spread over 48 hours**
```
breadth   = 2/5 × 50 = 20
milestones= 0
velocity  = 1            (48 h > 24 h)
total     = 21  →  LOW
```

**(c) Recon + delivery + exploitation over 10 hours**
```
breadth   = 3/5 × 50 = 30
exploitation = 15
velocity  = 4            (10 h ≤ 24 h)
total     = 49  →  MEDIUM
```

**(d) Recon + delivery + exploitation + persistence within 1 hour**
```
breadth  = 4/5 × 50 = 40 ; +15 exploitation ; +15 persistence ; +10 velocity
total    = 80  →  CRITICAL
```

**(e) Recon + C2 within 30 minutes (two phases, but a severe one)**
```
breadth = 2/5 × 50 = 20 ; +15 C2 ; +10 velocity
total   = 45  →  MEDIUM
```
Contrast (e) with (b): both are two-phase incidents, but the milestone and velocity terms separate
45 from 21. This demonstrates that the model is not a phase counter.

**Observable range.** Because an incident requires ≥ 2 phases, `breadth ≥ 20`, so the **minimum
possible incident score is 20** (21 with any velocity bonus) and the maximum is 100. No incident can
score in the 0–19 band; the `low` band is effectively 21–39. This is worth stating explicitly so the
severity distribution in the results chapter is interpreted correctly.

### 6.5 Model properties to defend in the viva

- **Monotonic in breadth**: adding a phase never lowers the score.
- **Bounded and interpretable**: every component has a stated ceiling and a security rationale; the
  score can be decomposed and explained to an operator, unlike an opaque ML score.
- **Deterministic and reproducible**: identical input always yields an identical score — a
  requirement for an evidentiary artefact.
- **Weights are expert-assigned, not learned.** State this openly as a limitation: 50/15/15/15/10
  encodes domain judgement about relative severity, and is not empirically optimised. The honest
  framing is that the weights are a *transparent, auditable prior* chosen because the study has no
  labelled corpus large enough to fit weights without overfitting; calibrating them against a
  labelled multi-campaign dataset is stated future work.

---

## 7. Persistence Layer (`persist.ts`) and Data Model

### 7.1 Canonical vocabulary normalisation

The phase table lives in `phase-vocab.ts` and is shared with the ground-truth loader, so a
declared campaign and a stored incident cannot disagree about what `installation` or `c2` means.

Before any write, phase and source strings are canonicalised so that different rule authors, source
adapters or future contributors cannot fragment the vocabulary:

```
recon | scanning | discovery                     → reconnaissance
weaponization                                    → delivery
exploit | execution                              → exploitation
installation                                     → persistence
c2 | cnc | command-and-control                   → command_and_control
```
Keys are lower-cased, trimmed, and whitespace/hyphens collapsed to underscores. An unrecognised
phase passes through in normalised form rather than being dropped.

Sources map similarly: `suricata eve` / `suricata-eve` → `suricata`; `windows security` / `winevt`
→ `windows_security`; `windows powershell` → `powershell`.

Note the mapping of `weaponization → delivery` and `installation → persistence`: this is the
Lockheed-Martin-to-ATT&CK reconciliation described in §1.3, implemented at the storage boundary.

### 7.2 Run lifecycle — experimental isolation

Every execution creates a `correlation_runs` row *before* processing, and all events and incidents
carry that `run_id` as a foreign key with `ON DELETE CASCADE`.

- `createRun()` — inserts with `status = 'running'` and records the configuration actually used
  (`attacker_ips`, `victim_ips`, `c2_ports`, `source_type`, optional `connection_id`).
- `completeRun()` — sets `status = 'completed'`, `event_count`, `incident_count`, `completed_at`,
  and two JSON aggregates: `source_counts` (events per source) and `phase_counts` (events per
  phase).
- `failRun()` — sets `status = 'failed'` with the error message, called from the orchestrator's
  `catch` block so a partial run is never silently left as "running".

**Thesis relevance:** this is the *experimental isolation* mechanism. Each run is a self-contained,
independently queryable experiment with its own configuration provenance, so results from different
datasets or parameter settings never contaminate one another and every reported figure is traceable
to the exact configuration that produced it. This is a reproducibility argument.

### 7.3 Batched writes

`BATCH_SIZE = 500`. Events are inserted in batches with `.select('id')`, and the returned IDs are
zipped back to the in-memory objects in a `Map<NormalizedEvent, string>`. That map is then used to
populate the `incident_events` junction table, also batched. A failed batch is logged and skipped
rather than aborting the run (partial-result tolerance); progress is logged every 50 batches
(25,000 events).

### 7.4 Relational schema

```sql
CREATE TYPE source_t   AS ENUM ('suricata','windows_security','powershell');
CREATE TYPE severity_t AS ENUM ('low','medium','high','critical');

correlation_runs(id PK, label, source_type, attacker_ips text[], victim_ips text[],
                 c2_ports int[], event_count, incident_count, status, error,
                 source_counts jsonb, phase_counts jsonb, ground_truth jsonb,
                 created_at, completed_at)

events(id PK, run_id FK→correlation_runs ON DELETE CASCADE, source source_t,
       event_time timestamptz, event_type, event_id, src_ip, dest_ip, src_port,
       dest_port, proto, signature, category, message, kill_chain_phase, raw jsonb)

incidents(id PK, run_id FK→correlation_runs ON DELETE CASCADE, attacker_ip, victim_ip,
          first_seen, last_seen, phases_detected text[], phase_count, risk_score,
          severity severity_t, event_count, summary, status, created_at)

incident_events(incident_id FK, event_id FK, phase, PRIMARY KEY (incident_id, event_id))
```

**Indexes** (chosen for the dashboard's actual query patterns): `events(event_time)`,
`events(kill_chain_phase)`, `events(src_ip, dest_ip)`, `events(run_id)`,
`incidents(first_seen)`, `incidents(risk_score DESC)`, `incidents(run_id)`,
`correlation_runs(created_at DESC)`.

**Design notes worth a paragraph:** `incident_events` is a many-to-many junction, not a foreign key
on `events`. This is deliberate — a single event can legitimately belong to more than one incident
(for example a scan event shared between two overlapping campaigns), and the junction preserves the
per-link `phase`. The `ON DELETE CASCADE` chain from `correlation_runs` means deleting a run cleanly
removes its entire result set. Row Level Security is enabled on all tables with read-only policies
for authenticated users; all writes go through the service-role key held server-side only.

---

## 8. Evaluation Methodology

### 8.1 Two ground-truth modes

Evaluation runs in one of two modes, and the mode is reported on the page, in the CLI output and in
the `EvaluationData.groundTruthMode` field. **The distinction is methodologically load-bearing and
must be stated wherever figures are quoted.**

| Mode | Answer key comes from | What the metrics mean |
|---|---|---|
| **Declared** | A ground-truth file written independently of any run — the operator who staged the attack, or the synthetic lab generator that constructed it | Genuine **detection accuracy** against external truth |
| **Derived** | Re-reading the events *this engine* classified and asking which pairs span ≥ 2 phases | Only **internal consistency** between classification and correlation |

Declared mode is used whenever the run has a `ground_truth` value; derived mode is the fallback, and
the UI labels itself accordingly so derived figures cannot be mistaken for detection accuracy.

### 8.2 Why derived mode is insufficient (and why declared mode fixes it)

The derived method is circular. Two distinct failure modes are invisible to it:

1. **A classification error is copied into the answer key.** If the classifier wrongly tags an event
   as `exploitation`, the derived key now contains that phase too, and the engine scores a hit for
   reproducing its own mistake.
2. **A wholly missed campaign never appears in the denominator.** If no event of a real campaign was
   classified at all, that campaign is absent from the derived key entirely. Recall is computed over
   a set that silently excludes it — so the engine can miss an entire attack and still report 100%
   recall.

Declared mode breaks the circle because the expected campaigns are fixed *before* the engine runs.
A campaign with no matching incident is now a **true false negative**, and a campaign found with
phases missing is reported as a **partial reconstruction** rather than a clean hit.

### 8.3 The ground-truth document

```json
{
  "label": "Synthetic lab",
  "campaigns": [
    {
      "attackerIp": "10.20.30.2",
      "victimIp": "10.20.40.10",
      "expectedPhases": ["reconnaissance", "delivery", "exploitation",
                         "persistence", "command_and_control"],
      "note": "Primary campaign: port sweep, .exe/.ps1 payloads, 4444 reverse shell."
    }
  ]
}
```

`parseGroundTruth()` is deliberately strict — a silently malformed answer key would corrupt every
metric derived from it, so each of these raises rather than degrading quietly: a non-object
document, a missing or empty `campaigns` array, a missing or non-IP `attackerIp`/`victimIp`, an
attacker equal to its victim, an empty `expectedPhases`, and **the same pair declared twice in
either direction** (which would otherwise double-count in both the numerator and denominator of
recall). Phase synonyms are canonicalised on load through the shared vocabulary (§7.1), so
`installation`, `C2` and `command-and-control` cannot cause a spurious mismatch.

If a stored ground truth fails validation, evaluation logs the error and falls back to derived mode
rather than reporting figures from a broken key.

### 8.4 Metrics computed

```
precision = TP / (TP + FP)          (0 when TP + FP = 0)
recall    = TP / (TP + FN)          (0 when TP + FN = 0)
F1        = 2 · (precision · recall) / (precision + recall)
reduction = round(classifiedEvents / totalIncidents)     reported as "N:1"
```

Term mapping in **declared** mode:

| Term | Definition |
|---|---|
| **TP** (`reconstructed`) | A declared campaign matched by an emitted incident (bidirectional pair match) that no analyst has marked `false_positive` |
| **FP** (`extra` + analyst-marked) | Emitted incidents matching no declared campaign, plus incidents explicitly marked `false_positive` |
| **FN** (`missed`) | Declared campaigns with no matching incident — **including campaigns whose events were never classified** |
| **partial** | Campaigns found, but with declared phases missing. Counted as TP for precision/recall, reported separately as a detection-depth measure |
| **suppressed** | Pairs with exactly one phase, correctly not elevated by the ≥ 2 rule. Neither TP nor FP |
| **unreviewed** | Emitted incidents not yet adjudicated by an analyst |

Per campaign the comparison also reports **`missingPhases`** (declared but not detected — the
classifier's blind spots) and **`unexpectedPhases`** (detected but not declared — over-
classification). These two lists are the most diagnostically useful output of the whole evaluation:
they say *which rule* is weak, not merely that a number is low.

The metrics panel still allows an analyst to **override the FP and FN counts by hand**, so expert
adjudication can supersede the automatic comparison. In declared mode the automatic FN count is
measured rather than guessed, so the override is a correction rather than the primary input.

### 8.5 The synthetic lab as a positive control

`scripts/generate-synthetic-lab.mjs` constructs a dataset **and emits its own answer key**, declared
beside the code that generates each campaign so the two cannot drift apart. It contains five
campaigns of deliberately varied depth:

| Pair | Declared phases | Purpose |
|---|---|---|
| 10.20.30.2 → 10.20.40.10 | all five | Full campaign; all endpoint telemetry merges here |
| 10.20.30.5 → 10.20.40.20 | recon, delivery, C2 | Network-only campaign on a preconfigured C2 port |
| 10.20.30.8 → 10.20.40.30 | recon, delivery, C2 | Exercises the **auto-detected** C2 port path (8888) |
| 198.51.100.44 → 10.20.40.10 | recon, delivery | Second attacker on the primary victim; below the auto-detect top-3, so it tests that the `.exe` URL rule fires for unknown hosts |
| 203.0.113.77 → 192.0.2.88 | recon, delivery | Neither host is a detected attacker or victim; tests signature-only correlation |

The measured result on this dataset is supplied separately (see §8.6). What matters structurally is
that every campaign's phase set is known in advance, so any missing or unexpected phase is
attributable to a specific classification rule rather than to an unknown dataset.

This is a **positive control**, and should be described as one: its job is to demonstrate that the
engine reconstructs campaigns whose composition is known by construction, across varied topologies
and both the configured and auto-detected C2 paths. It is not evidence about real-world traffic —
the synthetic events were written to be classifiable. The *negative* controls (a campaign missed
entirely, a campaign found with phases missing, over-classification) live in
`__tests__/ground-truth.test.ts`, where the comparison logic is verified to report each correctly.

Run it with:

```
node scripts/generate-synthetic-lab.mjs
npx tsx src/lib/correlation/run.ts --ground-truth fixtures/synthetic-lab/ground-truth.json
```

### 8.6 Results on the real lab capture

> **Figures for this section are supplied separately as dashboard screenshots.**
> Nothing in this document should be treated as the measured result — read the
> numbers off the screenshots and write them in. What follows is what to report
> and, more importantly, how to interpret it.

Ground truth is declared independently from the experiment record: one campaign,
`192.168.64.2 → 192.168.64.3`, with all five observable phases carried out.

**Report these, from the screenshots:**

| Measure | Where it comes from |
|---|---|
| Events ingested and classified | run summary / evaluation page |
| Incidents emitted | evaluation page |
| Alert reduction (`N:1`) | evaluation page, "Reduction" tile |
| Incident severity and risk score | incident list |
| Phases declared vs detected | evaluation page, campaign row |
| Missing / unexpected phases | evaluation page, "Missing" column |
| TP / FP / FN | evaluation page, "How the scores are counted" |
| Precision / Recall / F1 | evaluation page, score cards |
| Phase distribution | dashboard, "Events by phase" |
| Source distribution | dashboard, "Sources" |

#### How to interpret these figures honestly

**Do not lead with precision and recall.** With a single declared campaign the counts are one
correct decision, not a rate, and the confidence interval is enormous. Report the raw TP/FP/FN
counts and let the reader see the denominator. The single-campaign caveat in §8.7 applies in full.

**The reduction ratio needs framing.** It is real, but it is inflated by reconnaissance, which
dominates the corpus — a sustained port sweep generates enormous alert volume. The defensible claim
is the one the thesis actually needs: *an analyst facing the full raw alert volume is instead handed
a small number of prioritised incidents, each with a plain-English summary.* Report the funnel
(ingested → filtered → classified → groups → incidents), not just the quotient.

**The strongest empirical result is the rare-phase finding, and it deserves its own paragraph.**
The phases that drive severity are vanishingly rare in the data. Persistence is the rarest phase by
a wide margin, and every exploitation and persistence event originates in the endpoint telemetry
(Windows Security + PowerShell), which is a tiny fraction of the corpus beside the Suricata volume.
Those few endpoint events are what separate a `critical` incident from a routine port scan, and they
are statistically invisible next to the network events. A single-source SIEM would either drown them
or never join them to the network activity at all. This is direct empirical support for the
cross-source argument of §13.2: the engine's value is not that it processes a large number of
events, but that it finds the few that matter and binds them to the campaign they belong to.

**A zero false-positive count is a meaningful precision result** even with one positive instance,
because the engine had ample opportunity to emit spurious incidents from unrelated host pairs.
State the opportunity, not just the outcome.

**State the analysis window explicitly**, and make sure it matches the data. If a window is declared
in the methodology, the run must be scoped to it with `--from` / `--to` (§10) and the phase results
re-checked, because narrowing the window can remove whole sources and change which hosts
auto-detection identifies as attacker and victim.

### 8.7 Remaining limitations of the evaluation

- **Declared ground truth is only as good as the declaration.** It moves the answer key outside the
  engine, which removes the circularity, but the key is still authored by the researcher. For the
  synthetic lab it is exact by construction; for a live capture it reflects what the operator
  believes they staged. An independently labelled public corpus would be stronger still.
- **The synthetic lab is synthetic.** Its events were written to exercise the rules, so a perfect
  score there demonstrates correct reconstruction logic, not real-world detection rates. Report it
  as a positive control and keep it separate from results on the real capture.
- **Class imbalance on the real capture.** The lab capture contains a single staged campaign, so
  precision/recall over one positive instance carry wide confidence intervals. Report raw counts
  alongside any ratio.
- **True negatives are not reported.** The engine only emits incidents; it does not classify
  "non-attacks", so a full confusion matrix would overstate the evaluation. Precision, recall and F1
  are reported without accuracy or specificity for this reason.
- **The 15,000-event scan cap** still bounds the derived path and the per-campaign event totals on
  very large runs.

## 9. Configuration and Auto-Detection

### 9.1 Explicit configuration (`config.ts`)

Three environment variables, comma-separated, parsed once and cached:

```
KNOWN_ATTACKER_IPS=192.168.64.2
KNOWN_VICTIM_IPS=192.168.64.3
KNOWN_C2_PORTS=4444,5555
```

`setCorrelationConfig()` allows programmatic override (used by auto-detect and by tests), and
`resetConfigCache()` clears the cache — the mechanism that makes classification and correlation
deterministically testable under different configurations.

The lab topology is attacker `192.168.64.2` → victim `192.168.64.3`, with C2 on ports 4444/5555
(Metasploit's default handler port and a secondary listener).

### 9.2 Statistical auto-detection (`auto-detect.ts`)

To avoid requiring an SME operator to know their attacker's IP in advance, `autoDetectConfig()`
infers the configuration from the data:

1. **Attackers** = top 3 `src_ip` values by Suricata **alert** frequency (only events with a
   `signature` are counted, so benign flow volume cannot skew the result).
2. **Victims** = top 3 `dest_ip` values by alert frequency, **excluding** any IP already chosen as
   an attacker (prevents a host from occupying both roles).
3. **Fallback** — if no alerts exist at all, repeat the ranking over *all* events by raw src/dest
   frequency.
4. **C2 ports** = the top 5 destination ports, ranked by hit count, that satisfy **all** of:
   - `port > 1024` (above the well-known range),
   - not in
     `COMMON_PORTS = {22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 27017}`,
   - traffic flows from a detected attacker **to** a detected victim.

**Thesis significance:** this is the *zero-configuration deployment* property, and it is a direct
response to the SME constraint that motivates the whole project — SMEs have no analyst to configure
watchlists. The heuristic's assumption should be stated plainly: it assumes the noisiest alerting
source IP is the adversary, which holds in a controlled experiment and in a genuine active
intrusion, but could be inverted by an adversary who deliberately generates decoy alert volume from
a benign host. Documenting that adversarial-manipulation boundary is good thesis practice.

---

## 10. Orchestration (`run.ts`)

CLI entry point:
`npx tsx src/lib/correlation/run.ts [--label "My Run"] [--ground-truth path/to/truth.json]`
(the ground-truth path may also come from `GROUND_TRUTH_PATH`). It loads `.env.local`,
then executes and instruments the full pipeline:

1. **Ingestion** — construct `FileSource` from `EVE_JSON_PATH`, `WIN_SECURITY_CSV_PATH`,
   `PS_OPERATIONAL_CSV_PATH`; measure and print wall-clock ingestion time; print per-source event
   counts **and each source's min/max timestamp** (which documents the observation window and lets
   you verify the three sources actually overlap in time — a precondition for correlation).
2. **Auto-detection** — reset cache, infer config, print detected attackers/victims/C2 ports.
3. **Classification** — run `classifyAll`, print a per-phase breakdown sorted by frequency plus the
   unclassified count.
4. **Correlation** — run `correlate`, print the funnel.
5. **Incident report** — for each incident print attacker→victim, severity + score, the phase chain
   joined by `→`, event count, the `firstSeen → lastSeen` window and the generated summary.
6. **Ground-truth comparison** — when a ground-truth file is supplied, prints per campaign whether
   it was `FOUND`, `PARTIAL` (found with declared phases missing) or `MISSED`, with the expected and
   detected phase sets and any missing or extra phases, followed by TP/FP/FN and
   precision/recall/F1 measured against the declared campaigns. The file is loaded and validated
   *before* ingestion so a malformed key aborts in a second rather than after a long run.
7. **Persistence** — only if `SUPABASE_SERVICE_ROLE_KEY` is set; otherwise cleanly skipped with an
   explanatory message. On any exception the run is marked `failed` with the error before rethrowing.

Every number needed for the results chapter — ingestion timing, per-source counts and time ranges,
phase distribution, the reduction funnel, and per-incident scoring — is printed by a single command.
That console transcript is directly citable as an experimental artefact.

---

## 11. Verification: Unit Test Suite

`vitest`, run with `npm test`. Four suites covering classification, correlation, scoring and
ground truth.

**`classify.test.ts`** — one case per classification rule, with config pinned to the lab topology in
`beforeEach`:
- Suricata: nmap alert → recon; SYN-only flow → recon; HTTP between hosts → delivery; `.exe` URL
  from *any* host → delivery; C2 port **with data** → C2; **C2 port SYN-only probe → recon (not
  C2)**; SMB → recon; unrelated DNS → undefined.
- PowerShell: `Get-Process` → exploitation; registry Run key → persistence; `schtasks` →
  persistence; benign command → undefined.
- Windows: 4624 → exploitation; 4625 → recon; 4798 → exploitation; unrelated ID → undefined.
- `classifyAll` tags in place and leaves non-matching events undefined.
- Custom attacker/victim IPs from config are honoured (and the old IPs stop matching) — proving the
  rules are genuinely config-driven, not hard-coded.

**`correlate.test.ts`** — detects a 3-phase incident across two sources; does **not** emit an
incident for single-phase groups; ignores unclassified events; returns `[]` for empty input;
**normalises bidirectional traffic into one incident**; **merges IP-less endpoint events into the
primary group**; sorts incidents by descending risk score; generates a summary containing both IPs;
records correct `firstSeen`/`lastSeen`.

**`ground-truth.test.ts`** — validation and comparison. Rejects malformed answer keys (non-object,
empty campaigns, missing or non-IP addresses, attacker equal to victim, empty phases, and a pair
declared twice in either direction); canonicalises phase synonyms and sorts phases into kill-chain
order. The comparison cases are the **negative controls** the synthetic lab cannot provide: a
campaign that produced no incident at all is counted as a false negative (recall correctly reads
0.5, not 1.0 — the exact failure the derived method could not see); a campaign found with phases
missing is reported as partial; over-classification is reported as unexpected phases; a campaign
detected in the reverse direction still matches; and synonym-normalised detected phases compare
equal.

**`score.test.ts`** — the worked calculations of §6.4, plus: exploitation strictly increases the
score versus a non-milestone phase; faster attacks strictly outscore slower ones with identical
phases; the score is always clamped to [0, 100]; a single-event incident does not crash; each
severity threshold band is exercised.

**Thesis framing:** the test suite is the *verification* half of "verification and validation". It
demonstrates the implementation matches its specification (each rule and formula behaves exactly as
documented), while the evaluation module (§8) provides the *validation* half against real captured
attack data. The C2-probe-versus-C2-channel test is worth singling out — it is the test that pins
down the engine's most subtle precision decision.

---

## 12. Consolidated Limitations and Future Work

1. **Endpoint attribution heuristic** — IP-less Windows/PowerShell events are merged into the single
   primary attacker/victim pair; multi-victim environments need hostname→IP resolution via asset
   inventory. **This cannot be fixed from the current capture**: the Windows Event Viewer export used
   here has columns `Keywords, Date and Time, Source, Event ID, Task Category` — no `Computer`
   column — and `Workstation Name` is `-` in almost every record, so no per-host key exists in the
   data to group on. The heuristic is *correct* for this single-victim lab; the fix requires
   re-exporting the logs with the Computer field, and is stated as future work rather than a defect.
2. **Expert-assigned scoring weights** — 50/15/15/15/10 encode domain judgement, not empirical
   optimisation. Framed in §6.5 as a transparent, auditable prior rather than a flaw; calibration
   against a labelled multi-campaign corpus, and a weight sensitivity analysis, are future work.
3. **Signature/marker lists are finite** — the PowerShell exploitation and persistence markers cover
   well-known tooling; obfuscated or novel commands can evade substring matching. Adding
   entropy-based or AST-based script analysis is a natural extension.
4. **Ground truth authorship** — the circularity of the original derived method is resolved by
   declared ground truth (§8.1–8.3), and campaigns missed entirely are now counted as false
   negatives rather than being invisible. The residual limitation is that the declaration is still
   authored by the researcher; an independently labelled public corpus remains the strongest further
   improvement.
5. **Two kill-chain phases unimplemented** — weaponization (unobservable) and actions on objectives
   (needs DLP).
6. **Flow filtering may miss low-and-slow activity** on ports outside the C2/infrastructure sets.
7. **Auto-detection assumes the noisiest alert source is the adversary** — potentially manipulable
   by an attacker generating decoy alert volume from a benign host.
8. **Fixed query ceiling** — the Elasticsearch adapter caps at 10,000 hits per index per query; a
   production deployment needs pagination or a scroll/PIT search.
9. **Batch-oriented** — correlation runs over a bounded window rather than as a continuous stream;
   streaming/incremental correlation with a sliding window is a clear next step.

---

## 13. Quick Reference Tables

### 13.1 Every numeric constant in the engine

| Constant | Value | Location | Meaning |
|---|---|---|---|
| `TOTAL_PHASES` | 5 | `score.ts` | Kill-chain phases implemented |
| Breadth weight | 50 | `score.ts` | Max points from phase coverage (10/phase) |
| Milestone weight | 15 each | `score.ts` | Exploitation, persistence, C2 |
| Velocity max | 10 | `score.ts` | ≤ 1 h band |
| Velocity bands | 10 / 7 / 4 / 1 | `score.ts` | ≤1 h / ≤6 h / ≤24 h / >24 h |
| Severity thresholds | 80 / 60 / 40 | `score.ts` | critical / high / medium boundaries |
| Multi-stage threshold | ≥ 2 phases | `correlate.ts` | Incident eligibility |
| C2 packet gate | > 4 packets | `classify.ts` | Established channel vs. probe |
| Scan flow gate | `pkts ≤ 2` | `classify.ts`, `parse.ts` | Probe detection |
| `BATCH_SIZE` | 500 | `persist.ts` | Rows per insert |
| `EVENT_SCAN_CAP` | 15,000 | `evaluation/actions.ts` | Ground-truth derivation cap |
| ES query size | 10,000 | `elasticsearchSource.ts` | Hits per index per query |
| Message truncation | 500 / 1000 | `parse.ts` | Windows / PowerShell chars |
| Auto-detect top-N | 3 IPs, 5 ports | `auto-detect.ts` | Candidate list sizes |
| C2 port floor | > 1024 | `auto-detect.ts` | Above well-known range |

### 13.2 Phase → detection source matrix

| Phase | Suricata (network) | Windows Security | PowerShell |
|---|:---:|:---:|:---:|
| reconnaissance | ✅ scan sigs, SYN probes, SMB, recon categories | ✅ 4625 failed logon | — |
| delivery | ✅ HTTP between hosts, `.exe`/`.ps1`/`.bat` URLs | — | — |
| exploitation | — | ✅ 4624, 4798 | ✅ enumeration & download-cradle markers |
| persistence | — | — | ✅ Run key, `schtasks`, `new-service` |
| command_and_control | ✅ C2 ports with data, anomalies | — | — |

The empty cells are the argument for cross-source correlation: **no single source can observe more
than three of the five phases**, so a full campaign is only reconstructible by joining them.

### 13.3 Technology stack

Next.js 16.3 (App Router) · React 19.2 · TypeScript 5 · Tailwind CSS 4 · Supabase (PostgreSQL,
`@supabase/supabase-js` + `@supabase/ssr`) · `@elastic/elasticsearch` 9.5 · `csv-parse` 7 ·
`date-fns` 4 · Recharts 3 · Vitest 4 · `tsx` for CLI execution.

---

*End of specification.*
