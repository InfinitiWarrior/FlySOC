# Issues log

Every problem hit while building FlySOC: what we saw, why it happened, how we fixed it, and where
the fix lives. Newest entries go at the end of their section. Open issues are listed first.

Each entry follows this shape:

> **Symptom**: what we observed, with numbers.
> **Cause**: why, once we knew.
> **Fix**: what changed, and where.
> **Lesson**: what to remember (optional).

Phases follow the design notes' roadmap: P0 viewer, P1 encoding, P2 learning, P3 cluster.

---

## Open

### O1. The team does not beat the single fly on everything (P3)
**Symptom**: on the final set (10 intrusions, 50 look-alikes, never used for choices), the default
rule D (the team confirms the single fly) catches 10/10 at a median +89 s, with 20/50 look-alikes
and 2/2549 false-alarm seconds. The single fly alone: 10/10, +78 s, 21/50, 2. The team costs a
little time and buys nothing measurable. (Before E9 and L7: D 16 false seconds and +137 s, single
fly 46 and +102 s; before L8, both +94 s on thresholds set too low by luck; before E10, D +360 s.)
O12 is the same weakness seen from red's side: rule D can only be as good as the single fly.
**Cause, as far as we can tell**: requiring agreement costs time. The history components (E7) helped
the single fly as much as the specialists, and one circuit has enough capacity for all four kinds.
**Next**: a coordinator that learns how much to trust each fly, per-entity learning from look-alike
labels, and real data (O4).

### O4. Mostly synthetic; real data has started (LANL)
**Symptom**: the Phase 2-4 results come from our own generators (`tools/gen_traffic.py`,
`tools/gen_intrusion.py`), so the flies may be learning quirks of the generator.
**Progress**: the public LANL enterprise data (Kent 2015, 17,684 computers, red-team labels) runs
through `tools/lanl.py` (README "Real data"). First eval results: the identity fly names the red
team's computer in both daytime incidents among 21 alarms in 4 hours; it misses the evening
campaign (O15). Weekday calibration was needed (M11).
**Limits of the data**: LANL labels only the red team's logons, so only the identity fly can be
scored; process names and most ports are anonymised, DNS has no domain names, flows end on day 15.
**Next**: O15, then report on the final slices (days 12-14). OTRF Security-Datasets would label
endpoint activity.

### O15. Low-and-slow lateral movement with stolen accounts (LANL eval_2)
**Symptom**: on eval_2 (day 8, 19:00-23:00) the red team logs on 136 times from `C17693` with 18
different accounts in 15 minutes (the next busiest computer: 6), and the identity fly never alarms.
Its 20 s average stays at a median 6.2 MBON spikes/s, max 14.7 near red-team logons, against a
threshold of 39.1 set on a busy afternoon. Raw spikes at red-team seconds reach 83, but only 8 of
136 are above the evening's own 99th percentile (32).
**Cause**: two. (1) One threshold for the whole day: the evening background is a third of the
afternoon's. (2) The auth fly's history counts only *failed* users per source (built for sprays);
this attacker succeeds, so nothing counts the accounts it uses, and one logon a minute averages
away over 20 s.
**Tried**: count every user per source, failed or not (R1). Worse everywhere. Eval_1: 0 of 21
identity episodes about the attack (was 4); eval_2 still silent; synthetic eval rule D 26/50
look-alikes alerted (was 23), E 33/50 (was 30), first alerts +88 s / +77 s (were +87 / +74). Shared
machines also reach 16 users in 15 minutes by day, and 16 and 18 share a power-of-two bucket.
Reverted; raw runs in `data/runs/r1/` and `data/runs/lanl/r1_*`.
Offline, the R1 count separates well: red-team logons have a median 6 users per source in 15
minutes on eval_2, where 0.06% of benign logons reach 6 (eval_1: 5, 1.6%). The fly cannot use it
because its readout sums every logon: one odd logon a minute among ~600 normal ones in a 20 s
average. And no threshold helps on its own: near red-team logons the 20 s average peaks at 14.7,
the evening's benign maximum is 15.1.
**Tried**: shards (`FLYSOC_SHARDS=1`, `FLYSOC_REPLICAS=10`: each role's 10 individuals smell only
sources hashing to their tenth of the network, the role reads its most alarmed individual).
- Most readout spikes wins: the busiest shard sets the bar (identity threshold 107.7). eval_1: 1 of
  14 identity episodes about the attack.
- Each shard against its own background (`relative`: 20 s average over its 30-minute average), so
  busy and quiet shards and hours share one threshold. False episodes over both slices fall from 45
  to 19, and the network fly names `C17693` from its unlabelled flows (eval_1 +3700 s, 1 episode, 0
  false); the single fly does too (eval_2 +12371 s). But the identity fly loses its eval_1 catch.
- The same with the R1 count: identical to the second within one second. The count does not reach
  the identity fly's readout at all.

| (eval slices, all flies) | eval_1 episodes: attack / false | eval_2 | first naming `C17693` |
|---|---|---|---|
| 1 fly per role | 4 / 29 | 0 / 16 | identity +38 s, +689 s (eval_1) |
| 10 shards, loudest | 1 / 25 | 0 / 7 | identity names `C1610`, not the attacker |
| 10 shards, each relative | 2 / 7 | 1 / 12 | network +3700 s (eval_1), single fly +12371 s (eval_2) |

Default behaviour is unchanged (synthetic eval reproduced exactly). Training 50 flies on a 4-hour
slice takes 449 s, calibration 614 s, a slice about 4 minutes. Raw runs: `data/runs/lanl/s*`.
**Probe done** (O16): the count did not reach the readout because the fields drowned it; the
identity fly now smells only counts and catches eval_2 at +57 s with no false episode. Open: the
fly still finds far fewer attack episodes than the plain count on the final slices.

### O5. The whole brain still ignites (P0 viewer)
**Symptom**: in the whole-brain viewer, steady input makes about 60% of Kenyon cells fire at once
every minute or so (see S8).
**Status**: detection no longer uses the whole brain (see L1, L2), so this only affects the viewer.
The proper fix would be homeostasis, or the layered rule from L2 applied brain-wide.


### O10. Red's undetected intrusions were lucky backgrounds (P4)
**Symptom**: in the first red run (8 generations of 8), 19 of 64 candidates were never caught, from
generation 0 on. Replayed into 3 fresh backgrounds, red's 3 best were caught 11 times out of 12
(mean progress 0.56-0.65 instead of 1.0).
**Cause**: every generation scored each candidate on one background. Whether rule D fires depends
on the single fly crossing its threshold, which background traffic pushes either way, so red was
selecting lucky backgrounds, not evasions (the winner's curse).
**Tried**: each candidate scored on 3 fresh backgrounds per generation, ranked by the mean
(`BACKGROUNDS` in `tools/red.py`; the single-background run is kept in `data/runs/red_1bg/`). Red
again found intrusions uncaught on all 3. Replayed into 5 backgrounds never used in evolution
(seeds 8001-8005), its 3 best reached mean progress 0.43, 0.68 and 0.68, against 0.66 for the
unchanged baseline intrusion. Changing one stage at a time: slow exfiltration 0.65, slow spray 0.42,
slow scan 0.64. Blue caught 28 of the 35.
**What it means**: with this blue, when an intrusion is caught depends more on the background
traffic than on the intrusion's pacing. Red's optimiser cannot beat that noise with 3 samples, and
no pacing change reliably evades. Blue missing 1 in 5 regardless is the real weakness.
**Update**: with thresholds calibrated on 14,000 calm seconds (L8), red's #2 and #3 (scan over
900 s, exfiltration over 1600 s) reach progress 0.94 against both blues on backgrounds 7001-7003:
caught only late in exfiltration. On the earlier thresholds they reached 0.68.
**Update 2**: on 20 fresh backgrounds (9001-9020) the picture is clear. With the 60 s history, red
progress was 0.60, 0.83, 0.83 for red's best three and 0.53 for the baseline (50 of 80 caught);
with E10, 0.58, 0.79, 0.79 and 0.33 (44 of 80). Red's slow scan is a real evasion (O12): 5 seeds
(8001-8005) had suggested E10 fixed it (0.84 → 0.52), and that too was luck.
**Update 3**: red now scores each candidate on 8 backgrounds per generation (`BACKGROUNDS`,
`PARALLEL` = 8). The noise is no longer what it finds: its winners hold up on unseen backgrounds
(O13).
**Lesson**: an optimiser finds the noise in its fitness function. Score on several draws, and
re-check winners on draws they never saw.

### O12. Low-and-slow scans evade rule D because the single fly drowns them (P4; partly fixed by leads)
**Symptom**: on 20 fresh backgrounds (seeds 9001-9020), red's #2 and #3 (37 ports over 900 s,
exfiltration over 1600 s) reach kill-chain progress 0.79: usually never caught. With the 15-minute
counts of E10, the network fly does see the slow scan: its evidence peaks at 1.5x its threshold
during recon in 12 of 12 replays (backgrounds 7001-7003, `data/runs/two/o9_peaks_new.txt`). The
single fly crosses its threshold in only 5 of 12, and rule D needs the single fly
(`docs/red_vs_blue.png`, right).
**Cause, as far as we can tell**: the single fly smells all four kinds, ~40 events a second. A
scan event every 24 s is one smell in a thousand; its evidence (a 20 s average of MBON spikes) is
dominated by the volume of everything else.
**Tried**: a specialist at $\kappa$ times its threshold standing in for the single fly
(`cluster.rs`, eval set, backgrounds 9001-9020 for red):

| rule | eval: first alert, look-alikes, false s | red progress (9001-9020) |
|---|---|---|
| D (single fly + one specialist) | +87 s, 23/50, 0 | 0.58, 0.79, 0.79, 0.33 |
| D or strong specialist alone, κ = 1.25 / 1.5 / 2 / 3 | +41 / +60 / +81 / +87 s, 35 / 33 / 25 / 23, **195 / 166 / 127 / 65** | - |
| D or strong specialist + any other fly, κ = 1.25 | +74 s, 32/50, 3 | - |
| D or strong specialist + any other fly, κ = 1.5 | +74 s, 30/50, 0 | 0.50, 0.54, 0.79, 0.27 |
| D or strong specialist + any other fly, κ = 2 | +81 s, 25/50, 0 | 0.58, 0.76, 0.79, 0.33 |

**Partial fix**: the paired rule at κ = 1.5 is rule E (`Rule::ConfirmedOrStrong`, `STRONG`). Its
extra look-alike alerts (7 of 50 on the eval set) are too many to call incidents, so it is a second
tier: `Coordinator::alert` returns an incident when D fires and a lead when only E does (JSON
`"kind"`, and the `watch` status line). Reported on data not used to choose: final set, D 10/10 at
+89 s with 20/50 look-alikes and 2 false seconds; incidents plus leads 10/10 at +60 s, all within
2 minutes, 24/50, 2. Red on backgrounds 9101-9120: progress 0.38, 0.51, 0.68, 0.36 against D's
0.38, 0.70, 0.73, 0.49; 58 of 80 alerted instead of 52.
**Still open**: red's #3 sprays only 8 accounts, too few for the identity fly, so nothing names the
scanning workstation with the network fly and it reaches 0.68. Next: a lead from one specialist
far above its threshold that stays there (sustained, not a single second), or a coordinator that
learns how much to trust each fly.


### O13. Red adapted to leads by slowing every stage at once (P4)
**Symptom**: red evolved against rule E (incidents plus leads), 6 generations of 8, 8 backgrounds
per candidate (`data/runs/red8/`, about 2 hours). Its best rose from 0.49 to 0.88. Replayed on 20
backgrounds no generation used (9101-9120, `data/runs/red8/fresh.txt`):

| genome | against D | against E |
|---|---|---|
| #1: 32 ports over 919 s, 15 accounts over 883 s, exfil over 1583 s | 0.84 | **0.84** |
| #2: 37 ports over 235 s, 15 accounts over 60 s, exfil over 1583 s | 0.82 | 0.41 |
| #3: 37 ports over 1263 s, 15 accounts over 60 s, exfil over 1583 s | 0.84 | 0.68 |
| unchanged Phase 3 intrusion | 0.49 | 0.36 |
| caught, of 80 replays | 35 | 53 |

The baseline's 0.49 against D and 0.36 against E match the earlier run on the same backgrounds
(O12), so the replays are consistent. Leads stop #2 (0.82 → 0.41) and half of #3, which spray 15
accounts in a minute and so give the identity fly a reason to name the attacker. #1 is the real
adaptation: it also spreads the spray over 15 minutes, and reaches 0.84 against both rules.
**Cause** (measured below): a lead needs a specialist at 1.5x its threshold plus a second fly
naming the same host within HORIZON_S (300 s). Slowed down, no stage pushes any fly past about
1.25x, and the stages are minutes apart. A fast spray still gives the identity fly a strong,
brief reason to name the attacker, which is why #2 and #3 are caught more often.
**Measured** (`tools/o9.py`, which now also counts seconds above threshold; red's 3 best and the
baseline on backgrounds 7001-7003, `data/runs/red8/o9.txt`): nothing stays above its threshold. The
network fly crosses it during recon in 11 of 12 replays, but for a median 5 s, at 1.25x; the
identity fly during the spray in 10 of 12, for 6 s, at 1.21x. So a "sustained specialist" lead has
nothing to sustain. Each specialist does fire in its own stage, about the attacker, minutes apart.
**Tried**: rule F, rule E or two different specialists that fired about the same entity within a
slow horizon (any strength), one of them now. Eval set:

| slow horizon | first alert | look-alikes | false alert seconds |
|---|---|---|---|
| (rule E) | +74 s | 30/50 | 0 |
| 600 s | +34 s | 40/50 | **43** |
| 1200 s | +34 s | 41/50 | **42** |
| 1800 s | +34 s | 41/50 | **44** |
| 2400 s | +34 s | 42/50 | **45** |

Rejected: specialists name the same few busy servers all the time, so two of them agreeing over
minutes is noise (`data/runs/o13/`).
**Next**: a coordinator that links an entity's stages in kill-chain order (scan, then logins from
the same source, then ...), rather than any two flies agreeing.

### O14. Every intrusion fills the queue with about 4 alerts, and the scanner adds some (P3, P4; partly fixed by cases)
**Symptom**: scored as an analyst's queue (M10), rule D raises 43 alerts on the final set: 34 about
the 10 intrusions, 5 about the authorised scanner, 4 about nothing labelled (precision 79%).
**Cause**: alerts are per entity, and an intrusion involves several: the attacker's workstation,
the target server, the sprayed user, the servers reached by lateral movement. The scanner's sweep
smells exactly like recon: E4 removed host identity from the odour on purpose.
**Tried**: familiarity, a glomerulus lit when the source had fanned out this far before, on safe
training traffic, and frozen after training like the mushroom body (`History::learned_from`).
On the eval set it made no difference (D +82 s; look-alikes alerted by entity 9/50 against 8/50),
because there the scanner caused only 1 alert. Two lessons on the way: lit on every count, the
flag made later files smell different from training everywhere (D: 19 false-alarm seconds); and
reserving 2 more glomeruli for it changed which glomeruli every field hashes into, which alone
cost D 18 false seconds (E9 again: results hang on the hashing layout). Reverted.
Also tried: a 4x longer training file (`cluster_train_long.jsonl`, 9600 s: 8 intrusions, every
look-alike 8 times, seed 51), so the flies learn what is safe from 8 examples instead of 2, with the
calibration quantile re-swept. Eval set, rule D, scored as a queue (`data/runs/long/`):

| training, quantile | first alert | queue alerts | not about an intrusion |
|---|---|---|---|
| 2400 s (current), 0.995 | +87 s | 44 | **4** |
| 9600 s, 0.995 | **+74 s** | 73 | 18 |
| 9600 s, 0.998 | +74 s | 48 | 7 |
| 9600 s, 0.999 | +82 s | 38 | 5 |

More safe training depresses more synapses, so calm output drops and the thresholds with it
(network 31 → 26, DNS 57 → 39): the flies get faster and noisier together. Re-raising the quantile
slides back along the same curve; at equal speed it is no better. Kept: 2400 s, 0.995.
**Lesson**: with this encoding, more of the same synthetic data buys speed or precision, not both.
What is left that could move the curve itself: a learned readout on the Kenyon cell code instead of
a threshold on MBON spikes, and better data (O4).
**Partial fix: cases** (`Coordinator::case`, `CASE_S`; JSON `"case"` and `"named"`). An alert
joins an open case when anything its firing flies name was named in it before. Prototyped on the
eval alerts first: linking two alerts through *any* event between their entities joined everything,
because every workstation talks to the 5 servers all the time; linking only through what the flies
named works. Forbidding servers to join a case on their own split 7 of 10 intrusions in two, so
servers do join. Window, eval set (rule D incident cases): 300 s, 18 cases, 9 of 10 intrusions split
(stages are minutes apart); **600 s**, 8 cases, 1 split, 3 holding two intrusions; 900 s, 7 cases, 1
split, 4 holding two. Reported (`tools/cases.py`, `data/runs/fp/`): final set, 43 queue alerts → 5
cases, all about intrusions, none split; holdout 2 cases, one per intrusion.
**Still open**: on the final set every case holds both of its file's intrusions (they share
servers within 10 minutes), and the 9 alerts about no intrusion are folded into those cases rather
than shown alone, so a case can hide an unrelated alert. A network with more than 5 servers would
show whether this is the synthetic network or the linking.

---

### O16. On LANL a count of the identity fly's own input beat the fly (P8, partly fixed in P9)
**Symptom**: LANL final slices (days 12-14, 6 incidents). Distinct users failing from a source in
15 minutes, thresholded like the flies: 45 alarm episodes, 33 about the attack, 12 false. The
identity fly, fed exactly that count: 41 episodes, 6 about the attack, 35 false. The other flies
add 149 false episodes and nothing else. On the eval slices the count names `C17693` at +24 s
and +246 s; the identity fly misses eval_2 entirely.
**Cause** (partly known): the count reaches the fly as 4 of 20 history glomeruli per logon, one
logon among ~29 a second, and the readout is a population rate averaged over 20 s (O15). False
alarms on the final slices also come from calibrating on one weekday afternoon (M11) and watching
mornings and other days.
**On synthetic data the reverse holds**: the single fly names all 10 final intrusions with no
false episode, and the network fly beats the port count outright (9/10 at +36 s against 0/10),
because it learned that the authorised scanner is safe.
**Probe** (P9, README "Phase 9"): the identity fly added 20-50 readout spikes per new logon whether
the source's failed-users count was 1 or 16. It smelled new names, not counts, and on 17,684
computers new names are the background (median 23 spikes/s).
**Partial fix**: the identity fly smells only its history components (`HISTORY_ONLY` in
`cluster.rs`). Background median 0 spikes/s. LANL eval: 10 episodes, all about the attack, eval_2
caught at +57 s. LANL final: 12 episodes, 5 about the attack, 7 false (the count: 45, 33, 12); both
name 2 of 6 incidents. Synthetic final: rule D unchanged; rule E +75 s, 26/50, 45 false seconds
(was +60 s, 24/50, 2); the identity fly 102 false seconds (was 0).
**Tried**: every fly on counts only. The network fly lost the scanner/attacker distinction (eval
534 false seconds, was 230; rule D 22, was 0) and LANL's dns fly raised 49 false episodes. The
endpoint fly as well as identity: synthetic false episodes 11 to 4, LANL 3 to 1, but still 2 of 10
intrusions named and rule E +80 s: not worth it.
**Why the count still wins** (P9 probe, counts-only fly): each injected logon still fires 40-100
Kenyon cell spikes, the same at count 1 and 16, and adds ~0 readout spikes. The Kenyon cells see
the counts; the output synapses learned to ignore them, because the learning rule depresses a
pattern on every harmless sighting and a big network shows even rare counts harmlessly during 4
hours of training. A count gets "rare" from a percentile; the fly has no notion of frequency.
**Tried**: two global learning-rate changes, each a separate binary (`data/runs/p9/rec_*`, `lr_*`):
faster recovery (RECOVERY 0.002 to 0.01 per window) and gentler depression (LR_SAFE 0.1 to 0.02).
Both restore a readout response (8-77 spikes per logon), but flat across counts 1-16, and a few
extreme training seconds push the threshold above 300. LANL eval: 2 attack / 2 false episodes, and
0 / 7 (default: 10 / 0). Rejected. A uniform rate cannot make the fly frequency-aware; a rule that
weighs how often each pattern was harmless can (Phase 10's sleep phase, README "Phase 10 design").
**Tried** (P9): give a history-only fly every glomerulus for its counts (26 per code instead of 10)
and each bucket its own block of 4, so a high count shares no glomerulus with the common low ones.
For the first time the readout rose with the count in the probe (+11 to +27 spikes per logon over
counts 8-15), but ordinary count-1 logons now light a big block too: background p99 4 to 49 spikes/s,
threshold 0.6 to 14.5, and the control run (count stuck at 1) swung by up to 164. LANL eval: 2
attack / 4 false episodes (default 10 / 0); synthetic eval identity 19 / 5 and 27/50 look-alikes
(was 18 / 0, 14/50); rule D unchanged. Reverted (`data/runs/p9b/`); a test now pins the overlapping
code glomerulus for glomerulus.
**Where this stands**: four attempts (global learning rates, two sleeps, a disjoint code) moved the
readout or the noise, never the precision past the default history-only fly. On LANL final it is on
par with a plain count of its input (7 false episodes against 12, 5 attack episodes against 33;
since O18's fan-out vote 6 and 4). Since O20's fine count scale 7 false and 19 attack episodes (73%, the count's precision). At the readout the trained fly passes on 1.4 times more of a red team second's drive than of
a harmless one's, against 5 times on synthetic data (O19).

### O19. Training lights every Kenyon cell: the trained-fly guarantee is nearly empty (P5)
**Symptom**: Lean's `drive_loss_le_overlap` says training can only take an odour's drive through
Kenyon cells harmless traffic lit. `flysoc cover` measured how much of the drive goes through the
other cells: a median of 0 in every fly, attack or not, on LANL and synthetic final sets. Only 1%
of LANL red team seconds have any such drive (identity fly), 8% of synthetic intrusion seconds
(identity), 55% (single fly), 89% (DNS fly). No second of 409,000 broke the theorem.
**Cause**: the guarantee is about cells *never* lit, and over a training day of 4 hours (LANL)
every Kenyon cell fires in some harmless second. The fly separates attacks by how far the weights
were depressed, which the theorem does not bound (without sleep, only $w_j > 0$).
**What it showed instead**: the trained-to-untrained drive ratio. Synthetic identity fly: 0.287 in
intrusion seconds against 0.055 in harmless ones (5x). LANL: 0.019 against 0.013 (1.4x). The
trained LANL identity fly barely passes on more of the red team's drive than of the background's,
the readout-level face of O16. The single fly on LANL passes on 0.3% of either.
**Where this stands**: open. A graded guarantee would bound the weight by how often a cell was lit
(sleep's floor $w^0_j e^{-f_j/r}$ is one, `sleep_bounded`), but sleep did not help (O17). The real
fix is upstream: odours whose Kenyon cells differ from the background's (Phase 9).
**Where**: `MushroomBody::cover` (detect.rs), `cluster::cover`, `flysoc cover`.
**Lesson**: check what a proof covers on the real data before calling it a property of the trained
system; a true theorem can be vacuous in practice.

### O20. On LANL the identity fly could not smell a handful of failed logons (P9; fine scale, partly fixed)
**Symptom**: on LANL eval (day 8, 3 red-team incidents) a plain count of distinct failed users per
source names all 3 at a median +246 s (38 episodes, 35 about the attack); the identity fly 2 at
+785 s (10 episodes, all about the attack).
**What it was not: labels or too few attacks.** Two suspects, both measured on eval and rejected:
- *The attacker's traffic was trained as safe.* LANL labels only red-team logons, so the training
  slice had 11 attack events and 6,006 flows (plus 1 failed logon) from the attacking computer
  `C17693` labelled benign. `tools/lanl.py --attacker` labels every event of a red-team source
  within 30 min of its red-team logons (5,851 in that slice). Identity fly: 10 episodes, 9 about the
  attack, 1 false, named 2 of 3 (unchanged); endpoint fly 7 false instead of 3.
- *Too few attacks to learn from.* `train_rt.jsonl`: 8 windows, about 20 hours, around every
  red-team burst on days that are neither eval nor final (1, 2, 5, 9, 15, 26, 29; windows in
  `data/telemetry/lanl/train_rt.windows`), 98 red-team logons in 11 incidents instead of 11.
  Identity fly: 14 episodes, 12 about the attack, 2 false, named 2 of 3, +781 s. With `--attacker`
  as well (10,290 labelled events): 16 episodes, 13 about, 3 false, the same naming.
**Cause**: every red-team logon on eval succeeds; the count works because the attacker also fails
logons with other accounts, which LANL does not label. A per-second trace (`FLYSOC_TRACE`) against
the attacker's 15-minute failed-user count: while it was 1-6 (80 seconds) the fly's evidence never
crossed its threshold; from 7 on (30 seconds, eval_2 only) it did in 21. In eval_1 the attacker
never passed 5. The count's own threshold is 3. The power-of-two code puts 4-7 in one bucket
sharing 3 of 4 glomeruli with 2-3, which every busy source reaches daily and training marks safe;
and the history-only identity fly used only 20 of its 53 glomeruli (the 33 field glomeruli idle).
**Fix**: default since O20 (`FLYSOC_FINE=0` turns it off), `Encoder::fine`: a history-only fly smells raw counts on a fine
scale, every count up to 12 its own bucket, then powers of two (`fine_bucket`), over all 53
glomeruli (two codes of 26). A count of 5 now shares 1 glomerulus with 2, 6 none.
`History::observe` now hands encoders raw counts; flies with fields still bucket them by powers of
two (`log_bucket`), so their odours are unchanged.
**Results**: LANL eval (chosen on): identity fly 17 episodes, 15 about the attack, 2 false, 2 of 3
named at +135 s (before 10, 10, 0, +785 s; eval_1's first incident at +24 s instead of +1513 s).
The fine scale with the 20-hour training set named all 3 but with 9 false episodes, so training
stays on the 4-hour slice. Synthetic eval: rule D unchanged, E 35/50 and 16 false seconds (before
34/50, 5), identity fly 40 false seconds (22). Final, once: LANL identity fly 26 episodes, 19 about
the attack, 7 false (before 10, 4, 6; the failed-users count 45, 33, 12); synthetic identity fly 8
false seconds (94), rules A, B, C, E 2-12 (38-81), D unchanged, queues 87% and 85% (84%, 82%).
A bug caught by the test (13 shared 12's bucket, larger counts one bucket low) was fixed and the
eval re-run before the final runs; LANL eval was identical.
**Where this stands**: the fly now matches the count's precision on LANL final and finds 19 attack
episodes to its 33; both name 2 of 6 incidents. Still missing: the evening incident of eval_1
(count at most 5, sparse) and speed on LANL final (count +4988 s, fly +5503 s).
**Where**: `fine_bucket`, `log_bucket`, `Encoder::fine`, `Encoder::neurons` (detect.rs);
`cluster::fine`; `tools/lanl.py` (`--attacker`, several windows); runs in `data/runs/o20/`.
**Lesson**: two plausible causes (labels, data volume) were cheap to test and wrong; the per-second
trace against the competing detector's own score found the real one in minutes.

### O21. On LANL the coordinator's queue was empty or useless while single flies looked good (P9, partly fixed)
**Symptom**: O20 reported the identity fly at 73% on LANL final, scored per fly. The coordinator's
JSON queue, what an analyst reads, had never been scored on LANL: 0 alerts on eval, and on final 133
alerts with 1 about the red team (1%), 1 of 6 incidents.
**Cause**: rules D and E need two flies to name an entity. This red team shows only in logons, so
only the identity fly sees it; the alerts that did pass were the endpoint and single flies agreeing
about busy computers.
**Fix**: `FLYSOC_ROSTER=identity` (`roster`, `Coordinator::solo`, cluster.rs): only listed flies
fire, and a roster of one raises leads alone, never incidents. Unset, output is byte-identical
(`cluster_final_31`). `tools/attribution.py` no longer crashes on a queue with no catch.
**Results**: eval (chosen on) 17 alerts, 15 about the attack (88%), 2 of 3 incidents. Final, once:
36 alerts, 20 about the attack (56%), 2 of 6, first at +5503 s.
**Rejected**: calibrating on 16 benign hours over four days (`calib_multi.jsonl`): on eval 12
identity episodes, 11 about the attack, +462 s (was 17, 15, +135 s), endpoint 5 false (3).
**Where this stands**: open. 4 of 6 final incidents are still unnamed and 44% of the queue is false.
The roster is chosen per data source by hand; nothing picks it automatically.
**Where**: cluster.rs; runs in `data/runs/o21/`.
**Lesson**: score the output the user actually receives. A per-component metric hid a pipeline
that produced almost nothing useful.

### O22. A longer memory of failed logons did not catch the slow LANL incident (P9, rejected, open)
**Symptom**: with the O21 roster, eval incident `intrusion@1888` is never named: 28 logons over
6004 s, the longest gap 1374 s, too slow for a 15-minute count to add up.
**Evidence for trying it**: offline, distinct failed users per source over 60 minutes, against the
highest value any source reached on `calib_wd` (6), names @1888 at +3292 s and @475 at +0 s, misses
@12982, and no benign source crosses the line. 15 minutes misses @1888. This is a plain count on
three incidents with a threshold from one calibration file, not a fly.
**Tried on eval, identity fly, queue score** (baseline: 17 alerts, 88%, 2 of 3, median +12 s):

| memory of failed users | alerts | about the attack | incidents | median first alert | fly threshold (eval_1) | false seconds (eval_1) |
|---|---|---|---|---|---|---|
| 15 min (current) | 17 | 88% | 2 of 3 | +12 s | 1.3 | 0 |
| 60 min instead | 39 | 72% | 2 of 3 | +1870 s | 2.4 | 64 |
| 15 and 60 min, three codes | 35 | 69% | 2 of 3 | +757 s | 5.0 | 79 |

Both variants name @1888 and lose @12982, which the current fly names at +24 s.
**Cause**: not established. The calibrated threshold rose with each variant, and false seconds
appeared, which fits a longer count making benign traffic look more varied to the fly. No run
isolated that.
**Fix**: none. Both variants were removed; `src/detect.rs` is back to its committed state and the
LANL `eval_1` queue is byte-identical to O21's. The final sets were not run.
**Where**: runs in `data/runs/o22/`.
**Lesson**: a count that separates cleanly offline does not necessarily help once it is an input to
the fly. Test it through the queue before believing it.

### O23. A plain 60-minute failed-logon count beside the fly passed eval and failed final (P9, rejected, open)
**Symptom**: after O22, the count was tried outside the fly: a lead whenever a new failed user took
a source above the highest count any source reached on `calib_wd` (6 users in 60 minutes).
**Results**, identity fly plus the count, queue score:

| | alerts | about the attack | false | incidents | median first alert |
|---|---|---|---|---|---|
| eval, fly alone | 17 | 15 (88%) | 2 | 2 of 3 | +12 s |
| eval, fly + count | 28 | 26 (93%) | 2 | **3 of 3** | +24 s |
| final, fly alone | 36 | 20 (56%) | 16 | 2 of 6 | +5503 s |
| final, fly + count (once) | 49 | 27 (55%) | 22 | **2 of 6** | +5147 s |

On final the count added 13 queue entries, 7 about the attack and 6 false, and named no new
incident. Its false leads include sources C6010, C1089 and C1139.
**Cause**: not established. The 3-of-3 on eval rested on one count alert for `intrusion@1888`, and
the 30- and 120-minute windows both missed that incident, so the eval gain was fragile. The final
incidents were deliberately not inspected, to keep them usable as a test.
**Fix**: none. `FLYSOC_SLOW_COUNT` was removed. Unset, it had left `eval_1` byte-identical to O21.
**Where**: runs in `data/runs/o22/slow_eval_*` and `data/runs/o23/`.
**Lesson**: three eval incidents can make a rule look perfect by one alert. Final has now been used
for O20, O21 and O23, so the LANL final numbers carry some selection across attempts; fresh red-team
days should judge the next candidate.

### O24. On fresh LANL days the identity fly names nothing (P9, open)
**Symptom**: on four days it had never been scored on (`eval_3`-`eval_6`, days 15, 20, 21, 22, the
busiest red-team 4 hours of each), the O21 setup (`FLYSOC_ROSTER=identity`, trained on day 5) queues
**12 alerts, 0 about the red team, 0 of 6 incidents**. The 56% of O21 does not generalise.
**Cause, part known**: 3 of the 6 incidents are a single logon, and in 4 of the 6 (those 3 and a
3-logon incident) every user-source pair had been seen before. A fan-out count cannot see one
logon. Why the fly also misses the two 11-logon incidents is not established. A first-seen check over all
logons since day 1 (`data/runs/o24/edges.py`, output `edges_eval.txt`) finds:

| signal, 16 h of eval | red logons flagged (of 28) | benign logons flagged | incidents touched |
|---|---|---|---|
| new source-destination pair | 5 | 2,244 | 3 of 6 |
| new user-source pair | 5 | 1,104 | 2 of 6 |
| user, source and destination pairs all new | 4 | 52 | 2 of 6 |

The strictest signal would be about 7% precise per flagged logon and still miss 4 of 6 incidents.
Those 4 have no logon with all three pairs new. History here includes the red team's own earlier
logons, as it would in a live system.
**Fix**: none yet. No code changed.
**New sets**: `eval_3`-`eval_6` for choosing. `final_4`-`final_7` (days 26-29, busiest 4 hours each)
were cut and sealed while this entry's scan ran, which stopped before day 23. O25 then used them.
**Where**: runs in `data/runs/o24/`.
**Lesson**: a slice chosen for having an attack says little about the next attack. Before quoting
accuracy on real data, test on days that played no part in any earlier decision.

### O25. A plain logon-relationship detector finds 8 of 10 incidents, at 15% precision (P9, partly fixed)
**Symptom**: O24, the identity fly names 2 of 9 dev incidents and 2 of 10 on the sealed days.
**What the literature suggested**: [Hopper](https://arxiv.org/abs/2105.13442) (Ho et al., USENIX
Security 2021) detects lateral movement from credential switches. A
[re-evaluation of graph detectors](https://arxiv.org/abs/2607.29390) reports about 0.98 AUC and 0.02
average precision for Euler on LANL, so everything here is judged by queue precision, never AUC.
**Tried on dev** (days 8, 15, 20, 21, 22; 9 incidents): credential switching alone found **0 of 9**
and was dropped. New-relationship bursts found 4 of 9, failed users 4 of 9. Requiring two signals on
one source within an hour gave 4 alerts, 1 false.
**Method**: `tools/lanl_relations.py`, no fly involved. Per source over one hour: logons with all
three pairs new, failed users, new destinations. Two above their lines put the source on a watchlist
until an analyst clears it, and each later successful logon from it is a lead.
**The leak, caught before reporting**: lines first came from days 16-19, later than the day 8 alert
that fills the watchlist. That gave 75% on the sealed days (4 alerts, 1 false, 8 of 10). A live
system cannot know those lines. With lines from red-free days 3-4 (1, 2, 10 instead of 1, 5, 12),
five busy computers outside the red-team labels join the watchlist and stay:

| one queue entry per entity-hour | alerts | about the attack | false | precision | incidents |
|---|---|---|---|---|---|
| dev, identity fly | 12 | 1 | 11 | 8% | 2 of 9 |
| dev, relations | 31 | 4 | 27 | 13% | 7 of 9 |
| **sealed days 26-29, identity fly** | 19 | 2 | 17 | 11% | **2 of 10** |
| **sealed days 26-29, relations** | 20 | 3 | 17 | **15%** | **8 of 10** |

**Where this stands**: recall improved four-fold at the same number of false alerts. Precision is
still low. On the sealed days every alert comes from the watchlist: all 8 caught incidents involve
C17693, listed on day 8, and the 2 missed are C19932 alone. The result therefore rests on the red
team reusing one computer. A red team that changes machines would not be caught this way.
The sealed days were run twice, once with the leaking lines and once with the fixed ones. The
change was made because of the leak and lowered the score. They are no longer unseen.
**Where**: `tools/lanl_relations.py` (`check` self-test); runs in `data/runs/o25/`. Not in the Rust
engine or the flies.
**Lesson**: check where every threshold came from in time. A threshold from the future turned 15%
into 75%.
**Update**: O26 removes these false listings without using future data.

### O26. Warm-up listings caused the false alerts; the detector now lists one machine in 58 days (P9, partly fixed)
**Symptom**: O25's watchlist held five computers outside the red-team labels, and they stayed listed.
**Cause**: the detector was armed from day 0. With almost no history every logon looks new, so busy
computers were listed in the first days, before the lines' own calibration days had even passed.
**Fix** (`tools/lanl_relations.py`): no alert or listing before day 5 (`ARMED_S`), and a signal counts
only above both its line and that source's own highest count so far (`peak`). On days 8, 15, 20-22 arming
alone left 11 false alerts, the baseline alone 18, both together 2.
**Rejected on days 8, 15, 20-22**: watchlist expiry, tested before arming: 1 or 3 days lost incidents (5 of 9), 7 days kept 7 of 9 with 23 false.
Keeping the busiest 1% or 5% of sources off the list changed nothing once the detector was armed.

| one queue entry per entity-hour | detector | alerts | about the attack | false | precision | incidents |
|---|---|---|---|---|---|---|
| days 8, 15, 20-22 (rules chosen here) | identity fly | 12 | 1 | 11 | 8% | 2 of 9 |
| | relations | 6 | 4 | 2 | 67% | 7 of 9 |
| days 12-14 (never scored for this detector) | identity fly | 13 | 2 | 11 | 15% | 2 of 6 |
| | relations | 4 | 4 | 0 | 100% | 6 of 6 |
| days 26-29 (third use) | identity fly | 19 | 2 | 17 | 11% | 2 of 10 |
| | relations | 4 | 3 | 1 | 75% | 8 of 10 |

**Whole dataset, 58 days, 101.7 million remote human logons** (`data/runs/o26/full.txt`): exactly one
computer is ever listed, C17693, on day 8.415. No computer is listed in the 28 days after the last
red-team logon (day 29.6), which no earlier step had read. Of its 812 watchlist leads, 611 are
labelled red-team logons (75%). 629 of the 715 distinct labelled logons come after the listing (88%).
**What these numbers do not show**:
- **One detection.** Every alert in the table names C17693, so the 21 caught incidents are one
  discovery followed over time, not 21 independent catches.
- **1 of 4 red-team sources.** C19932, C22409 and C18025 (32 distinct labelled logons) are never found.
- **Late.** The first red logon from C17693 is on day 1.75, before the detector is armed. It is
  listed 6.7 days after that.
- **Chosen with this machine in view.** Arming and the baseline were picked on days that include its
  listing, so its discovery is not independent evidence. The clean 28 days are.
- The "false" queue entries are hours on C17693 with no labelled logon nearby. LANL labels only
  logons, so some may be the attacker's own activity; they are counted as false.
**Where**: `tools/lanl_relations.py`; runs in `data/runs/o26/`. Also `flysoc relations` (`src/relations.rs`),
same alerts on every scored slice.
**Lesson**: when a result looks perfect, count independent events. Here 100% was one machine.

### O27. Following accounts from the listed machine does not find the other three (P9, rejected)
**Symptom**: O26 finds C17693 but not C19932, C22409 or C18025. All three share an account with
C17693 at some point, so following its accounts to other machines looked like a way to find them.
**Test** (`data/runs/o27/pivot.py`, all 58 days): flag each account-machine pair first seen within a
window around the time the account is tied to C17693 (the listing, or its first later logon there).
There are 4 red account-machine pairs on those three sources. One, U3486 on C22409, never has a
successful logon, so at most 3 can be found.

| rule | accounts followed | pairs flagged | machines | red pairs found |
|---|---|---|---|---|
| 7 days back and forward | 117 | 3,278 | 3,108 | 3 of 4 |
| 3 days back and forward | 117 | 2,212 | 2,174 | 1 of 4 |
| 7 days, accounts on at most 50 machines | 116 | 581 | 490 | 2 of 4 |
| 7 days, accounts on at most 20 machines | 108 | 422 | 371 | 1 of 4 |

**Cause**: accounts on C17693 are ordinary roaming accounts. U1653 alone reaches 3,382 machines, and
U737 and U748 reach 47 and 65, so a new machine for one of them is normal. Best precision is 2 of 581
pairs (0.3%). The account cap was also read with the labels in view, so even that is optimistic.
**Fix**: none. Not added to `tools/lanl_relations.py`.
**Measurement trap**: counted per machine, a first run showed C18025 found in windows that cannot
reach its red logon (day 2.43), because a different, innocent account was new there. Count the exact
labelled pair.
**Lesson**: a shared account links machines but does not implicate them. Account overlap can help an
analyst look around a confirmed machine, but it is not an alert.

## Solved: measurement and alerts (since Phase 8)

### O29. The neurons the MBONs feed latch or time out; they do not integrate (P9, open)
**Symptom**: Phase 9 asks to replace the hand-written 20 s evidence average (`cluster.rs`
`evidence`, `EVIDENCE_S`) with a circuit from the connectome. 20 s of telemetry is 1 s of fly time,
so that circuit must hold activity for about a second, in proportion to how much input it got.
**Probe** (`cargo test --release memory -- --ignored --nocapture`, `src/main.rs` `downstream_memory`;
output in `data/runs/o29/memory.txt`): the 96 MBONs plus every neuron with at least 20 (1,118
neurons) or 5 (2,510) excitatory synapses from them, all their connections kept, loops included.
The MBONs are driven for 100 ms, then silent. Downstream spikes per 50 ms after the input stops:

| adaptation (mV per spike) | MBONs at 5 Hz | MBONs at 100 Hz |
|---|---|---|
| 0 | about 1,500 per bin, forever | the same |
| 0.5 | about 1,000 per bin for 350 ms, then 0 | the same, 400 ms |
| 1 | 250 ms, then 0 | 200 ms |
| 2 to 10 (the brain's) | under 100 ms | under 100 ms |

**Cause**: the downstream wiring is dense enough to run on its own once kicked, and with this point
neuron model the run is all or nothing. Without adaptation a single weak kick latches it for good.
Adaptation turns that into a timer whose length is set by the adaptation, not by the input: 5 Hz and
100 Hz give the same burst. Of the 300 most MBON-excited neurons, mostly unannotated SMP, SIP and
CRE types, the median gets 11% of its excitatory input from the others, and they inhibit each other
more than they excite. Nothing there sums inputs gradually.
**Fix**: none. The 20 s average stays, documented as a departure (README "Model").
**What could still work**: memory that lives in synapses rather than spikes, such as the MBON-DAN
feedback loops (10 of the 300 neurons the MBONs excite most are DANs), which act through
plasticity. That needs a model of dopamine release, which this simulation leaves out (`detect.rs`
`NOT_SIMULATED`).
**Lesson**: check a circuit's input-output curve before wiring it in. Activity that lasts is not
memory unless it grows with the input.

### O30. Analyst marks cut false alarms, and a mark on a benign machine blinded the fly to the attacker (P10, open)
**What was built** (`FLYSOC_MARKS=<n>`, `cluster.rs` `play_marked`, `detect.rs` `play_marked`): a
simulated analyst reviews new queue entries as they are raised, up to n per run and each machine
once. An entry is real if an event involving the machine in the last 60 s is labelled red team,
else a false alarm. A false alarm is the dopamine signal of training (`MushroomBody::learn`, safe)
for the flies that fired, on that second's Kenyon cells, and they play on with the new weights.
Test: `a_mark_teaches_only_the_marked_fly` (no marks equals plain play; a mark changes only the
marked fly, and quiets it). Off by default; with 0 marks every slice reproduces O24's numbers.
**Chosen on the dev slices** (days 8, 15, 20-22, `FLYSOC_ROSTER=identity`, 10 marks per 4-hour
slice, `data/runs/p10/`). Every variant gave the same queue: 12 entries with 11 false became 9 with
8, still 2 of 9 incidents. They differed in side effects:

| variant | side effect on dev |
|---|---|
| every mark teaches; a real mark restores weights (the training rule) | alarm seconds about benign C1611 rose from 10 to 268: restoring weights made the fly louder for everything sharing those Kenyon cells |
| a false verdict sticks: every later alarm on that machine teaches "safe" | C17693 was marked false in an hour with no labelled logon nearby (LANL labels only logons); its red-labelled alarm seconds fell from 33 to 13 |
| **each machine once, only false alarms teach** (kept) | the same wrong mark cost 33 to 31 |

**Reported once** (10 marks per slice, one queue entry per entity-hour, `tools/lanl_relations.py` scoring):

| slices | marks used | queue | false | precision | incidents |
|---|---|---|---|---|---|
| days 12-14, no marks | 0 | 13 | 11 | 15% | 2 of 6 |
| days 12-14, marks | 12 (2 real) | 12 | 10 | 17% | 2 of 6 |
| days 26-29, no marks | 0 | 19 | 17 | 11% | 2 of 10 |
| days 26-29, marks | 14 (0 real) | 14 | 13 | 7% | **1 of 10** |

Alarm volume falls where marks land: on day 29, 4 marks took the alarm seconds from 283 to 70.
**Symptom**: on day 26 (`final_4`) the analyst marked two benign machines, C5808 and C5787, and the
fly then missed its only catch, C17693 at 1.0-1.2x its threshold about 3 hours later. Phase 10's
done-when asks that a mark on one benign source not blind the fly to an attack from another: this
fails.
**Cause**: the identity fly smells only counts, not names (Phase 9, O16). "This was safe on C5787"
is learned as "this count pattern is safe", for every machine. A marginal catch drops under.
Also, one of the 14 marks on days 26-29 called C17693 a false alarm (`final_5`), because no
labelled logon fell in the minute before. A real analyst would know better; the simulation cannot.
**Fix**: none yet. Marks stay off by default.
**Next**: let a mark teach only what was specific to the marked machine, for example a fly that
smells the source's name beside the counts, so "safe" can attach to one machine; or apply marks
as a per-machine allowance in the coordinator instead of in the fly's weights.
**Lesson**: learning from a mark generalises exactly as far as the odour does. A fly that cannot
tell machines apart cannot be told that one machine is fine.

### O18. Flies voted on alarms with nothing behind them (P11)
**Symptom**: on LANL, the DNS fly raised 25 alarm episodes on the eval slices and 72 on the final
ones, none about the attack. Phase 11's explanations said why for every one: *no fan-out behind
C1936 (count 1): the fly reacted to the event itself*. LANL's DNS records name computers, not
domains, so names-per-domain is always 1 and the fly reacts to unfamiliar computer pairs.
**Cause**: a fly fired whenever its evidence passed its threshold, whatever drove it. On a big
network novelty alone keeps a fly near threshold.
**Fix**: the coordinator counts a fly as firing only if the count behind its suspects is at least
2 (`fan_out` in `cluster.rs`, `Coordinator::second`'s `fan`); the evidence keeps accumulating, so
the fly fires at once when fan-out appears. Chosen on eval: no attack episode lost on either eval
set, the 25 DNS episodes gone, rules D and E unchanged to the second. Reported on the final sets:
LANL false episodes 156 to 82 (DNS 72 to 0; identity 12/5/7 to 10/4/6 episodes/attack/false);
synthetic final rule D and E unchanged, queue precision D 75% to 84%, E 75% to 82%; holdout
unchanged. Raw runs: `data/runs/p11g/`, `p11f/`.
**Lesson**: an explanation is also a measurement. Reading why each false alarm fired found a
rule in one pass that four rounds of tuning the circuit had not.

### M12. Explanations named a cause the fly had not been asked about (P11)
**Symptom**: Phase 11's sentences ("9 distinct users failed to log in from C17693") read as the
fly's reason, but they come from FlySOC's history bookkeeping: the most extreme count among the
fly's recent events. Phase 9's probe had shown a fly can fire for something else (names) while the
count beside it is high.
**Fix**: say so (README "Who says what"), and ask the fly: `FLYSOC_VERIFY=1` replays the 120 s
before an alarm with and without the suspect's events (history primed with the 15 minutes before)
and reports whether the fly still fires (`cluster::verify`). Final sets: the identity fly is
confirmed in 25 of 27 synthetic episodes and 7 of 10 on LANL; the endpoint fly in 11 of 18 and 24
of 44.
**Tried**: demoting unconfirmed cluster alerts. Unconfirmed per-fly episodes are mostly false
(synthetic eval 8 of 9, final 13 of 17), but in the queue the 4 demoted rule D entries were all
about intrusions (93% to 92%): corroboration already fixes the entity. Not adopted.
**Lesson**: a confirmation tests the cause, not the intent. On LANL 50 of 52 confirmed episodes
are false: the fly really did fire because a server started 109 processes; that server is busy,
not compromised.

## Solved: simulation and GPU

### S1. Pull-based simulation was too slow (P0)
**Symptom**: 1 s of fly time took 18 s: 0.06x real time on an RTX 4090.
**Cause**: every neuron read every one of its incoming synapses every 0.1 ms step, which is 15M
random reads per step. But only about 176 of 138,639 neurons spike per step.
**Fix**: event-driven push (`src/sim.wgsl`). Neurons that spike append themselves to a list, and an
indirect dispatch (one workgroup per spike) pushes their outgoing weights into a delay ring. This
gave 5.5x real time, and 9x after adaptation lowered background activity. Spike counts matched the
old version to within 0.01%, which is how we knew the rewrite was correct.
**Lesson**: spiking networks are sparse in time. Do work per spike, not per synapse.

### S2. WGSL has no float atomics (P0)
**Symptom**: the push design needs many threads adding into the same neuron's input at once.
**Fix**: weights are signed synapse counts, which are integers, so the ring uses `atomic<i32>`.
Later the ring counts 1/16 synapses (`FIX`), so learned float weights still fit (see L4, L5).

### S3. wgpu 30 and glam 0.34 API changes (P0)
**Symptom**: code written from memory of older versions did not compile.
**Fix**:
- Camera functions moved from `Mat4::perspective_rh` / `look_at_rh` to
  `glam::camera::rh::{proj::directx::perspective, view::look_at_mat4}`.
- `RequestAdapterOptions` needs `apply_limit_buckets`.
- Frames are presented with `queue.present(frame)`.
- `get_default_config` takes the adapter.
- Surfaces need the display handle passed into the `Instance`.

We checked each against Crowmation and the crate sources in `~/.cargo/registry`.
**Lesson**: read the installed crate's source instead of trusting memory.

### S4. WGSL details (P0, P2)
**Symptom and fix**:
- Indexing a `let` or `const` array with a runtime index is rejected. Copy it into a `var` first
  (`src/view.wgsl`).
- Auto-generated pipeline layouts only contain the bindings an entry point uses. Each entry point
  (`step`, `deliver`, `tick`) therefore gets its own bind group (`Sim::new`).
- Storage bindings may not be empty. The plastic synapse buffers get one padding element when a
  fly has no plastic synapses (the viewer and bench).

### S5. Zeroed buffers, but zero was not silence (memory work)
**Symptom**: GPU buffers can be created already zeroed for free, but a zeroed membrane potential
meant 0 mV, far above the -45 mV threshold.
**Fix**: store potentials relative to rest (-52 mV), so a zero is a silent neuron (`VRESET = 0`,
`VTH = 7`). `reset` clears buffers on the GPU instead of uploading zeros from host memory.

### S6. Memory use (P0 to P3)
**Symptom**: 534 MiB of GPU memory and a 607 MiB peak in host RAM for one brain.
**Causes and fixes**:
- Connections were stored as a 32-bit target plus a 32-bit weight. Neuron IDs fit in 18 bits and
  the largest weight is 2,405 synapses, so both now share one 32-bit word (`tools/convert.py`,
  `deliver` in `sim.wgsl`). Connections went from 121 MB to 60 MB, and `fly.bin` from 125 MB to 64 MB.
- The delay ring had 32 slots. A 1.8 ms delay needs only DELAY + 1 = 19.
- Loading kept three copies of the file in RAM. It now reads each section straight into its own
  vector, and the connections are dropped once they are on the GPU (`Fly::load`, `Sim::new`).
- All-zero buffers were uploaded from host memory. They are now created zeroed on the GPU.
- wgpu enabled every backend, which loaded OpenGL, EGL and Mesa (with LLVM) into the process. It is
  now restricted to primary backends (`sim::instance`). `WGPU_BACKEND` still overrides.

**Result**: whole-brain data went from about 145 MB to about 78 MB. The detection circuit is about
3 MB per fly (see S10 for why each cluster fly is a full copy).
**Not fixable from our code**: the ~207 MiB per process on the GPU is mostly NVIDIA's Vulkan context,
paid once per process. Host RSS also counts shared driver libraries, so read
`Private_Dirty` / `Pss_Anon` in `/proc/<pid>/smaps_rollup`, not RSS.
**Known leftover**: host RAM does not drop after the full connectome is pruned to the circuit,
because the allocator keeps freed memory. Saving the pruned circuit to its own file would fix it.

### S7. The whole brain locks into endless firing (P1)
**Symptom**: about 2 s of sparse input pushed the brain to about 74,000 spikes per 50 ms window, and it
kept firing at that rate for 15+ s after the input stopped. The readout was saturated and identical
for scans, bursts and idle traffic.
**Cause**: about 9,000 central brain neurons excite each other, and 654 of them fire near their maximum
rate. The Shiu et al. model was validated on brief stimulation of a few neurons, where this never
shows up.
**Fix**: spike-frequency adaptation (+10 mV per spike, 1 s decay), a parameter of `Sim::new`. The
whole brain uses `BRAIN_ADAPT`, and the circuits use 0. This is a documented departure from Shiu et al.

### S8. Adaptation turned the brain into an oscillator (P1)
**Symptom**: with adaptation, plain benign traffic still triggered "ignitions" every 20 to 90 s (the
interval depended on the setting). Thousands of Kenyon cells fired at once, the same size as the
response to a scan.
**Cause**: adaptation builds up and wears off, so steady input slowly recharges the brain until it
fires all at once.
**Fix**: we tried several settings, and none removed it. Solved for detection by not using the whole
brain (L1, L2). Still present in the viewer (O5).

### S9. A WGSL uniform larger than its buffer (P3 viewer)
**Symptom**: the viewer's camera uniform gained two `u32` fields (neurons per fly, alarm bits), padded
with `_pad: vec3<u32>` to make 96 bytes.
**Cause**: a `vec3` member is 16-byte aligned, so the struct became 112 bytes, larger than the 96-byte
buffer. We caught it while reviewing the struct, before running.
**Fix**: pad with three scalar `u32`s (`src/view.wgsl`).
**Lesson**: in WGSL uniforms, vec3 behaves like vec4 for alignment; pad with scalars.

### S10. Cluster flies ran one after another (P3)
**Symptom**: a `cluster` run took about 4 minutes. The 5 flies shared one circuit on the GPU and each
played the telemetry in turn, with its weights swapped in.
**Cause**: the simulation is bound by dispatches (3 per 0.1 ms step), not by neuron count, so 5 runs
cost 5x.
**Fix**: one simulation holding 5 disjoint copies of the circuit (`Synapses::replicate`,
`Plastic::replicate`). The shared `Player` (`src/detect.rs`) feeds each fly's events into its own
copy, and every fly learns only from its own labels (`MushroomBody::of_fly`). A run now takes 56 s,
with identical held-out results. Cost: each fly is a full copy (about 3 MB of GPU memory, not
250 KB), and 18-bit neuron ids limited one simulation to 28 circuit flies (raised to 56 in S16).
**Bonus**: this made the live cluster viewer (`watch`) possible, since all flies advance together.

### S11. Driving the viewer step by step (P3 viewer)
**Symptom**: playback was a single function that ran to the end, and the viewer needs one frame at
a time.
**Fix**: the `Player` advances one 1 ms bin per call and reports when a telemetry second ends, and
the `Coordinator` takes one second at a time. `detect`, `cluster` and `watch` all use them, so the
viewer shows exactly what the batch commands compute. The viewer is now generic over a `Driver`:
the whole brain (`view::Brain`) or the cluster (`cluster::Watch`).
**Shortcut**: `Watch` leaks the telemetry and the trained cluster (`Box::leak`) so the `Player` can
borrow them for the life of the window. That is fine for a process that exits when the window
closes.

### S12. Every launch retrained the cluster (P3, was open issue O6)
**Symptom**: `watch` showed a blank window for about 40 s on every launch, and `cluster` spent the
same time before playing anything. Every run retrained all five flies from scratch.
**Cause**: training plays the 2400 s training file twice: once learning (19.5 s), once replaying
without learning to calibrate thresholds (16.9 s).
**Fix**: the trained weights and thresholds are cached in `data/cache/cluster-<key>.bin` (now `cluster<k>-<key>.bin`, S17; 1.2 MB,
`cluster::build`). The key hashes the training file and the FlySOC binary, so new training data or
any rebuild retrains, and every other launch loads instantly. Results are identical with and
without the cache. Startup now prints how long each step takes, and `watch` prints how long each
playback loop took.
**Leftover**: `detect --train` (one fly, a few seconds) is not cached.

### S13. The cluster flies looked like blobs (P3 viewer)
**Symptom**: in `watch`, each fly was just its 9,262-neuron circuit: two antennal lobes, two
mushroom body cups and the lateral horns. Floating alone, the round clumps did not read as brains, and the
whole-brain viewer looked far more detailed.
**Fix**: each fly is drawn inside its whole brain: all 138,639 neurons as a dim outline coloured by
super class (optic lobes blue, central brain orange and so on), with the simulated circuit lit in its
real position. Context points are marked `GHOST | fly` in the scene's index buffer, never flash, and
turn red with their fly's alarm (`src/view.wgsl`). That is about 740,000 points per frame, which
the GPU draws easily.

### S14. Checking what the viewer looks like without a window (P3 viewer)
**Symptom**: there was no way to check the viewer's look without opening a window, and desktop
screenshots capture far more than the FlySOC window.
**Fix**: `snapshot` renders the `watch` view at a chosen telemetry second into an offscreen texture
and writes a PPM image (`view::snapshot`). The drawing code moved into a `Renderer` that draws into
either the window or the offscreen texture, so the image matches the live view. PPM avoids a PNG
dependency; convert it with any image tool.
**Found with it, right away**:
- At the first brightness, the whole-brain outlines were nearly invisible (optic lobes barely
  showed). Context points are now at 0.03 glow instead of 0.012.
- A row of four brains is too wide for 16:9. The outer brains were cut off, or everything was tiny
  when zoomed out. The layout is now the team as a 2x2 grid on the left and the single fly on the
  right.

### M8. Unrelated look-alikes made the cluster quorum (P3)
**Symptom**: with history components, the cluster alerted on 9/10 look-alikes on the test file
(the single fly on 6/10).
**Cause**: the coordinator only asked "did 2 specialists fire within 300 s?". The test file's
look-alikes come about 70 s apart, so two flies firing on two unrelated benign oddities made the
quorum.
**Fix**: entity correlation (`cluster::Coordinator`). Each fly names suspects: the entities behind
its most extreme history count among its events of the last 20 s (`Player::suspects`), and the
quorum must agree about the same entity. Look-alike alerts went 9/10 → 3/10 on test and 6/10 → 2/10
on the holdout, and incidents now say which host or user they are about. Both holdout incidents
named the right one.

### S15. Making the cluster faster (P3)
**Symptom**: a cluster run took about 55 s: training 20 s, calibration 18 s, playback 17 s.
**Measured, not guessed**: `perf` had no access to hardware events, so we timed the three
phases with temporary instrumentation (removed afterwards). Playback of 2417 s: turning events into
input 0.8 s (CPU), recording GPU commands 6.0 s (CPU, the same with no events), waiting for the GPU
10.7 s (3.3 s with no events). The GPU is the bottleneck: about 14 µs per 0.1 ms step for 5 flies,
mostly launch latency of 3 dependent dispatches per step.
**What we did**:
- Input was uploaded as a full array (185 KB for 5 flies) for every 1 ms bin with an event, with
  one submit per bin. It is now a list of the neurons to fire, applied on the GPU by `inject`, sent in
  batches of 5 bins. A first version batched a whole second per submit and was *slower* (71 s vs
  55 s): it removed the overlap between the CPU recording one bin and the GPU running the previous one.
- The `tick` dispatch is gone (3 → 2 dispatches per step). Workgroup 0 of `deliver` advances the clock
  and resets the next step's spike counter. Two counters alternate, because the current one is
  `deliver`'s indirect argument. The other workgroups take the step's time from the spiking
  neuron's `last` instead of the clock, which may already have moved on.

**Result**: cached playback 18.1 → 16.1 s, a full run about 55 → 52 s, the whole-brain bench 9.2x →
9.6x real time. Scorecards and the whole-brain spike count (66,129) are identical.
**Not done**: going further needs fewer steps (a larger time step changes the model) or fewer
dependent dispatches, which wgpu cannot do without global barriers.
**Lesson**: we assumed the input upload was the cost, and it was not. Measure the phases first.

### S16. Only 28 flies fit in one simulation (P3 ensemble)
**Symptom**: `FLYSOC_REPLICAS=6` (30 flies) panicked at once with "packed post ids have 18 bits".
**Cause**: each synapse is one u32: target neuron in the low 18 bits, signed count in the high 14.
18 bits address 262,144 neurons, enough for the whole brain (138,639) but only 28 copies of the
9,262-neuron circuit.
**Fix**: 19 bits for the target, 13 for the count (`sim::POST_BITS`, mask and shift in
`sim.wgsl`'s `deliver`). The largest |count| in FlyWire 783 is 2405, which fits 13 signed bits
(±4095). The limit is now 2^19 = 524,288 neurons, 56 circuits. `data/fly.bin` keeps the 18-bit
packing, and `Fly::load` repacks, so an old file cannot be misread silently. Scorecards for 5 flies
are identical before and after.

### S17. Fly counts overwrote each other's training cache (P3 ensemble)
**Symptom**: while comparing fly counts, every run retrained, and the 50-fly viewer would have
lost its training to the next 30-fly run.
**Cause**: the cache name (S12) hashed the training file and binary but not the number of flies.
A different count failed the size check, retrained, and saved over the same file.
**Fix**: the name includes the fly count, `data/cache/cluster<k>-<key>.bin` (`cluster::build`).

---

## Solved: data and encoding

### E1. FlyWire data access (P0)
**Symptom**: FlyWire Codex downloads need a login.
**Fix**: we use the public export from Shiu et al. 2024 (`Connectivity_783.parquet`,
`Completeness_783.csv`) and the `flywire_annotations` supplemental file for positions and cell
types. 99.5% of IDs matched, and only 14 neurons had no position (they are placed at the centroid).
**Lesson**: check ID overlap before trusting a join across sources.

### E2. Input never left the first layer (P1)
**Symptom**: events were hashed into random sensory neurons. Descending neurons stayed silent and
nothing propagated.
**Cause**: two thirds of "sensory" neurons are photoreceptors, and each event touched a few unrelated
neurons from mixed senses.
**Fix**: use the olfactory pathway. Each value is an "odour" that fires the receptor neurons of
whole glomeruli. About 43 receptors converge on a few projection neurons, so the signal carries on to
the Kenyon cells.

### E3. One receptor spike per event barely reached Kenyon cells (P3)
**Symptom**: one isolated event gave about 25 projection neuron spikes but only 0 to 5 Kenyon cell
spikes. Quiet intrusion stages (0.25 to 2 events/s) produced no response at all.
**Cause**: Kenyon cells only fire when several inputs arrive together, and one synchronous spike is
a single brief pulse. Using more glomeruli per event helped only a little (about 2.4 Kenyon spikes).
**Fix**: puffs. Each event makes its receptors fire 5 spikes 4 ms apart (`PUFF_SPIKES`,
`PUFF_GAP_MS`), like a real odour response. This gives about 170 Kenyon spikes per event, still a
small fraction of 5,177 cells.

### E4. Hashing a whole event key prevented generalisation (P3)
**Symptom**: the authorised scanner could never become familiar.
**Cause**: "scanner, port 123" and "scanner, port 456" hashed to unrelated odours.
**Fix**: odours are built from components, one per field (`Event::features`). Each component gets 2
glomeruli, so the scanner's source becomes a familiar component. For DNS, the components are the base
domain and the first label's length bucket, so exfiltration through random subdomains still looks
alike even though every name is new.

### E5. Only 53 input channels (P3)
**Symptom**: with one glomerulus per key, hundreds of benign keys covered all 53 glomeruli, so
everything looked familiar.
**Fix**: combinations of glomeruli per event (E4), as real odours use. 3 of 53 already allows about
23,000 combinations.

### E6. Rust's standard hasher is not stable
**Symptom**: none yet, but trained flies depend on the same value always mapping to the same
glomeruli.
**Fix**: FNV-1a (`detect::fnv`), which is fixed forever, unlike `DefaultHasher`, which may change
between Rust releases.

### E7. Per-event novelty could not see scans and sprays (P3, was open issues O2 and O3)
**Symptom**: the identity fly missed the password spray (0/2), rating it below a user mistyping
(68 vs 83 output spikes/s). The network fly missed the slow scan (0/2): 12 spikes/s during the scan,
12 during the authorised scanner, 9 during plain traffic.
**Cause**: both attacks are patterns across events. Each failed login of a spray looks like a typo,
and one scan connection every 3 s drowns in 20 normal ones per second.
**Fix**: `History` (`src/detect.rs`) adds one component per event: how many distinct ports this
source touched, users failing from this source, processes on this host, or names under this base
domain in the last 60 s, bucketed by powers of two. On the holdout, identity catches 2/2 sprays and
network 1/2 slow scans.

### E8. History components were drowned out (P3)
**Symptom**: with 2 glomeruli per history component, like every other component, spray and typo
still looked alike (80 vs 76 identity output spikes/s on the test file).
**Cause**: an auth event has 4 field components (8 glomeruli) against 1 history component
(2 glomeruli), and a failed login of any kind is rare, so "fail" dominated the odour.
**Fix**: history components get 4 glomeruli (`GLOMERULI_PER_HISTORY`). Spray vs typo became 95 vs 71,
slow scan vs authorised scanner 23 vs 16, and exfiltration vs new sites 190 vs 39.

### E9. Results depended on a lucky glomerulus hashing (P3 ensemble, was open issue O7)
**Symptom**: summing R individuals per role (`FLYSOC_REPLICAS`, README "More flies") should average
away noise. Instead, on cluster_eval_21-25 rule D's false-alert seconds go 0 (5 flies) → 4 (10) →
111 (15) → 189 (30) → 115 (50), and the single-fly role's go 3 → 25 → 211 → 229 → 178. Detection gets
~30 s faster and look-alikes stay flat (23-27/50). It is not one bad file: with 15 flies every eval
file has 10-46 false seconds under D.
**What we know**: each role's threshold is the highest calm-training evidence. With 3 individuals the
single fly's threshold is 2.6x the 1-individual one (118.9 vs 45.9 spikes/s), not 3x. So the new
individuals are quieter on training data than individual 0, yet fire on new benign test traffic.
**Hypothesis (untested)**: the encoding was tuned with individual 0's glomerulus hashing (E3-E8 were
tuned on test files), so other hashings put features on colliding glomeruli and generalise worse.
**Tested**: each individual alone (`FLYSOC_SALT`, 5 flies, eval set, rule D / single-fly role):

| individual | D caught | D look-alikes | D false s | single false s |
|---|---|---|---|---|
| 0 (the original) | 10/10 | 25/50 | 0 | 3 |
| 1 | 10/10 | 18/50 | 8 | 39 |
| 2 | 10/10 | 15/50 | 229 | 261 |
| 3 | 10/10 | 20/50 | 106 | 110 |
| 4 | 9/10 | 13/50 | 127 | 182 |

So the hypothesis holds: individual 0 is the outlier, not the norm. Results depend on which
features happen to share glomeruli, and the encoding was tuned on individual 0's draw. Summing
individuals mixes in the worse ones. Every earlier result is one lucky draw of the hashing.
**Cause**: 53 glomeruli, and an event lights about 12 of them (E5, E8). History components carry the
detection signal, but they hash into the same glomeruli as very common fields (`result=ok`,
`dport=443`), which training teaches the fly to ignore.
**Fix**: the last 13 of the 53 glomeruli are reserved for history components, and no field hashes
into them (`HISTORY_GLOMERULI`, `Encoder::neurons`). A first try hashed history into the 13 reserved
glomeruli: false alarms vanished for every individual, but individuals 1 and 2 caught only 5/10,
because "6 ports" and "1 port" now collided with each other. History values are magnitudes, so they
are not hashed at all: bucket b lights reserved glomeruli b to b+3 (an ordinal code, the same in
every individual). Eval set, rule D, each individual alone:

| individual | caught | median first alert | look-alikes | false s (before → after) |
|---|---|---|---|---|
| 0 | 10/10 | +82 s (was +70) | 23/50 | 0 → 0 |
| 1 | 10/10 | +626 s | 11/50 | 8 → 0 |
| 2 | 10/10 | +625 s | 18/50 | 229 → 0 |
| 3 | 10/10 | +105 s | 22/50 | 106 → 0 |
| 4 | 10/10 (was 9) | +448 s | 19/50 | 127 → 0 |

Every individual now catches everything without false alarms. The remaining lottery is speed,
from the hashed fields. Chosen on the eval set; the final-set numbers in README are after this fix,
and the single fly's slowness there was fixed by L7. Phase 2 moved from 1/502 to 2/502 false windows.
**Lesson**: tuning on one random draw of a hash tunes on that draw. Vary the seed before trusting a
result.

### E10. History over one minute could not see low-and-slow attacks (P4, was open issue O11)
**Symptom**: blue retrained on red's 3 best intrusions (`red.py harden`) did no better against
them than the original blue (8/12 caught each, L8). Red's #2 and #3 scan 37 ports over 900 s and
spread exfiltration over 1600 s.
**First guess, wrong**: learning only depresses Kenyon cell → MBON synapses in safe windows, and
attack windows only restore weights toward their start (L5), so already-novel smells teach blue
nothing. Letting attack windows potentiate up to a cap changed nothing beyond noise. Rule D on the
eval set and the harden duel (original vs retrained blue, replays caught of 12):

| attack windows | eval D first alert, look-alikes, false s | duel |
|---|---|---|
| restore to start (current) | +88 s, 22/50, 0 | 8 vs 8 |
| potentiate to 1.5x | +86 s, 22/50, 0 | - |
| potentiate to 2x | +86 s, 23/50, 0 | 7 vs 7 |
| potentiate to 4x | +74 s, 24/50, 0 | 8 vs 7 |
| only synapses not depressed, to 1x | +88 s, 22/50, 0 | 7 vs 7 |
| only synapses not depressed, to 4x | +86 s, 22/50, 0 | 8 vs 7 |

Raw scorecards in `data/runs/cap/`.
**Cause**: every history count looked back 60 s. One port every 24 s is 2-3 distinct ports a
minute, like any workstation; ~8 exfiltration names a minute is below what benign CDN traffic
shows (21). The smells were the same as benign ones, so no learning rule could separate them.
Over 15 minutes benign counts barely grow (at most 6 ports per workstation, 1 failed user per
source, 30 names per domain, in `cluster_calib.jsonl`), while the slow stages pile up (37 ports,
~114 names).
**Tried**: one longer window for ports, failed users and DNS names. 300 s: eval rule D +210 s, 2
false seconds; 900 s: +443 s, 4 false seconds (from +88 s, 0). Slow genomes improved (0.84 → 0.70
at 900 s on 5 backgrounds), fast intrusions got slower: one window cannot serve both.
**Fix**: both windows. Ports, failed users and DNS names get a 60 s and a 15-minute component
(`LONG_HISTORY_S` in `detect.rs`, `name_long=bucket`), each in its own ordinal code of 10 reserved
glomeruli (`HISTORY_GLOMERULI_TWO_CODES`). Processes keep only 60 s: benign hosts cycle through
all their processes within minutes. The first version gave every fly 20 reserved glomeruli, which
cost the processes-only endpoint fly field glomeruli for nothing (3/10 caught, 117 false seconds
on the eval set); it now keeps one code of 13 and is back to exactly 5/10, 20. Suspects use the
15-minute count.
**Result**: eval set, rule D: +87 s, 23/50, 0 false seconds (was +88 s, 22/50, 0). Final set: +89 s
(was +360 s), 8 of 10 caught during the scan (was 5), 20/50 look-alikes (was 19), 2 false seconds
(was 0). Against red on 20 fresh backgrounds, mean progress 0.58, 0.79, 0.79, 0.33 instead of 0.60,
0.83, 0.83, 0.53: the baseline-paced intrusion is caught much earlier, but red's slow scan still
gets through (O12). The harden duel stays even (O11's symptom remains: 4 vs 5 of 12 on 7001-7003,
15 vs 15 of 20 on 8001-8005), which is expected while O12 hides the slow scan from rule D.
**Cost**: Phase 2's port-scan test lost its learning gain. Trained, the fly now catches 36/40 scan
windows 1 s in with 3/502 false alerts, like the untrained fly (was 40/40, 0 s, 2/502). That test is
saturated: the untrained fly already catches every scan within 1 s.
**Lesson**: when learning cannot separate two things, check whether the input can. Also, 5
backgrounds were not enough to judge red: they said this fixed the slow scan, 20 said it did not.

---

## Solved: circuit and learning

### O17. Sleep that overwrites the day's weights destroys what attacks taught (P10, fixed; no gain yet)
**Symptom**: `MushroomBody::sleep` as first built set every output weight to
$w^0 e^{-f/r}$ from its safe-second frequency $f$, replacing the day's weight. Eval sets
(`data/runs/p10/z*`):

| | LANL eval, identity episodes attack / false | synthetic eval, rule D | synthetic network fly |
|---|---|---|---|
| no sleep (default) | 10 / 0 | +87 s, 23/50, 0 false s | 10/10, +34 s |
| sleep, r = 0.005 | 10 / 0 | +624 s, 12/50, 0 | 6/10, +324 s |
| sleep, r = 0.02 | 12 / 1 | +633 s, 10/50, 0 | 10/10, +53 s |

The probe (README "Phase 9") still showed no readout response rising with the failed-users count.
**Cause**: sleep ignored attack seconds and threw away the day's weights, including what attack
seconds restored. Kenyon cells are shared between odours: a cell that signals a scan also fires in
ordinary traffic, so its frequency is high and sleep silenced it. The Lean theorem
`night_forgets_the_weight` states the overwrite exactly; it holds, and it is the flaw.
**Fix**: sleep only gives weight back, $w \leftarrow \max(w, w^0 e^{-f/r})$ (`MushroomBody::sleep`,
`floor`): what attacks and common patterns taught by day stays, a pattern met harmlessly once or
twice is restored. Lean: `sleep_never_lowers`, `sleep_keeps_day_learning`,
`days_and_nights_bounded` replace the overwrite theorem; the Rust tests fail on the overwrite
version (4 tests) and on min for max (9).

| restore-only sleep | LANL eval, identity attack / false | synthetic eval, rule D | rule E | network fly |
|---|---|---|---|---|
| r = 0.005 | 11 / 0 | +87 s, 23/50, 0 false s | +74 s, 34/50, 5 | 10/10, +34 s |
| r = 0.02 | 10 / 1 | +88 s, 23/50, 0 | +78 s, 34/50, 5 | 10/10, +34 s |

Safe: synthetic results are the default's to the second. But it changes nothing that matters, and
the probe is still flat (readout added per logon at counts 1..16: 0, 0, 1, 1, 0, 16, 5, 0, ...,
7; count 6 responds in every variant, so that is the background, not the count). Sleep stays
opt-in (`FLYSOC_SLEEP=1`), off by default.
**Lesson**: the hypothesis behind it, that one harmless sighting over-depresses a rare count's
synapses, is mostly wrong. With one failure a minute the 60-second code always reads 1, and
neighbouring 15-minute buckets share 3 of 4 glomeruli (ordinal code, O7), so a count of 16 lights
nearly the same Kenyon cells as a count of 2. No learning rule can separate cells the encoding has
merged: the next step is the encoding (Phase 9).

### L1. In the whole brain, every input looked the same to the mushroom body (P2)
**Symptom**: scan, burst and spontaneous ignitions each fired about 3,200 of 5,177 Kenyon cells (60%),
with 88 to 97% identical patterns. No learning rule could separate them. Real flies use 5 to 10%.
**Cause**: the brain-wide ignition (S8) drowned out the odour's identity.
**Fix**: see L2 and L3.

### L2. The smell circuit alone still ran away (P2)
**Symptom**: the extracted olfactory to mushroom body circuit (9,262 neurons) still fired forever
without adaptation. Even with adaptation it ignited 27 times in 600 s.
**Cause**: excitatory loops a point-neuron model cannot handle. Kenyon cell → Kenyon cell connections
are 40% of the circuit's connections, all excitatory and axon-to-axon. After cutting them, receptor
neurons kept firing from synapses onto their axon terminals, and then projection, local and lateral
horn neurons kept each other going. In a real fly these synapses modulate release; in a point
neuron they trigger spikes.
**Fix**: a layered rule (`detect::circuit`). Keep every inhibitory connection and only excitatory
connections that go forward a layer (receptors → antennal lobe → Kenyon cells and lateral horn →
output neurons). The circuit is then stable with no adaptation (the Shiu model unchanged), Kenyon
coding is sparse (about 1%), and scan and burst patterns have a cosine similarity of 0.13 (from 0.93).
Standard mushroom body models are feedforward with APL inhibition, too.
**Lesson**: we chased loops one at a time twice before switching to a rule. Look for the principle
sooner.

### L3. Dopamine neurons as fast excitation (P2)
**Symptom**: the connectome includes dopamine neurons, and the model would treat their synapses as
ordinary excitation.
**Fix**: dopamine neurons (DAN, DPM) are not simulated. In flies they modulate learning, so they
became the learning signal instead (L5). APL, the inhibitory feedback neuron that keeps Kenyon cells
sparse, stays in.

### L4. Output neurons were silent before training (P2)
**Symptom**: with sparse Kenyon coding, MBONs never fired.
**Cause**: raw synapse counts are not enough at about 1% Kenyon activity.
**Fix**: plastic Kenyon cell → MBON weights start at `INIT_GAIN` (16x) their synapse count. Learning
only lowers them from there.

### L5. Learning that only forgets (P2, P3)
**Symptom**: first it over-depressed (trained scans averaged 3.4 MBON spikes; only 13 of 50 scan windows
alerted). In P3 every fly became nearly silent after training, attacks included.
**Cause**: every Kenyon cell that fired in a safe window lost its output, permanently. With busy
traffic, that is nearly every Kenyon cell.
**Fix**: tuned the gain and rate (`INIT_GAIN` 16, `LR_SAFE` 0.1), then added `RECOVERY`: every weight
drifts 0.2% back toward its start each window. "Familiar" now means "seen often", not "seen once".

### L6. One-sided thresholds (P1, P2)
**Symptom**: after training, benign traffic gave exactly 0 output spikes, so mean + 4σ came out as
0. A few stray spikes then raised alerts.
**Fix**: a minimum (`MIN_ALERT`, 20 MBON spikes; scans drive hundreds). In P3 thresholds come from
replaying training data (M4).

### L7. Thresholds hung on the single highest calm second (P3, P4; was open issue O8)
**Symptom**: on the final set the single fly, and so rule D, caught 5 of 10 intrusions only when
exfiltration began (+610 s; D median +354 s), although the network fly saw each scan within 70 s.
**Cause**: each fly fired only above the highest evidence on any calm training second. One unusual
calm second set the bar for the whole run, and the bar grows with the length of training.
**Fix**: the 99.9th percentile of calm evidence (`CALM_QUANTILE` in `cluster.rs`). Eval set, rule D:

| calm threshold | median first alert | look-alikes | false s |
|---|---|---|---|
| maximum | +82 s | 23/50 | 0 |
| 99.9th percentile | +64 s | 24/50 | 0 |
| 99.5th | +56 s | 28/50 | 5 |
| 99th | +55 s | 30/50 | 7 |

Chosen on the eval set. On the final set D went from +354 s to +94 s, still with 0 false seconds.
It did not fix O9 (now L8), which it was meant for.

### L8. Thresholds depended on which benign bursts the training file contained (P3, P4; was open issue O9)
**Symptom**: blue retrained on the training file plus red's 3 best intrusions (`red.py harden`,
2400 s → 11,600 s of training) caught fewer of red's intrusions than the original blue: 7/12
against 10/12, replayed into 3 backgrounds neither had seen. The first guess, that the maximum
grows with file length, was wrong: the 99.9th percentile (L7) gave the same result.
**Cause**: found with `tools/o9.py`, which prints every fly's threshold and its peak evidence per
stage (raw output in `data/runs/o9_peaks.txt`). The identity fly's threshold rose from 28.2 to
47.5, and with it spray detection fell from 10/12 to 6/12, while its evidence on red's stages
barely moved. The new threshold came from seconds 8259-8270 of the hardened file: a random cluster
of 9 ordinary logins in 3 s, which drove the identity fly to 300 MBON spikes/s. The original blue
responds to that same burst just as strongly (evidence 49.3 vs 51.8), so this was calibration, not
learning. Only 2,855 of the hardened file's seconds were calm (red's slow stages make most of it
unsafe), and the original file had ~1,700: the 99.9th percentile was the 2nd or 3rd highest second,
and so depended on which rare bursts a file happened to contain. The original blue's low threshold
was luck; it would false-alarm on such a burst.
**Tried, no help**: divisive gain control, scoring MBON spikes per Kenyon cell spike instead of per
second (MBON output scales with Kenyon input at a near-constant ~0.25 for one login and for the
burst). Offline on the eval set, false-alarm seconds stayed the same or rose for every fly at every
offset tried, and endpoint caught 6-7/10 either way: dividing removes signal along with volume.
**Fix**: thresholds are set on the calm seconds of the training replay plus a calibration replay
of `data/telemetry/cluster_calib.jsonl` (12,000 s of benign traffic with every look-alike 6 times,
written by `tools/gen_intrusion.py`): ~14,000 calm seconds (`CALIBRATION` in `cluster.rs`, part of
the cache key). With more calm seconds the quantile was chosen again on the eval set, rule D:

| calm quantile | median first alert | look-alikes | false s |
|---|---|---|---|
| 99th | +64 s | 26/50 | 0 |
| **99.5th (chosen)** | +88 s | 22/50 | 0 |
| 99.8th | +107 s | 20/50 | 0 |
| 99.9th | +372 s | 19/50 | 0 |
| 99.95th | +612 s | 17/50 | 0 |

99.5th is clear of the cliff between 99.8th and 99.9th, and about 70 calm seconds lie above it, so
no single burst moves it. Raw scorecards in `data/runs/calib/`.
**Result**: the harden duel now comes out equal (8/12 both; then E10). Final set, rule D: 10/10, 19/50
look-alikes (was 22), 0 false seconds, median first alert +360 s (was +94 s). The medians are
bimodal: each intrusion is caught during the scan (+20 to +117 s) or at exfiltration (~+610 s);
D catches 5/10 early on the final set and 9/10 on the eval set. Calibration adds ~77 s to the
first run of a training file.
**Lesson**: a high quantile of a small sample is just one of its largest values. Count how many
samples lie above a threshold before trusting it.

---

## Solved: measurement and evaluation

### M1. A lucky test result (P1)
**Symptom**: "detected 0 s after start, no false alerts".
**Cause**: the whole brain ignited about every 80 s, and the single test scan started at t = 80. The
detection may have been a scheduled ignition.
**Fix**: test files with several incidents at different times. A 600 s benign-only file gives an
honest false-alert rate, because incidents every minute were resetting the oscillator and hiding its
false alerts.
**Lesson**: one incident is an anecdote. Use several, at varied times.

### M2. Tuning on the test set (P2, P3)
**Symptom**: settings chosen by sweeping against `test.jsonl` flatter results on that file.
**Fix**: a third seed, `holdout.jsonl` / `cluster_holdout.jsonl`, never used for tuning. README numbers
come from it.

### M3. Responses outlast the incident (P2, P3)
**Symptom**: the second after a scan ends, labelled plain benign, alerted and counted as a false
alert.
**Cause**: 1 s of telemetry is only 50 ms of fly time, so the response spills into the next window.
In P3 the 20 s evidence average remembers about 60 s.
**Fix**: alerts within `TAIL_S` after an incident count as part of it (2 s in `detect`, 60 s in
`cluster`). This applies equally to every fly, so comparisons stay fair.

### M4. Thresholds from a baseline without look-alikes (P3)
**Symptom**: the DNS fly raised 29 false alert seconds. Its threshold came from a 300 s benign
baseline that contains no look-alikes.
**Fix**: after training, each fly replays its training data without learning and fires only above the
highest evidence it showed on safe training seconds, look-alikes included (`cluster::run`). The
separate baseline file is no longer needed for `cluster`.

### M5. Noisy single seconds (P3)
**Symptom**: ordinary benign seconds reached 170 to 420 MBON spikes at their peaks.
**Fix**: the coordinator uses evidence averaged over about 20 s (`cluster::evidence`). Intrusion stages
last minutes anyway.

### M6. Measuring memory
**Symptom**: the first attempts measured nothing. GNU `time` is not installed, and `nvidia-smi`
sampled after a short run had already ended.
**Fix**: sample a longer run (`detect` or `cluster`) while it is still running. For host memory,
use Python's `resource.getrusage` or `/proc/<pid>/smaps_rollup`, and `nvidia-smi
--query-compute-apps` for GPU.

### M7. Offline analysis disagreed with FlySOC about when a fly alarms
**Symptom**: recomputing the flies' alarms in pandas from a `FLYSOC_TRACE` file showed the single
fly red for 14 s at the start of the holdout file. FlySOC's own scorecard and viewer showed no such
thing.
**Cause**: `ewm(adjust=False)` starts the moving average at the first value. FlySOC starts it at 0
(`Coordinator::second`), so the first seconds differ.
**Fix**: prepend a 0 before computing the average in pandas. The two then agree.
**Lesson**: when re-deriving a result outside the code, match its initial conditions, and check
against the code's own output before drawing conclusions.

### M10. "Look-alikes alerted" counted coincidences, not false alarms (P3, P4)
**Symptom**: the scorecard said rule D alerts on 20 of 50 look-alikes on the final set (E: 24), which
reads as a false-positive rate near 50%.
**Cause**: the scorecard counts an episode as alerted when any alert fires during it, about any
entity. The eval and final files overlay 10 look-alikes on 2 intrusions in 40 minutes, on a network
of 5 servers: a scan or an admin session usually shares a server with an intrusion running at the
same time, and the alert about that server is about the intrusion. Of the 8 look-alike episodes
that rule D's alerts named an entity of on the eval set, 7 had an intrusion on the same server at
that moment.
**Fix**: `tools/attribution.py` scores `flysoc cluster`'s JSON alerts as an analyst's queue:
alerts about one entity less than 60 s apart are one alert, attributed to an intrusion if the entity
takes part in one at that time, else to a look-alike, else to nothing.

| alert queue | eval: alerts, precision | final: alerts, precision | final: first alert naming the intrusion |
|---|---|---|---|
| D, incidents | 44, 91% (1 scanner, 3 nothing) | 43, **79%** (5 scanner, 4 nothing) | +102 s |
| E, incidents + leads | 55, 91% (1 scanner, 4 nothing) | 55, 76% (5 scanner, 8 nothing) | +90 s |

Holdout: 5 alerts (D), 6 (E), all about the 2 intrusions. The scorecard's time-only first alert was
also generous: on the final set, D's first alert *naming one of the intrusion's hosts* is +102 s
(scorecard +89 s), E's +90 s (+60 s). Raw alerts in `data/runs/fp/`.
**Lesson**: score what the analyst sees, an alert about an entity, not a second in which something
fired.

### M11. A weekend calibration set thresholds too low for weekdays (LANL)
**Symptom**: calibrated on day 3, 08:00-12:00, the identity fly was alarmed in 1530 of 6946 benign
seconds (22%) of eval_1 (day 8).
**Cause**: days 3, 4, 10 and 11 carry 155 auth lines/s, the others 205-240: weekends. A quiet day's
calm sets the threshold (30.0) below a busy day's calm.
**Fix**: calibrate on a weekday without red-team activity, day 7, 12:00-16:00
(`FLYSOC_CALIB=data/telemetry/lanl/calib_wd.jsonl`): threshold 39.1, 12 false seconds, both incidents
still caught (+403 s, +38 s by the scorecard). Also found: `tools/lanl.py` wrote `failure` where the
flies expect `fail`; fixing it changed nothing measurable (0.6% of human logons fail).
**Lesson**: real traffic has a week; calibrate on the kind of day you will watch. The evening miss
(O15) says the same for the time of day.

### M9. Two intrusions and ten look-alikes are too few to compare rules (P3)
**Symptom**: on `cluster_test`, coordinator rule C (all five flies vote) beat the single fly on
speed and look-alikes. On `cluster_holdout` it lost on both, and the single fly's 0/10 look-alikes
looked perfect.
**Cause**: one incident more or less flips the comparison. The single fly's perfect holdout score was
luck: over 50 look-alikes it alerts on 23 to 29.
**Fix**: two sets of 5 files with random timings, each with 10 intrusions and 50 look-alikes
(`gen_intrusion.py`). `cluster_eval_*` is for choosing (it chose rule D), and `cluster_final_*` is
never used for a choice; the README reports it.
**Lesson**: size the evaluation to the size of the differences you want to see, and keep the set
you report separate from the one you choose with. Differences of a few alerts out of 50 are still
noise.

---

## Solved: tooling

### D1. Missing Python packages
**Symptom**: system Python has no numpy, pandas or pyarrow.
**Fix**: `tools/convert.py` declares its dependencies inline and runs with `uv run`. One-off analysis
uses `uv run --with numpy --with pandas`.

### D2. The viewer's status was invisible on Hyprland (P3 viewer)
**Symptom**: `watch` put all its status (telemetry second, what is happening, red flies, incidents)
in the window title. Hyprland draws no title bars, so none of it was visible. It also looped
forever with no visible clock, so there was no way to tell how long was left.
**Fix**: `watch` also prints a terminal line whenever the status changes, plus a marker each time it
restarts from 0 (`Watch::describe`). Labels count as "happening" for 10 s after their last event,
otherwise the slow scan (one event every 3 s) would flicker the log. On Hyprland you can also run
`hyprctl clients` to see titles. A text overlay in the window needs a UI library (egui is planned
for Phase 6).

### D3. Setting up Lean and Mathlib (P5)
**Symptom**: `lake new lean math` failed with "reserved package name". In a project named
`FlySOC`, `lake init` then failed to fetch Mathlib: "couldn't find remote ref v4.36.0".
**Cause**: `lean` is a reserved package name. Lake's math template pins Mathlib to the tag of
the newest Lean release (v4.36.0), which Mathlib had not tagged yet; its newest tag was v4.35.0.
**Fix**: the project lives in `proofs/`, with Mathlib pinned to `v4.35.0` in `lakefile.toml` and
the matching `leanprover/lean4:v4.35.0` in `lean-toolchain`. `lake exe cache get` downloads
Mathlib prebuilt (about 7 GB in `proofs/.lake`, which `proofs/.gitignore` ignores), so nothing of
Mathlib is compiled locally.
**Lesson**: pin Mathlib to a tag that exists, and pin the toolchain to match it.

