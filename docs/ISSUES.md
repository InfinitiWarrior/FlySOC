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
rule D (the team confirms the single fly) catches 10/10 at +94 s with 0 false-alarm seconds and
22/50 look-alikes. The single fly alone does the same (+94 s, 0, 25/50). The team no longer costs
time, but no rule beats the single fly clearly either. (Before E9 and L7: D 16 false seconds and
+137 s, single fly 46 and +102 s.)
**Cause, as far as we can tell**: requiring agreement costs time. The history components (E7) helped
the single fly as much as the specialists, and one circuit has enough capacity for all four kinds.
**Next**: a coordinator that learns how much to trust each fly, per-entity learning from look-alike
labels, and real data (O4).

### O4. Everything is synthetic
**Symptom**: all results come from our own generators (`tools/gen_traffic.py`,
`tools/gen_intrusion.py`).
**Risk**: the flies may be learning quirks of the generator, e.g. its fixed set of benign ports and
processes.
**Next**: a real labelled dataset. CICIDS2017 has network flows. OTRF Security-Datasets has real
recorded ATT&CK techniques from Windows hosts and fits the endpoint and identity flies.

### O5. The whole brain still ignites (P0 viewer)
**Symptom**: in the whole-brain viewer, steady input makes about 60% of Kenyon cells fire at once
every minute or so (see S8).
**Status**: detection no longer uses the whole brain (see L1, L2), so this only affects the viewer.
The proper fix would be homeostasis, or the layered rule from L2 applied brain-wide.

### O9. Retraining on red's evasions made blue less sensitive (P4)
**Symptom**: blue retrained on the training file plus red's 3 best intrusions, each in fresh
background (`red.py harden`, 2400 s → 7000 s of training). Against those intrusions, replayed into 3
backgrounds neither side had seen, the original blue caught 11/12 and the retrained blue 7/12.
**First guess, wrong**: a fly's threshold was the highest evidence on calm training seconds (M4),
and more calm seconds give a higher maximum. Thresholds are now the 99.9th percentile (L7), which
does not grow with file length, but the duel came out the same: original blue 10/12, retrained 7/12.
**Next**: compare the two blues' thresholds and evidence on red's intrusions, stage by stage. Likely
suspects: the hardened training adds 3 intrusions' worth of depression-free "unsafe" seconds that
learning cannot use (learning only depresses on safe seconds, L5), and 4600 s more benign traffic
that depresses more Kenyon cell synapses overall.

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
**Next**: make blue's decision less dependent on background (O9's calibration first), then red with
more backgrounds per candidate (each one costs ~10 s of GPU time).
**Lesson**: an optimiser finds the noise in its fitness function. Score on several draws, and
re-check winners on draws they never saw.

---

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

---

## Solved: circuit and learning

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
It did not fix O9, which it was meant for.

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
