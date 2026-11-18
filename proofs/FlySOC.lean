/-
FlySOC, Phase 5: machine-checked properties of the encoding and the learning rule.
Each definition mirrors a line of the Rust code, named in its docstring. `lake build` checks all
of it; there is no `sorry` in this file.
-/
import Mathlib

namespace FlySOC

/-- Power-of-two bucket of a count: `usize::BITS - n.leading_zeros()` in `History::observe`. -/
def bucket (n : ℕ) : ℕ := if n = 0 then 0 else Nat.log2 n + 1

/-- Reserved glomeruli lit by bucket `b` in an ordinal code of `size` glomeruli at offset `o`:
`offset + (bucket + k).min(size - 1)` for `k < GLOMERULI_PER_HISTORY = 4` in `detect.rs`. -/
def code (o size b : ℕ) : Finset ℕ :=
  (Finset.range 4).image fun k => o + min (b + k) (size - 1)

/-- More distinct values never mean a lower bucket. -/
theorem bucket_mono {m n : ℕ} (h : m ≤ n) : bucket m ≤ bucket n := by
  unfold bucket
  split_ifs with hm hn
  · exact le_rfl
  · omega
  · omega
  · simp only [Nat.log2_eq_log_two]
    exact Nat.add_le_add_right (Nat.log_mono_right h) 1

/-- The 15-minute count covers the 1-minute one, so an event's long bucket is never below its
short bucket (`History::distinct` returns both). -/
theorem long_bucket_ge_short {short long : ℕ} (h : short ≤ long) : bucket short ≤ bucket long :=
  bucket_mono h

/-- Away from the cap, buckets four or more apart light disjoint glomeruli. -/
theorem code_disjoint {o size b b' : ℕ} (hcap : b' + 3 < size) (h : b + 4 ≤ b') :
    Disjoint (code o size b) (code o size b') := by
  rw [Finset.disjoint_left]
  simp only [code, Finset.mem_image, Finset.mem_range]
  rintro _ ⟨k, hk, rfl⟩ ⟨k', hk', he⟩
  omega

/-- Away from the cap, a code is four consecutive glomeruli. -/
theorem code_eq_Ico {o size b : ℕ} (hcap : b + 3 < size) :
    code o size b = Finset.Ico (o + b) (o + b + 4) := by
  ext g
  simp only [code, Finset.mem_image, Finset.mem_range, Finset.mem_Ico]
  constructor
  · rintro ⟨k, hk, rfl⟩; omega
  · intro hg; exact ⟨g - (o + b), by omega, by omega⟩

/-- Close magnitudes share glomeruli, in proportion to how close they are:
`|G(b) ∩ G(b')| = max(0, 4 - |b - b'|)` (written with truncated subtraction). -/
theorem code_overlap {o size b b' : ℕ} (hb : b + 3 < size) (hb' : b' + 3 < size) :
    (code o size b ∩ code o size b').card = 4 - (max b b' - min b b') := by
  rw [code_eq_Ico hb, code_eq_Ico hb', Finset.Ico_inter_Ico, Nat.card_Ico]
  omega

/-- One second of the three-factor rule on one synapse (`MushroomBody::learn`). -/
noncomputable def learn (ρ ηs ηr w0 w : ℝ) (α : ℕ) (safe : Bool) : ℝ :=
  let w := w + ρ * (w0 - w)
  if α = 0 then w
  else if safe then w * (1 - ηs) ^ α
  else w0 + (w - w0) * (1 - ηr) ^ α

/-- Learning never makes a synapse stronger than it started, nor silences it. -/
theorem learn_bounded {ρ ηs ηr w0 w : ℝ} {α : ℕ} {safe : Bool}
    (hρ : 0 ≤ ρ ∧ ρ ≤ 1) (hs : 0 ≤ ηs ∧ ηs < 1) (hr : 0 ≤ ηr ∧ ηr ≤ 1)
    (hw : 0 < w ∧ w ≤ w0) :
    0 < learn ρ ηs ηr w0 w α safe ∧ learn ρ ηs ηr w0 w α safe ≤ w0 := by
  obtain ⟨hρ0, hρ1⟩ := hρ
  obtain ⟨hw0, hww⟩ := hw
  -- after recovery, w₁ = (1 - ρ) w + ρ w0 lies in (0, w0]
  have h1 : 0 < w + ρ * (w0 - w) := by nlinarith
  have h2 : w + ρ * (w0 - w) ≤ w0 := by nlinarith
  unfold learn
  split_ifs with hα hsafe
  · exact ⟨h1, h2⟩
  · have hc : 0 < (1 - ηs) ^ α := pow_pos (by linarith [hs.2]) α
    have hc1 : (1 - ηs) ^ α ≤ 1 := pow_le_one₀ (by linarith [hs.2]) (by linarith [hs.1])
    exact ⟨mul_pos h1 hc, by nlinarith⟩
  · have hc : 0 ≤ (1 - ηr) ^ α := pow_nonneg (by linarith [hr.2]) α
    have hc1 : (1 - ηr) ^ α ≤ 1 := pow_le_one₀ (by linarith [hr.2]) (by linarith [hr.1])
    constructor <;> nlinarith

/-- So a whole training run keeps every weight in (0, w0]: induction over the seconds. -/
theorem train_bounded {ρ ηs ηr w0 : ℝ}
    (hρ : 0 ≤ ρ ∧ ρ ≤ 1) (hs : 0 ≤ ηs ∧ ηs < 1) (hr : 0 ≤ ηr ∧ ηr ≤ 1) (hw0 : 0 < w0)
    (seconds : List (ℕ × Bool)) :
    let w := seconds.foldl (fun w s => learn ρ ηs ηr w0 w s.1 s.2) w0
    0 < w ∧ w ≤ w0 := by
  suffices ∀ (l : List (ℕ × Bool)) (w : ℝ), 0 < w ∧ w ≤ w0 →
      let w' := l.foldl (fun w s => learn ρ ηs ηr w0 w s.1 s.2) w; 0 < w' ∧ w' ≤ w0 from
    this seconds w0 ⟨hw0, le_rfl⟩
  intro l
  induction l with
  | nil => intro w hw; exact hw
  | cons s l ih => intro w hw; exact ih _ (learn_bounded hρ hs hr hw)

/-- `train_bounded` from any starting weight in (0, w0], e.g. the weight a sleep left. -/
theorem train_bounded_from {ρ ηs ηr w0 : ℝ}
    (hρ : 0 ≤ ρ ∧ ρ ≤ 1) (hs : 0 ≤ ηs ∧ ηs < 1) (hr : 0 ≤ ηr ∧ ηr ≤ 1)
    (seconds : List (ℕ × Bool)) :
    ∀ w : ℝ, 0 < w ∧ w ≤ w0 →
      0 < seconds.foldl (fun w s => learn ρ ηs ηr w0 w s.1 s.2) w ∧
      seconds.foldl (fun w s => learn ρ ηs ηr w0 w s.1 s.2) w ≤ w0 := by
  induction seconds with
  | nil => intro w hw; exact hw
  | cons s l ih => intro w hw; exact ih _ (learn_bounded hρ hs hr hw)

/-! ## Sleep (`MushroomBody::sleep`, Phase 10)

By day each synapse counts the safe seconds (`safe`) and those in which its Kenyon cell fired
(`seen`); a day is the list of (spikes, safe?) seconds `learn` saw. At night the weight is
restored to at least `w0 * exp(-f / RARE)` with `f = seen / max(safe, 1)`: sleep only gives
weight back (overwriting destroyed what attacks taught, ISSUES O17). -/

/-- Safe seconds in a day (`MushroomBody::safe`). -/
def safeCount (day : List (ℕ × Bool)) : ℕ := (day.filter fun s => s.2).length

/-- Safe seconds in which the Kenyon cell fired (`MushroomBody::seen`). -/
def seenCount (day : List (ℕ × Bool)) : ℕ :=
  ((day.filter fun s => s.2).filter fun s => decide (s.1 ≠ 0)).length

/-- How often the cell fired in safe seconds: `seen / max(safe, 1)`. -/
noncomputable def freq (day : List (ℕ × Bool)) : ℝ :=
  (seenCount day : ℝ) / (max (safeCount day) 1 : ℕ)

/-- The weight sleep restores to at least (`MushroomBody::floor`). -/
noncomputable def floorW (rare w0 : ℝ) (day : List (ℕ × Bool)) : ℝ :=
  w0 * Real.exp (-freq day / rare)

/-- The weight after sleep (`MushroomBody::sleep`): the day's weight, or the floor if higher. -/
noncomputable def sleepW (rare w0 w : ℝ) (day : List (ℕ × Bool)) : ℝ :=
  max w (floorW rare w0 day)

theorem seen_le_safe (day : List (ℕ × Bool)) : seenCount day ≤ safeCount day :=
  List.length_filter_le _ _

/-- So a frequency is a fraction: f ∈ [0, 1]. -/
theorem freq_mem (day : List (ℕ × Bool)) : 0 ≤ freq day ∧ freq day ≤ 1 := by
  unfold freq
  have hpos : (0 : ℝ) < ((max (safeCount day) 1 : ℕ) : ℝ) := by exact_mod_cast (by omega)
  refine ⟨div_nonneg (Nat.cast_nonneg _) hpos.le, ?_⟩
  rw [div_le_one hpos]
  exact_mod_cast le_trans (seen_le_safe day) (le_max_left _ _)

/-- The floor lies in [w0 * exp(-1 / RARE), w0]. -/
theorem floor_bounded {rare w0 : ℝ} (hr : 0 < rare) (hw0 : 0 < w0) (day : List (ℕ × Bool)) :
    w0 * Real.exp (-1 / rare) ≤ floorW rare w0 day ∧ floorW rare w0 day ≤ w0 := by
  obtain ⟨f0, f1⟩ := freq_mem day
  unfold floorW
  constructor
  · apply mul_le_mul_of_nonneg_left _ hw0.le
    apply Real.exp_le_exp.mpr
    exact div_le_div_of_nonneg_right (by linarith) hr.le
  · have : Real.exp (-freq day / rare) ≤ 1 :=
      Real.exp_le_one_iff.mpr (div_nonpos_of_nonpos_of_nonneg (by linarith) hr.le)
    nlinarith

/-- Sleep keeps a weight in (0, w0] and lifts it to at least w0 * exp(-1 / RARE). -/
theorem sleep_bounded {rare w0 w : ℝ} (hr : 0 < rare) (hw0 : 0 < w0) (hw : 0 < w ∧ w ≤ w0)
    (day : List (ℕ × Bool)) :
    w0 * Real.exp (-1 / rare) ≤ sleepW rare w0 w day ∧
      0 < sleepW rare w0 w day ∧ sleepW rare w0 w day ≤ w0 := by
  obtain ⟨lo, hi⟩ := floor_bounded hr hw0 day
  unfold sleepW
  exact ⟨le_trans lo (le_max_right _ _), lt_of_lt_of_le hw.1 (le_max_left _ _),
    max_le hw.2 hi⟩

/-- Sleep never takes weight away. -/
theorem sleep_never_lowers (rare w0 w : ℝ) (day : List (ℕ × Bool)) : w ≤ sleepW rare w0 w day :=
  le_max_left _ _

/-- What the day taught above the floor stays exactly (the O17 lesson). -/
theorem sleep_keeps_day_learning {rare w0 w : ℝ} {day : List (ℕ × Bool)}
    (h : floorW rare w0 day ≤ w) : sleepW rare w0 w day = w :=
  max_eq_left h

/-- The commoner a pattern was in safe seconds, strictly the lower its floor. -/
theorem floor_strictAnti {rare w0 : ℝ} (hr : 0 < rare) (hw0 : 0 < w0) {d d' : List (ℕ × Bool)}
    (h : freq d < freq d') : floorW rare w0 d' < floorW rare w0 d := by
  unfold floorW
  apply mul_lt_mul_of_pos_left _ hw0
  apply Real.exp_lt_exp.mpr
  exact div_lt_div_of_pos_right (by linarith) hr

/-- So, for the same day weight, the commoner pattern is never restored more. -/
theorem sleep_antitone {rare w0 w : ℝ} (hr : 0 < rare) (hw0 : 0 < w0) {d d' : List (ℕ × Bool)}
    (h : freq d ≤ freq d') : sleepW rare w0 w d' ≤ sleepW rare w0 w d := by
  unfold sleepW
  rcases h.lt_or_eq with hlt | heq
  · exact max_le_max le_rfl (floor_strictAnti hr hw0 hlt).le
  · simp [floorW, heq]

/-- A cell never seen firing in a safe second is restored to its resting weight exactly. -/
theorem sleep_unseen {rare w0 w : ℝ} {day : List (ℕ × Bool)} (h : seenCount day = 0)
    (hw : w ≤ w0) : sleepW rare w0 w day = w0 := by
  simp [sleepW, floorW, freq, h, hw]

/-- A cell active in exactly a RARE fraction of safe seconds has the floor w0 / e. -/
theorem floor_at_rare {rare w0 : ℝ} (hr : rare ≠ 0) {day : List (ℕ × Bool)} (h : freq day = rare) :
    floorW rare w0 day = w0 * Real.exp (-1) := by
  simp [floorW, h, neg_div, div_self hr]

/-- Seconds labelled attack change nothing sleep sees. -/
theorem attack_seconds_ignored (day : List (ℕ × Bool)) (a : ℕ) :
    freq (day ++ [(a, false)]) = freq day := by
  simp [freq, seenCount, safeCount, List.filter_append]

/-- Sleep counts sightings, not spikes: any positive spike count in a second is the same. -/
theorem spikes_count_once (day : List (ℕ × Bool)) {a b : ℕ} (ha : a ≠ 0) (hb : b ≠ 0)
    (safe : Bool) :
    freq (day ++ [(a, safe)]) = freq (day ++ [(b, safe)]) := by
  cases safe <;> simp [freq, seenCount, safeCount, List.filter_append, ha, hb]

/-- One day and its night: learn through the day's seconds, then sleep on that day's counts. -/
noncomputable def dayNight (ρ ηs ηr rare w0 w : ℝ) (day : List (ℕ × Bool)) : ℝ :=
  sleepW rare w0 (day.foldl (fun w s => learn ρ ηs ηr w0 w s.1 s.2) w) day

/-- Any number of days, each followed by a night, keeps every weight in (0, w0]. -/
theorem days_and_nights_bounded {ρ ηs ηr rare w0 : ℝ}
    (hρ : 0 ≤ ρ ∧ ρ ≤ 1) (hs : 0 ≤ ηs ∧ ηs < 1) (hr : 0 ≤ ηr ∧ ηr ≤ 1)
    (hrare : 0 < rare) (hw0 : 0 < w0) (days : List (List (ℕ × Bool))) :
    ∀ w : ℝ, 0 < w ∧ w ≤ w0 →
      0 < days.foldl (dayNight ρ ηs ηr rare w0) w ∧
        days.foldl (dayNight ρ ηs ηr rare w0) w ≤ w0 := by
  induction days with
  | nil => intro w hw; exact hw
  | cons d ds ih =>
    intro w hw
    have hday := train_bounded_from hρ hs hr d w hw
    have hn := sleep_bounded hrare hw0 hday d
    exact ih _ ⟨hn.2.1, hn.2.2⟩

/-! ## The coordinator (`Coordinator::incident` in `cluster.rs`)

One second of the cluster, abstracted from the spikes: which of the five flies fire now (fly 4
is the single fly), who each names, the entities each named when it last fired within
`HORIZON_S`, and which specialists are at `STRONG` times their threshold. -/

/-- The cluster's state in one second; `α` is the type of entities (hosts, users). -/
structure Second (α : Type) where
  now : Fin 5 → Bool
  suspects : Fin 5 → Finset α
  recent : Fin 5 → Finset α
  strong : Fin 5 → Bool

variable {α : Type} [DecidableEq α]

def single : Fin 5 := 4
def specialists : Finset (Fin 5) := {0, 1, 2, 3}

/-- How many flies recently named `e` (`voters.iter().filter(..).count()`). -/
def votes (x : Second α) (e : α) : ℕ := (Finset.univ.filter fun g => e ∈ x.recent g).card

/-- `quorum(&all, from)`: a fly of `from` firing now names an entity that `QUORUM = 2` flies
agree about. Rust takes the best-supported entity (`max_by_key`); some entity reaching the
quorum is the same condition. -/
def quorum (x : Second α) (src : Finset (Fin 5)) : Prop :=
  ∃ f ∈ src, x.now f ∧ ∃ e ∈ x.suspects f, 2 ≤ votes x e

/-- Rule D, incidents. -/
def confirmed (x : Second α) : Prop := quorum x {single}

/-- Rule E, incidents and leads. -/
def confirmedOrStrong (x : Second α) : Prop :=
  confirmed x ∨ quorum x (specialists.filter fun f => x.now f ∧ x.strong f)

/-- Rule B, team or the single fly alone. -/
def teamOrSingle (x : Second α) : Prop := quorum x specialists ∨ x.now single = true

/-- Two different flies recently named the same entity. -/
def corroborated (x : Second α) : Prop :=
  ∃ e g g', g ≠ g' ∧ e ∈ x.recent g ∧ e ∈ x.recent g'

/-- Every incident is also raised by the lead rule, so leads only ever add alerts. -/
theorem incident_is_alert {x : Second α} (h : confirmed x) : confirmedOrStrong x := Or.inl h

lemma quorum_corroborated {x : Second α} {src : Finset (Fin 5)} (h : quorum x src) :
    corroborated x := by
  obtain ⟨_, _, _, e, _, he⟩ := h
  obtain ⟨g, hg, g', hg', hne⟩ :=
    Finset.one_lt_card.mp (show 1 < (Finset.univ.filter fun g => e ∈ x.recent g).card by
      unfold votes at he; omega)
  simp only [Finset.mem_filter, Finset.mem_univ, true_and] at hg hg'
  exact ⟨e, g, g', hne, hg, hg'⟩

/-- No single fly can raise an incident or a lead on its own: rule E (and so rule D) alerts only
about an entity two different flies named. -/
theorem alert_corroborated {x : Second α} (h : confirmedOrStrong x) : corroborated x := by
  rcases h with h | h <;> exact quorum_corroborated h

/-- Rule B does not have that property: the single fly alone raises it. -/
theorem teamOrSingle_uncorroborated :
    ∃ x : Second ℕ, teamOrSingle x ∧ ¬ corroborated x := by
  refine ⟨⟨fun f => f == single, fun _ => ∅, fun _ => ∅, fun _ => false⟩,
    Or.inr rfl, ?_⟩
  rintro ⟨e, g, g', -, h, -⟩
  simp at h

/-- A lead that is not an incident has a specialist at `STRONG` times its threshold firing. -/
theorem lead_has_strong_specialist {x : Second α} (h : confirmedOrStrong x) (hn : ¬ confirmed x) :
    ∃ f ∈ specialists, x.now f ∧ x.strong f := by
  rcases h with h | ⟨f, hf, -⟩
  · exact absurd h hn
  · simp only [Finset.mem_filter] at hf
    exact ⟨f, hf.1, hf.2.1, hf.2.2⟩

end FlySOC
