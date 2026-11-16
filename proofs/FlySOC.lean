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
