"""Phase 4, red team: evolve the intrusion of tools/gen_intrusion.py to get further before the cluster
raises an incident, within limits that keep every stage doing its real job.

Run: python3 tools/red.py evolve <train.jsonl> <out_dir> [generations] [population]
     python3 tools/red.py harden <train.jsonl> <out_dir> [k]   (see the bottom of this file)
Needs a release build (target/release/flysoc, or the binary in FLYSOC_BIN). Each candidate intrusion is played into fresh
background traffic and scored by `flysoc cluster` with the default rule (D, confirmed).

Genome (ATT&CK technique each stage stays faithful to):
  recon    T1046      ports to scan (>= 10, else it learns nothing) over recon_s seconds
  spray    T1110.003  accounts to try (>= 5) over spray_s seconds, then the victim's success
  lateral  T1021.002 + T1569.002  psexec into 1-3 servers the victim never used, lateral_gap_s apart
  exfil    T1048      a fixed 6000 hex chars of data in DNS labels of label_len chars, over exfil_s
  gap_s    seconds between stages
Red's score is progress through the kill chain: per stage, the share of its events that happened
before the first incident, averaged over the four stages (1.0 = never caught; 0.5 = caught as
lateral movement began). Counting events instead would let exfil's many queries dominate.
"""
import json, os, random, re, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_intrusion import SRV, USERS, WS, background, spread, write  # noqa: E402

PAYLOAD = 6000  # hex chars to exfiltrate
BOUNDS = dict(ports=(10, 100), recon_s=(30, 1800), users=(5, 19), spray_s=(30, 1800), servers=(1, 3),
              lateral_gap_s=(10, 600), label_len=(10, 60), exfil_s=(60, 1800), gap_s=(30, 600))
INTS = {"ports", "users", "servers", "label_len"}
START = 100  # the intrusion starts this long into its file
BACKGROUNDS = 3  # fresh background traffic per candidate per generation
PARALLEL = 4  # flysoc processes at once: the GPU is bound by launches, not throughput
BIN = os.environ.get("FLYSOC_BIN", "./target/release/flysoc")  # e.g. a copy built with another encoding


def baseline():
    """The gen_intrusion.py intrusion as a genome."""
    return dict(ports=40, recon_s=120, users=15, spray_s=60, servers=2, lateral_gap_s=40, label_len=30, exfil_s=120, gap_s=120)


def clamp(g):
    return {k: (round if k in INTS else float)(min(max(v, BOUNDS[k][0]), BOUNDS[k][1])) for k, v in g.items()}


def mutate(rng, g):
    g = dict(g)
    for k in rng.sample(list(BOUNDS), rng.randint(1, 3)):
        lo, hi = BOUNDS[k]
        g[k] = g[k] * rng.uniform(0.5, 2.0) if rng.random() < .7 else rng.uniform(lo, hi)
    return clamp(g)


def intrusion(rng, g, T, usual_srv):
    """The four stages, laid out by the genome. For baseline() this is gen_intrusion.intrusion's
    attack, with stages starting a few seconds later (each gap counts from the previous stage's end)."""
    atk, target, victim = rng.choice(WS[:19]), rng.choice(SRV), rng.choice(USERS[:19])
    others = [s for s in SRV if s != target and s not in usual_srv[victim]] or [s for s in SRV if s != target]
    lab = lambda stage: f"intrusion@{T}:{stage}"
    t = T
    ev = spread(t, g["recon_s"], rng.sample(range(1, 1024), g["ports"]),
                lambda t, p: dict(ts=t, kind="conn", src=atk, dst=target, dport=p, label=lab("recon")))
    t += g["recon_s"] + g["gap_s"]
    users = rng.sample([u for u in USERS[:19] if u != victim], g["users"] - 1) + [victim]
    ev += spread(t, g["spray_s"], users, lambda t, u: dict(ts=t, kind="auth", user=u, src=atk, dst=target, result="fail", label=lab("spray")))
    t += g["spray_s"] + 2
    ev.append(dict(ts=t, kind="auth", user=victim, src=atk, dst=target, result="ok", label=lab("spray")))
    t += g["gap_s"]
    for s in others[:g["servers"]]:
        ev.append(dict(ts=t, kind="auth", user=victim, src=target, dst=s, result="ok", label=lab("lateral")))
        for k, (p, parent) in enumerate([("psexesvc.exe", "services.exe"), ("cmd.exe", "psexesvc.exe"),
                                         ("whoami.exe", "cmd.exe"), ("net.exe", "cmd.exe")]):
            ev.append(dict(ts=t + 2 + 3 * k, kind="proc", host=s, process=p, parent=parent, label=lab("lateral")))
        t += g["lateral_gap_s"]
    t += g["gap_s"]
    n = -(-PAYLOAD // g["label_len"])
    names = ["".join(rng.choice("0123456789abcdef") for _ in range(g["label_len"])) + ".sync-telemetry.io" for _ in range(n)]
    ev += spread(t, g["exfil_s"], names, lambda t, q: dict(ts=t, kind="dns", host=others[:g["servers"]][-1], query=q, label=lab("exfil")))
    return ev


def scenario(g, seed):
    """Fresh background with one intrusion; returns (events, intrusion events)."""
    rng = random.Random(seed)
    length = START + g["recon_s"] + g["spray_s"] + 3 * g["gap_s"] + 3 * g["lateral_gap_s"] + g["exfil_s"] + 200
    bg, usual = background(rng, 0, length)
    atk = intrusion(rng, g, START, usual)
    return bg + atk, atk


def first_alert(train, path, rule="cluster D confirmed"):
    """Seconds from the intrusion's start to the rule's first incident, or None if never."""
    r = subprocess.run([BIN, "cluster", train, path], capture_output=True, text=True)
    for line in r.stderr.splitlines():
        if line.strip().startswith(rule):
            m = re.search(r"(\d+)/1 \(([^)]*)\)", line)
            return int(m[2].strip("+s")) if m and m[1] == "1" else None
    raise RuntimeError(f"no scorecard from flysoc:\n{r.stderr[-2000:]}")


def progress(train, g, seed, workdir):
    """Kill-chain progress before the first incident (1.0 = undetected), and that delay."""
    events, atk = scenario(g, seed)
    path = f"{workdir}/cand_{seed}_{abs(hash(json.dumps(g, sort_keys=True))) % 10**8}.jsonl"
    with open(path, "w") as f:
        for e in sorted(events, key=lambda e: e["ts"]):
            f.write(json.dumps(dict(e, ts=round(e["ts"], 3))) + "\n")
    d = first_alert(train, path)
    os.remove(path)
    if d is None:
        return 1.0, None
    stages = {e["label"].split(":")[-1] for e in atk}
    done = lambda st: [e["ts"] < START + d for e in atk if e["label"].endswith(":" + st)]
    return sum(sum(done(st)) / len(done(st)) for st in stages) / len(stages), d


def evolve(train, out, generations=6, population=8, seed=0):
    """(mu + lambda) evolution: keep the best half, refill with mutants. Every generation plays all
    candidates on the same BACKGROUNDS fresh background seeds and scores the mean, so they compete on
    equal terms and one lucky background cannot make a winner (ISSUES M10)."""
    rng = random.Random(seed)
    os.makedirs(out, exist_ok=True)
    # flysoc trains and caches the blue team on first use; do that once before going parallel
    progress(train, baseline(), 999, out)
    pop = [baseline()] + [mutate(rng, baseline()) for _ in range(population - 1)]
    log = []
    for gen in range(generations):
        seeds = [1000 * (seed + 1) + 100 * gen + b for b in range(BACKGROUNDS)]
        with ThreadPoolExecutor(PARALLEL) as ex:
            runs = list(ex.map(lambda j: progress(train, pop[j[0]], j[1], out), [(i, s) for i in range(len(pop)) for s in seeds]))
        mean = lambda xs: sum(xs) / len(xs)
        scores = [(mean([r[0] for r in runs[i * BACKGROUNDS:(i + 1) * BACKGROUNDS]]),
                   [r[1] for r in runs[i * BACKGROUNDS:(i + 1) * BACKGROUNDS]]) for i in range(len(pop))]
        ranked = sorted(zip(scores, pop), key=lambda x: -x[0][0])
        for (p, d), g in ranked:
            log.append(dict(gen=gen, progress=p, first_alert=d, genome=g))
        best = ranked[0]
        print(f"gen {gen}: best progress {best[0][0]:.2f} (first alert {best[0][1]}), median "
              f"{sorted(s[0] for s in scores)[len(scores) // 2]:.2f}  {best[1]}", flush=True)
        keep = [g for _, g in ranked[: population // 2]]
        pop = keep + [mutate(rng, rng.choice(keep)) for _ in range(population - len(keep))]
    with open(f"{out}/log.jsonl", "w") as f:
        f.writelines(json.dumps(x) + "\n" for x in log)
    return log


def harden(train, genomes, out, seed=5000):
    """Blue's answer: the training file, then each of red's intrusions in its own fresh background
    after it, labelled as intrusions. Writes and returns the new training file's path."""
    events = [json.loads(line) for line in open(train)]
    t0 = max(e["ts"] for e in events) + 1
    for k, g in enumerate(genomes):
        ev, _ = scenario(g, seed + k)
        events += [dict(e, ts=e["ts"] + t0, label=e["label"].replace(f"@{START}", f"@{int(START + t0)}")) for e in ev]
        t0 += max(e["ts"] for e in ev) + 1
    path = f"{out}/train_hardened.jsonl"
    write(path, events)
    return path


def best(out, k):
    """Red's k best distinct genomes from an evolve run's log."""
    log = sorted((json.loads(line) for line in open(f"{out}/log.jsonl")), key=lambda x: -x["progress"])
    seen, top = set(), []
    for x in log:
        key = json.dumps(x["genome"], sort_keys=True)
        if key not in seen:
            seen.add(key)
            top.append(x["genome"])
    return top[:k]


def duel(trains, genomes, seeds, out):
    """Mean progress of each genome over fresh backgrounds, against each blue training file."""
    for train in trains:
        progress(train, genomes[0], seeds[0], out)  # train and cache this blue once, before going parallel
        jobs = [(g, s) for g in genomes for s in seeds]
        with ThreadPoolExecutor(PARALLEL) as ex:
            res = list(ex.map(lambda j: progress(train, j[0], j[1], out)[0], jobs))
        per = [sum(res[i * len(seeds):(i + 1) * len(seeds)]) / len(seeds) for i in range(len(genomes))]
        caught = sum(r < 1.0 for r in res)
        print(f"{train}: red progress per genome {[round(p, 2) for p in per]}, caught {caught}/{len(res)}", flush=True)


if __name__ == "__main__":
    # evolve <train> <out> [generations] [population]   red evolves against blue trained on <train>
    # harden <train> <out> [k]                           blue retrains on red's k best from <out>,
    #                                                    then both blues face them on fresh backgrounds
    cmd, train, out = sys.argv[1:4]
    if cmd == "evolve":
        evolve(train, out, *(int(a) for a in sys.argv[4:6]))
    elif cmd == "harden":
        k = int(sys.argv[4]) if len(sys.argv) > 4 else 3
        top = best(out, k)
        hardened = harden(train, top, out)
        duel([train, hardened], top + [baseline()], [7001, 7002, 7003], out)
