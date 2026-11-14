"""Synthetic multi-domain telemetry with a multi-stage intrusion and benign look-alikes.

Run: python3 tools/gen_intrusion.py
Writes data/telemetry/cluster_{baseline,train,test,holdout}.jsonl. Every event has a `kind`:
  conn  src dst dport          network
  auth  user src dst result    identity (result: ok | fail)
  proc  host process parent    endpoint
  dns   host query             DNS

An intrusion (labels "intrusion@T:<stage>") is four quiet stages a few minutes apart, all from one
compromised workstation. No single stage is loud:
  recon    40 ports of one server over 120 s (0.33 conn/s)
  spray    one failed login for each of 15 users on that server, then one success
  lateral  the sprayed account logs into two servers it never used and runs commands via psexec
  exfil    200 DNS queries for long random subdomains of one domain over 120 s

Each stage has a benign look-alike (labels "benign_<what>@T"):
  benign_vulnscan  the authorised scanner sweeps 40 ports (it does so in training too)
  benign_mistype   a user fails 6 logins, then succeeds
  benign_admin     the admin logs into 3 servers and runs psexec there
  benign_newsites  a workstation looks up 60 never-seen domains in a minute
  benign_backup    one workstation hammers SMB at 100 conn/s (the Phase 2 burst)
`label` is ground truth for scoring and is never encoded.
"""
import json, os, random

WS = [f"10.0.0.{i}" for i in range(1, 21)]
SRV = [f"10.0.1.{i}" for i in range(1, 6)]
ADMIN_WS, SCANNER = "10.0.0.20", "10.0.1.9"
USERS = [f"u{i:02d}" for i in range(1, 20)] + ["adm"]
HOME = dict(zip(USERS, WS))  # each user's own workstation
PORTS = {443: .5, 80: .15, 53: .15, 445: .1, 22: .05, 3389: .05}
PROCS = {"chrome.exe": ("explorer.exe", .4), "outlook.exe": ("explorer.exe", .2), "teams.exe": ("explorer.exe", .2),
         "svchost.exe": ("services.exe", .15), "powershell.exe": ("explorer.exe", .05)}
SRV_PROCS = {"w3wp.exe": "svchost.exe", "sqlservr.exe": "services.exe", "svchost.exe": "services.exe"}
SITES = [f"{w}.com" for w in "mail news docs wiki intranet jira git chat search maps cloud office video".split()]
CDN = [f"edge-{i:02d}.cdn-example.net" for i in range(30)]


def poisson(rng, rate, start, end):
    t = start + rng.expovariate(rate)
    while t < end:
        yield t
        t += rng.expovariate(rate)


def background(rng, start, end):
    """Steady benign traffic in all four domains."""
    ev = []
    usual_srv = {u: rng.sample(SRV, 2) for u in USERS}
    for h in WS:
        for t in poisson(rng, 1.0, start, end):
            port = rng.choices(list(PORTS), list(PORTS.values()))[0]
            ev.append(dict(ts=t, kind="conn", src=h, dst=rng.choice(SRV), dport=port))
        for t in poisson(rng, 0.3, start, end):
            p = rng.choices(list(PROCS), [v[1] for v in PROCS.values()])[0]
            ev.append(dict(ts=t, kind="proc", host=h, process=p, parent=PROCS[p][0]))
        for t in poisson(rng, 0.5, start, end):
            q = rng.choice(SITES) if rng.random() < .6 else rng.choice(CDN)
            ev.append(dict(ts=t, kind="dns", host=h, query=q))
    for s in SRV:
        for t in poisson(rng, 0.5, start, end):
            p = rng.choice(list(SRV_PROCS))
            ev.append(dict(ts=t, kind="proc", host=s, process=p, parent=SRV_PROCS[p]))
    for u in USERS:
        for t in poisson(rng, 0.03, start, end):
            dst = rng.choice([HOME[u]] + usual_srv[u])
            if rng.random() < .03:  # occasional single typo
                ev.append(dict(ts=t, kind="auth", user=u, src=HOME[u], dst=dst, result="fail"))
                t += 3
            ev.append(dict(ts=t, kind="auth", user=u, src=HOME[u], dst=dst, result="ok"))
    for e in ev:
        e["label"] = "benign"
    return ev, usual_srv


def spread(start, seconds, items, make):
    return [make(start + k * seconds / len(items), x) for k, x in enumerate(items)]


def intrusion(rng, T, usual_srv):
    """Four stages from one compromised workstation, ~2 min apart."""
    atk, target = rng.choice(WS[:19]), rng.choice(SRV)
    victim = rng.choice(USERS[:19])
    others = [s for s in SRV if s != target and s not in usual_srv[victim]][:2] or [s for s in SRV if s != target][:2]
    ports = rng.sample(range(1, 1024), 40)
    lab = lambda stage: f"intrusion@{T}:{stage}"
    ev = spread(T, 120, ports, lambda t, p: dict(ts=t, kind="conn", src=atk, dst=target, dport=p, label=lab("recon")))
    users = rng.sample([u for u in USERS[:19] if u != victim], 14) + [victim]
    ev += spread(T + 240, 60, users, lambda t, u: dict(ts=t, kind="auth", user=u, src=atk, dst=target,
                                                       result="fail", label=lab("spray")))
    ev.append(dict(ts=T + 302, kind="auth", user=victim, src=atk, dst=target, result="ok", label=lab("spray")))
    t = T + 420
    for s in others:
        ev.append(dict(ts=t, kind="auth", user=victim, src=target, dst=s, result="ok", label=lab("lateral")))
        for k, (p, parent) in enumerate([("psexesvc.exe", "services.exe"), ("cmd.exe", "psexesvc.exe"),
                                         ("whoami.exe", "cmd.exe"), ("net.exe", "cmd.exe")]):
            ev.append(dict(ts=t + 2 + 3 * k, kind="proc", host=s, process=p, parent=parent, label=lab("lateral")))
        t += 40
    names = ["".join(rng.choice("0123456789abcdef") for _ in range(30)) + ".sync-telemetry.io" for _ in range(200)]
    ev += spread(T + 600, 120, names, lambda t, q: dict(ts=t, kind="dns", host=others[-1], query=q, label=lab("exfil")))
    return ev, T + 720


def lookalike(rng, what, T):
    lab = f"benign_{what}@{T}"
    if what == "vulnscan":
        return spread(T, 120, rng.sample(range(1, 1024), 40),
                      lambda t, p: dict(ts=t, kind="conn", src=SCANNER, dst=rng.choice(SRV), dport=p, label=lab))
    if what == "mistype":
        u = rng.choice(USERS[:19])
        ev = [dict(ts=T + 5 * k, kind="auth", user=u, src=HOME[u], dst=HOME[u], result="fail", label=lab) for k in range(6)]
        return ev + [dict(ts=T + 31, kind="auth", user=u, src=HOME[u], dst=HOME[u], result="ok", label=lab)]
    if what == "admin":
        ev = []
        for k, s in enumerate(rng.sample(SRV, 3)):
            t = T + 60 * k
            ev.append(dict(ts=t, kind="auth", user="adm", src=ADMIN_WS, dst=s, result="ok", label=lab))
            ev += [dict(ts=t + 2, kind="proc", host=s, process="psexesvc.exe", parent="services.exe", label=lab),
                   dict(ts=t + 5, kind="proc", host=s, process="cmd.exe", parent="psexesvc.exe", label=lab)]
        return ev
    if what == "newsites":
        h = rng.choice(WS)
        sites = [f"{rng.choice('abcdefghijklmnop')}{rng.randrange(10**6)}-shop.com" for _ in range(60)]
        return spread(T, 60, sites, lambda t, q: dict(ts=t, kind="dns", host=h, query=q, label=lab))
    if what == "backup":
        return spread(T, 10, [445] * 1000, lambda t, p: dict(ts=t, kind="conn", src="10.0.0.7", dst="10.0.1.3", dport=p, label=lab))
    raise ValueError(what)


def scenario(seed, seconds, intrusions, lookalikes):
    rng = random.Random(seed)
    ev, usual = background(rng, 0, seconds)
    for T in intrusions:
        ev += intrusion(rng, T, usual)[0]
    for what, T in lookalikes:
        ev += lookalike(rng, what, T)
    return ev


def write(path, events):
    with open(path, "w") as f:
        for e in sorted(events, key=lambda e: e["ts"]):
            e["ts"] = round(e["ts"], 3)
            f.write(json.dumps(e) + "\n")
    print(f"{path}: {len(events)} events")


ALL = ["vulnscan", "mistype", "admin", "newsites", "backup"]


def random_times(rng):
    """Two intrusions (720 s each, non-overlapping) and each look-alike twice, at random times."""
    a = rng.randrange(50, 800)
    b = rng.randrange(a + 760, 1650)
    looks = [(w, rng.randrange(50, 2280)) for w in ALL for _ in range(2)]
    return [a, b], looks


if __name__ == "__main__":
    os.makedirs("data/telemetry", exist_ok=True)
    write("data/telemetry/cluster_baseline.jsonl", scenario(10, 300, [], []))
    write("data/telemetry/cluster_train.jsonl",
          scenario(11, 2400, [100, 1300], [(w, 900 + 60 * k) for k, w in enumerate(ALL)] + [(w, 2100 - 50 * k) for k, w in enumerate(ALL)]))
    write("data/telemetry/cluster_test.jsonl",
          scenario(12, 2400, [200, 1500], [(w, 1000 + 70 * k) for k, w in enumerate(ALL)] + [(w, 2300 - 60 * k) for k, w in enumerate(ALL)]))
    # Never used for tuning: report final numbers on these only.
    write("data/telemetry/cluster_holdout.jsonl",
          scenario(13, 2400, [400, 1700], [(w, 100 + 55 * k) for k, w in enumerate(ALL)] + [(w, 1200 + 65 * k) for k, w in enumerate(ALL)]))


    # Two sets of 5 seeds with random timings, 10 intrusions and 50 look-alikes each. One file of
    # 2 intrusions and 10 look-alikes is too small to tell coordinator rules apart.
    # cluster_eval_*: for choosing between options. cluster_final_*: never used for choosing; report these.
    for name, seeds in [("eval", range(21, 26)), ("final", range(31, 36))]:
        for seed in seeds:
            intrusions, looks = random_times(random.Random(seed * 7919))
            write(f"data/telemetry/cluster_{name}_{seed}.jsonl", scenario(seed, 2400, intrusions, looks))
