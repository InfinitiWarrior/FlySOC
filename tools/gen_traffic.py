"""Synthetic connection logs, one JSON object per line, sorted by time.

Run: python3 tools/gen_traffic.py
Writes data/telemetry/baseline.jsonl (120 s, benign only), data/telemetry/train.jsonl (600 s,
different seed and incident times, for learning) and data/telemetry/test.jsonl (600 s of benign
traffic) with 10 s incidents, labelled by type and start second. holdout.jsonl is a third seed
with other incident times, kept out of all tuning:
  portscan@60, @180, @300, @420, @540        100 conn/s from one host to 1000 different ports
  benign_burst@120, @240, @360, @480         100 conn/s from one host to one SMB port (backup)
The burst has the same event rate as the scan, so volume alone cannot tell them apart.
Also writes data/telemetry/benign_long.jsonl (600 s, benign only) for an honest false alert rate:
incidents every minute keep resetting the fly, so test.jsonl alone flatters it.
`label` is ground truth for scoring and is never encoded.
"""
import json, os, random

PORTS = {443: .5, 80: .15, 53: .15, 445: .1, 22: .05, 3389: .05}
HOSTS = [f"10.0.0.{i}" for i in range(1, 21)]
SERVERS = [f"10.0.1.{i}" for i in range(1, 6)]


def benign(rng, seconds, rate_per_host=1.0):
    for src in HOSTS:
        t = rng.expovariate(rate_per_host)
        while t < seconds:
            port = rng.choices(list(PORTS), list(PORTS.values()))[0]
            yield dict(ts=round(t, 4), src=src, dst=rng.choice(SERVERS), dport=port, label="benign")
            t += rng.expovariate(rate_per_host)


def steady(start, seconds, rate, src, dst, ports, label):
    return [dict(ts=round(start + k / rate, 4), src=src, dst=dst, dport=p, label=label)
            for k, p in enumerate(ports[:int(seconds * rate)])]


def write(path, events):
    with open(path, "w") as f:
        for e in sorted(events, key=lambda e: e["ts"]):
            f.write(json.dumps(e) + "\n")
    print(f"{path}: {len(events)} events")


os.makedirs("data/telemetry", exist_ok=True)
write("data/telemetry/baseline.jsonl", list(benign(random.Random(1), 120)))
def incidents(seed, scans, bursts):
    rng = random.Random(seed)
    events = list(benign(rng, 600))
    for t in bursts:
        events += steady(t, 10, 100, "10.0.0.7", "10.0.1.3", [445] * 1000, f"benign_burst@{t}")
    for t in scans:
        ports = list(range(1, 1001))
        rng.shuffle(ports)
        events += steady(t, 10, 100, "10.0.0.66", "10.0.1.2", ports, f"portscan@{t}")
    return events


write("data/telemetry/train.jsonl", incidents(5, scans=(30, 150, 270, 390, 510), bursts=(90, 210, 330, 450)))
write("data/telemetry/test.jsonl", incidents(2, scans=(60, 180, 300, 420, 540), bursts=(120, 240, 360, 480)))
# Never used for tuning: report final numbers on this one only.
write("data/telemetry/holdout.jsonl", incidents(7, scans=(45, 200, 330, 470), bursts=(100, 260, 400, 530)))
write("data/telemetry/benign_long.jsonl", list(benign(random.Random(3), 600)))
