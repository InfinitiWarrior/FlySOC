"""Entity-aware scoring of FlySOC's JSON alerts (ISSUES M10): what an analyst's queue would hold.

The scorecard counts an episode as alerted when any alert fires during it, about anything. Here
alerts are grouped into alert episodes (same entity, less than GAP_S apart), and each is
attributed by the entity it names: to an intrusion if the entity takes part in one at that time
(as src, dst, host or user of one of its events), else to a look-alike, else to nothing (a false
alert). The synthetic network has 5 servers, so a scan or an admin session often shares a server
with an intrusion running at the same time; such an alert is about the intrusion.

Run: flysoc cluster <train> <file> > alerts.jsonl, then
     python3 tools/attribution.py <file> <alerts.jsonl> [<file> <alerts.jsonl> ...]
"""
import json, statistics, sys
from collections import Counter, defaultdict

TAIL_S = 60  # cluster.rs: an alert this long after an episode's last event still belongs to it
GAP_S = 60  # alerts about one entity less than this apart are one alert in the queue


def episodes(path):
    ep = defaultdict(lambda: [1e18, 0, set()])  # label id -> first s, last s, entities
    for line in open(path):
        e = json.loads(line)
        lab = e.get("label", "benign")
        if lab == "benign":
            continue
        x = ep[lab.rsplit(":", 1)[0] if lab.startswith("intrusion") else lab]
        x[0], x[1] = min(x[0], int(e["ts"])), max(x[1], int(e["ts"]))
        x[2] |= {e[k] for k in ("src", "dst", "host", "user") if k in e}
    return ep


def main(pairs):
    for tiers, name in (({"incident"}, "incidents (rule D)"), ({"incident", "lead"}, "incidents + leads (rule E)")):
        queue, caught, intrusions, delays = Counter(), set(), 0, []
        for data, alerts in pairs:
            ep = episodes(data)
            intrusions += sum(lab.startswith("intrusion") for lab in ep)
            last = {}
            for line in open(alerts):
                x = json.loads(line)
                if x["kind"] not in tiers:
                    continue
                s, ent = x["ts_start"], x["entity"]
                about = [lab for lab, (a, b, e) in ep.items() if a <= s <= b + TAIL_S and ent in e]
                intr = [lab for lab in about if lab.startswith("intrusion")]
                for lab in intr:
                    if (data, lab) not in caught:
                        caught.add((data, lab))
                        delays.append(s - ep[lab][0])
                new = s - last.get(ent, -1e9) >= GAP_S
                last[ent] = s
                if new:
                    queue["intrusion" if intr else about[0].split("@")[0] if about else "nothing labelled"] += 1
        total = sum(queue.values())
        print(f"== {name}: {total} alerts in the queue, {queue['intrusion']} about an intrusion "
              f"(precision {queue['intrusion'] / max(total, 1):.0%}); intrusions caught {len(caught)}/{intrusions}, "
              f"median first alert " + (f"+{statistics.median(delays):.0f} s" if delays else "none"))
        for k, v in queue.most_common():
            if k != "intrusion":
                print(f"   {k:18} {v}")


if __name__ == "__main__":
    a = sys.argv[1:]
    main(list(zip(a[::2], a[1::2])))
