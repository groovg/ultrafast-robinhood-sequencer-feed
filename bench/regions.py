"""Compare when the same feed messages arrived in different places.

    python bench/regions.py us-east-2=a.tsv us-east-1=b.tsv eu-central-1=c.tsv

Each file has one line per message, "seq<TAB>received_at", from
`rhfeed --json ... | jq -r '[.seq,.received_at]|@tsv'`. The machines' clocks must be
in sync (on EC2, Amazon Time Sync keeps them within tens of microseconds). For every
sequence number seen everywhere, it takes how much later each place got it than the
first place did.
"""

import statistics
import sys


def load(path):
    out = {}
    for line in open(path):
        seq, at = line.split()
        out[int(seq)] = float(at)
    return out


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, int(p / 100 * len(values)))]


def main():
    places = dict(arg.split("=", 1) for arg in sys.argv[1:])
    arrivals = {name: load(path) for name, path in places.items()}
    common = set.intersection(*(set(a) for a in arrivals.values()))
    print(f"{len(common)} messages seen in all {len(places)} places\n")
    print(f"{'place':<16}{'first':>8}{'median behind':>16}{'p90':>10}{'p99':>10}")
    for name, a in arrivals.items():
        behind = [(a[s] - min(x[s] for x in arrivals.values())) * 1e3 for s in common]
        first = sum(1 for b in behind if b == 0) / len(behind) * 100
        print(
            f"{name:<16}{first:>7.1f}%{statistics.median(behind):>13.2f} ms"
            f"{pct(behind, 90):>7.2f} ms{pct(behind, 99):>7.2f} ms"
        )
    names = list(arrivals)
    print("\npairwise, median of (row - column), ms")
    print(" " * 16 + "".join(f"{n:>16}" for n in names))
    for r in names:
        cells = [statistics.median(arrivals[r][s] - arrivals[c][s] for s in common) * 1e3 for c in names]
        print(f"{r:<16}" + "".join(f"{v:>16.2f}" for v in cells))


if __name__ == "__main__":
    main()
