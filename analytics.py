"""Secure multi-party aggregation (sum / mean / variance) built on secret sharing."""
from fractions import Fraction
import math
import numpy as np
import secret_sharing as ss
import security as sec

STATS = ("count", "sum", "sumsq")


def party_values_from_df(df, party_col, value_col):
    d = df[[party_col, value_col]].dropna()
    return {str(k): g[value_col].astype(float).tolist() for k, g in d.groupby(party_col)}


def local_stats(values):
    """Each party computes these locally on its own raw data (fixed-point ints)."""
    xi = [ss.to_int(v) for v in values]
    return {"count": len(xi), "sum": sum(xi), "sumsq": sum(x * x for x in xi)}


def plaintext_stats(party_values):
    allv = np.array([v for vals in party_values.values() for v in vals], dtype=float)
    return {"count": int(allv.size), "sum": float(allv.sum()), "mean": float(allv.mean()),
            "variance": float(allv.var()), "std": float(allv.std())}


def finalize(count, s, q):
    """Turn reconstructed totals (scaled integers) into real statistics."""
    mean_scaled = Fraction(s, count)
    var_scaled = Fraction(q, count) - mean_scaled ** 2
    S = ss.SCALE
    mean = float(mean_scaled / S)
    var = float(var_scaled / (S * S))
    return {"count": count, "sum": s / S, "mean": mean, "variance": var, "std": math.sqrt(max(var, 0))}


def secure_aggregate(party_values, n_nodes=3, mode="additive", t=2,
                     tamper=None, available_nodes=None):
    """Run the protocol.

    party_values    : {party: [floats]}  (stays private to each party)
    mode            : 'additive' (n-of-n) or 'shamir' (t-of-n)
    tamper          : (party, stat, node) -> flip that share in transit
    available_nodes : list of node ids (1..n) still online (Shamir only)
    Returns dict with results and a full trace for display/analysis.
    """
    parties = list(party_values)
    keys = sec.make_party_keys(parties)
    nodes = list(range(1, n_nodes + 1))
    inbox = {j: {s: [] for s in STATS} for j in nodes}      # what node j receives
    trace = {}
    rejected = set()

    for p in parties:
        stats = local_stats(party_values[p])
        trace[p] = {"local": stats, "shares": {}}
        for s in STATS:
            secret = ss.to_field(stats[s])
            if mode == "additive":
                shares = ss.additive_split(secret, n_nodes)
            else:
                shares = [y for _, y in ss.shamir_split(secret, n_nodes, t)]
            trace[p]["shares"][s] = shares
            for j, sh in zip(nodes, shares):
                tag = sec.share_tag(keys[p], p, s, j, sh)           # sender tags
                sent = sh
                if tamper and tamper == (p, s, j):                   # attacker flips share
                    sent = (sh + 1) % ss.PRIME
                if sec.verify_tag(keys[p], p, s, j, sent, tag):      # node verifies
                    inbox[j][s].append(sent)
                else:
                    rejected.add(j)
                    inbox[j][s].append(None)

    if mode == "additive" and rejected:
        raise sec.IntegrityError(f"Share rejected at node(s) {sorted(rejected)}: HMAC mismatch")

    # each node adds the shares it received (local, no communication needed)
    node_totals = {j: {s: (None if j in rejected else sum(inbox[j][s]) % ss.PRIME) for s in STATS}
                   for j in nodes}

    usable = [j for j in (available_nodes or nodes) if j not in rejected]
    totals = {}
    for s in STATS:
        if mode == "additive":
            if len(usable) < n_nodes:
                raise ValueError("Additive sharing needs all nodes online")
            totals[s] = ss.from_field(ss.additive_combine([node_totals[j][s] for j in nodes]))
        else:
            if len(usable) < t:
                raise ValueError(f"Only {len(usable)} nodes usable; threshold is {t}")
            pts = [(j, node_totals[j][s]) for j in usable[:t]]
            totals[s] = ss.from_field(ss.shamir_combine(pts))

    res = finalize(totals["count"], totals["sum"], totals["sumsq"])
    return {"results": res, "node_totals": node_totals, "trace": trace,
            "rejected_nodes": sorted(rejected), "usable_nodes": usable,
            "mode": mode, "n": n_nodes, "t": t}


# ---------- security experiments ----------
def uniformity_test(secret=123456, n=3, trials=6000, bins=20):
    """Share the SAME secret many times; a single share should look uniform."""
    first = [ss.additive_split(ss.to_field(secret), n)[0] / ss.PRIME for _ in range(trials)]
    counts, _ = np.histogram(first, bins=bins, range=(0, 1))
    expected = trials / bins
    chi2 = float(((counts - expected) ** 2 / expected).sum())
    crit = {10: 27.88, 20: 43.82}.get(bins, None)       # chi-square critical value at 0.1% (df = bins-1)
    return {"counts": counts.tolist(), "chi2": chi2, "critical": crit,
            "looks_uniform": (chi2 < crit) if crit else None}


def threshold_test(secret=987654, n=5, t=3):
    pts = ss.shamir_split(ss.to_field(secret), n, t)
    ok = ss.from_field(ss.shamir_combine(pts[:t]))
    other = ss.from_field(ss.shamir_combine(pts[n - t:]))
    short = ss.from_field(ss.shamir_combine(pts[:t - 1]))
    return {"secret": secret, "with_t_shares": ok, "other_t_subset": other,
            "with_t_minus_1": short, "t_minus_1_correct": short == secret}
