"""Automated tests + experiment runner. Writes output/test_results.json"""
import json, time
import pandas as pd
import analytics as a, secret_sharing as ss, security as sec

df = pd.read_csv("data/sample_dataset.csv")
out = {"dataset": {"rows": len(df), "columns": list(df.columns), "parties": df.hospital.nunique()}}
checks = []
def check(name, cond, detail=""):
    checks.append({"test": name, "passed": bool(cond), "detail": detail}); print(("PASS " if cond else "FAIL ") + name, detail)

# correctness on every numeric column, both modes
corr = []
for col in ["age", "cholesterol", "systolic_bp"]:
    pv = a.party_values_from_df(df, "hospital", col); pt = a.plaintext_stats(pv)
    for mode, n, t in [("additive", 3, 2), ("shamir", 5, 3)]:
        t0 = time.perf_counter(); r = a.secure_aggregate(pv, n, mode, t); dt = (time.perf_counter() - t0) * 1000
        err = {k: abs(r["results"][k] - pt[k]) for k in ("sum", "mean", "variance", "std")}
        corr.append({"column": col, "mode": mode, "secure_mean": r["results"]["mean"], "plain_mean": pt["mean"],
                     "secure_var": r["results"]["variance"], "plain_var": pt["variance"],
                     "max_abs_err": max(err.values()), "ms": round(dt, 1)})
        check(f"Secure == plaintext [{col}, {mode}]", max(err.values()) < 1e-6, f"max err {max(err.values()):.2e}")
out["correctness"] = corr

# threshold / dropout
pv = a.party_values_from_df(df, "hospital", "cholesterol"); pt = a.plaintext_stats(pv)
r = a.secure_aggregate(pv, 5, "shamir", 3, available_nodes=[2, 4, 5])
check("Shamir 3-of-5 works with 2 nodes offline", abs(r["results"]["mean"] - pt["mean"]) < 1e-6)
try: a.secure_aggregate(pv, 5, "shamir", 3, available_nodes=[1, 2]); check("Shamir fails below threshold", False)
except ValueError: check("Shamir fails below threshold", True)
th = a.threshold_test(); out["threshold"] = th
check("t shares recover secret", th["with_t_shares"] == th["secret"] and th["other_t_subset"] == th["secret"])
check("t-1 shares do NOT recover secret", not th["t_minus_1_correct"])

# uniformity
un = a.uniformity_test(); out["uniformity"] = un
check("Single share looks uniform (chi-square)", un["looks_uniform"], f"chi2={un['chi2']:.2f} < {un['critical']}")

# tamper
try: a.secure_aggregate(pv, 3, "additive", tamper=("AIIMS Delhi", "sum", 2)); check("Tampered share rejected (additive)", False)
except sec.IntegrityError as e: check("Tampered share rejected (additive)", True, str(e))
r = a.secure_aggregate(pv, 5, "shamir", 3, tamper=("AIIMS Delhi", "sum", 2))
check("Shamir excludes tampered node and still correct", r["rejected_nodes"] == [2] and abs(r["results"]["mean"] - pt["mean"]) < 1e-6)
out["tamper"] = {"rejected_nodes_shamir": r["rejected_nodes"]}

# crypto round trip
tok, key = sec.encrypt_bytes(b"hello"); check("Fernet round-trip", sec.decrypt_bytes(tok, key) == b"hello")

# scalability
sc = []
import numpy as np
for k in (5, 20, 50):
    big = {f"P{i}": list(np.random.default_rng(i).normal(100, 15, 400)) for i in range(k)}
    t0 = time.perf_counter(); a.secure_aggregate(big, 3, "additive"); sc.append({"parties": k, "records": k * 400, "ms": round((time.perf_counter() - t0) * 1000, 1)})
out["scalability"] = sc; print(sc)

out["checks"] = checks
out["all_passed"] = all(c["passed"] for c in checks)
json.dump(out, open("output/test_results.json", "w"), indent=2)
print("ALL PASSED" if out["all_passed"] else "FAILURES")
