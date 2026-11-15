"""ShareGuard - Secure multi-party analytics using secret sharing (Streamlit app)."""
import io, json
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

import analytics as an
import secret_sharing as ss
import security as sec

st.set_page_config(page_title="ShareGuard", page_icon="🔐", layout="wide")

MODULES = ["Overview", "Upload & Configure", "Share Generation", "Secure Computation",
           "Security Analysis", "Encryption & Export"]
st.sidebar.markdown("## Navigation")
page = st.sidebar.radio("Choose module", MODULES)
st.sidebar.divider()
st.sidebar.caption("ShareGuard | Mini Project")

S = st.session_state
S.setdefault("df", None); S.setdefault("result", None); S.setdefault("cfg", None)


def need_data():
    if S.df is None or S.cfg is None:
        st.warning("Please upload a dataset and confirm the configuration in **Upload & Configure** first.")
        st.stop()


# ------------------------------------------------------------------ 1
if page == "Overview":
    st.title("🔐 ShareGuard")
    st.subheader("Secure multi-party analytics using secret sharing")
    st.write("Several organisations can compute joint statistics (count, sum, mean, variance) "
             "**without revealing their raw data to anyone**. Each party splits its local totals "
             "into random shares and sends one share to each computing node. No single node "
             "learns anything; only the combined result is reconstructed.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Dataset uploaded", "Yes" if S.df is not None else "No")
    c2.metric("Secure result available", "Yes" if S.result else "No")
    c3.metric("Encryption available", "Yes")
    st.markdown("**Workflow:** Upload → Configure → Generate shares → Secure computation → "
                "Security analysis → Encrypt & export")

# ------------------------------------------------------------------ 2
elif page == "Upload & Configure":
    st.header("Upload & Configure")
    up = st.file_uploader("Upload a CSV dataset", type=["csv"])
    if st.button("Use sample dataset"):
        S.df = pd.read_csv("data/sample_dataset.csv"); S.result = None; S.cfg = None
    if up is not None:
        try:
            S.df = pd.read_csv(up); S.result = None; S.cfg = None
        except Exception as e:
            st.error(f"Could not read file: {e}")
    if S.df is not None:
        df = S.df
        st.subheader("Dataset preview")
        st.dataframe(df.head(10), use_container_width=True)
        st.caption(f"Shape: {df.shape[0]} rows × {df.shape[1]} columns")
        num_cols = df.select_dtypes("number").columns.tolist()
        cat_cols = [c for c in df.columns if c not in num_cols or df[c].nunique() <= 50]
        if not num_cols:
            st.error("No numeric column found."); st.stop()
        st.subheader("Protocol configuration")
        a, b = st.columns(2)
        party_col = a.selectbox("Party column (each value = one organisation)", cat_cols, index=0)
        value_col = b.selectbox("Numeric column to analyse", num_cols)
        c, d, e = st.columns(3)
        mode = c.radio("Sharing scheme", ["additive", "shamir"],
                       format_func=lambda m: "Additive (n-of-n)" if m == "additive" else "Shamir (t-of-n)")
        n = d.slider("Computing nodes (n)", 3, 7, 5 if mode == "shamir" else 3)
        t = e.slider("Threshold (t)", 2, n, min(3, n), disabled=(mode == "additive"))
        pv = an.party_values_from_df(df, party_col, value_col)
        st.write(f"**Detected parties ({len(pv)}):** " + ", ".join(f"{k} ({len(v)} records)" for k, v in pv.items()))
        if st.button("Confirm configuration", type="primary"):
            S.cfg = dict(party_col=party_col, value_col=value_col, mode=mode, n=n, t=t, pv=pv)
            S.result = None
            st.success("Configuration saved. Continue to **Share Generation**.")

# ------------------------------------------------------------------ 3
elif page == "Share Generation":
    need_data(); cfg = S.cfg
    st.header("Share Generation")
    st.write("Each party computes three local numbers from its own raw data – **count, sum and sum of squares** – "
             "and splits each into random shares, one per node.")
    party = st.selectbox("Inspect party", list(cfg["pv"]))
    loc = an.local_stats(cfg["pv"][party])
    st.markdown("**Local statistics (known only to this party, fixed-point integers):**")
    st.json(loc)
    if st.button("Generate shares", type="primary"):
        rows = []
        for s in an.STATS:
            secret = ss.to_field(loc[s])
            if cfg["mode"] == "additive":
                sh = ss.additive_split(secret, cfg["n"])
            else:
                sh = [y for _, y in ss.shamir_split(secret, cfg["n"], cfg["t"])]
            rows.append({"statistic": s, "secret": loc[s], **{f"Node {j+1}": v for j, v in enumerate(sh)}})
        S.share_view = pd.DataFrame(rows)
    if S.get("share_view") is not None:
        st.dataframe(S.share_view.astype(str), use_container_width=True)
        st.info("Every node receives a large random-looking number. Without the other shares "
                "(all n for additive, at least t for Shamir) the secret cannot be recovered.")

# ------------------------------------------------------------------ 4
elif page == "Secure Computation":
    need_data(); cfg = S.cfg
    st.header("Secure Computation")
    avail = None
    if cfg["mode"] == "shamir":
        avail = st.multiselect("Nodes currently online", list(range(1, cfg["n"] + 1)),
                               default=list(range(1, cfg["n"] + 1)))
        st.caption(f"Threshold t = {cfg['t']}: reconstruction needs at least {cfg['t']} online nodes.")
    if st.button("Run secure computation", type="primary"):
        try:
            S.result = an.secure_aggregate(cfg["pv"], cfg["n"], cfg["mode"], cfg["t"], available_nodes=avail)
        except Exception as e:
            S.result = None; st.error(f"Computation failed: {e}")
    if S.result:
        r = S.result["results"]; pt = an.plaintext_stats(cfg["pv"])
        cmp = pd.DataFrame({"Statistic": ["Count", "Sum", "Mean", "Variance", "Std. deviation"],
                            "Secure result": [r["count"], r["sum"], r["mean"], r["variance"], r["std"]],
                            "Plaintext (for verification)": [pt["count"], pt["sum"], pt["mean"], pt["variance"], pt["std"]]})
        cmp["Absolute difference"] = (cmp["Secure result"] - cmp["Plaintext (for verification)"]).abs()
        st.dataframe(cmp.style.format({"Secure result": "{:.4f}", "Plaintext (for verification)": "{:.4f}",
                                       "Absolute difference": "{:.2e}"}), use_container_width=True)
        st.success("Secure result matches the plaintext computation." if cmp["Absolute difference"].max() < 1e-6
                   else "Mismatch detected!")
        fig = go.Figure(go.Bar(x=cmp["Statistic"][2:], y=cmp["Secure result"][2:], name="Secure"))
        fig.add_bar(x=cmp["Statistic"][2:], y=cmp["Plaintext (for verification)"][2:], name="Plaintext")
        fig.update_layout(barmode="group", title="Secure vs plaintext", height=320)
        st.plotly_chart(fig, use_container_width=True)
        st.subheader("What each node holds (sum of received shares)")
        nt = pd.DataFrame({f"Node {j}": {s: str(v) for s, v in d.items()}
                           for j, d in S.result["node_totals"].items()})
        st.dataframe(nt, use_container_width=True)

# ------------------------------------------------------------------ 5
elif page == "Security Analysis":
    need_data(); cfg = S.cfg
    st.header("Security Analysis")
    st.subheader("1. A single share reveals nothing")
    st.write("The same secret is shared 6000 times; the first share is plotted. A flat histogram means it is uniformly random.")
    un = an.uniformity_test()
    fig = go.Figure(go.Bar(x=list(range(1, 21)), y=un["counts"]))
    fig.update_layout(title="Distribution of one share (same secret, 6000 runs)", xaxis_title="Bin of share value (0–1)",
                      yaxis_title="Frequency", height=320)
    st.plotly_chart(fig, use_container_width=True)
    st.write(f"Chi-square = **{un['chi2']:.2f}** (critical value {un['critical']}) → "
             + ("**consistent with uniform randomness**" if un["looks_uniform"] else "**not uniform**"))

    st.subheader("2. Threshold test (Shamir)")
    n_t, t_t = st.columns(2)
    nn = n_t.slider("n", 3, 8, 5, key="tn"); tt = t_t.slider("t", 2, nn, 3, key="tt")
    th = an.threshold_test(n=nn, t=tt)
    st.table(pd.DataFrame({"Case": [f"Any {tt} shares (set 1)", f"Any {tt} shares (set 2)", f"Only {tt-1} shares"],
                           "Reconstructed value": [th["with_t_shares"], th["other_t_subset"], th["with_t_minus_1"]],
                           "Equals secret?": [th["with_t_shares"] == th["secret"], th["other_t_subset"] == th["secret"],
                                              th["t_minus_1_correct"]]}).astype(str))
    st.caption(f"True secret = {th['secret']}")

    st.subheader("3. Tamper detection (HMAC)")
    st.write("Simulate an attacker flipping one share in transit. Every share carries an HMAC-SHA256 tag that the node verifies.")
    parties = list(cfg["pv"])
    a_, b_, c_ = st.columns(3)
    tp = a_.selectbox("Party", parties); ts = b_.selectbox("Statistic", list(an.STATS)); tn = c_.selectbox("Node", list(range(1, cfg["n"] + 1)))
    if st.button("Tamper with this share and run"):
        try:
            out = an.secure_aggregate(cfg["pv"], cfg["n"], cfg["mode"], cfg["t"], tamper=(tp, ts, tn))
            st.warning(f"Node(s) {out['rejected_nodes']} rejected the tampered share; "
                       f"computation still succeeded using nodes {out['usable_nodes'][:cfg['t']]}.")
            st.write(f"Mean = {out['results']['mean']:.4f}")
        except sec.IntegrityError as e:
            st.error(f"🚨 Integrity violation detected – computation aborted. {e}")

# ------------------------------------------------------------------ 6
elif page == "Encryption & Export":
    need_data()
    if not S.result:
        st.warning("Run **Secure Computation** first."); st.stop()
    cfg = S.cfg; r = S.result["results"]
    st.header("Encryption & Export")
    report = pd.DataFrame([{"column": cfg["value_col"], "parties": len(cfg["pv"]), "scheme": cfg["mode"],
                            "nodes": cfg["n"], "threshold": cfg["t"] if cfg["mode"] == "shamir" else cfg["n"], **r}])
    csv_bytes = report.to_csv(index=False).encode()
    st.dataframe(report, use_container_width=True)
    digest = sec.sha256_hex(csv_bytes)
    st.markdown("**SHA-256 of the results file:**"); st.code(digest)
    st.download_button("Download results CSV", csv_bytes, "secure_results.csv", "text/csv")
    st.subheader("Encrypt results (Fernet)")
    if st.button("Generate key and encrypt", type="primary"):
        S.enc, S.key = sec.encrypt_bytes(csv_bytes)
    if S.get("enc"):
        st.success("Encryption completed.")
        st.code(S.enc[:64].decode() + "…")
        st.download_button("Download encrypted file", S.enc, "secure_results.enc")
        st.download_button("Download encryption key (keep private)", S.key, "secure_results.key")
        st.warning("Anyone with the key can decrypt the file. Store it separately and securely.")
    st.subheader("Verify file integrity")
    chk = st.file_uploader("Upload a results CSV to verify", type=["csv"])
    if chk is not None:
        ok = sec.sha256_hex(chk.getvalue()) == digest
        (st.success if ok else st.error)("Hashes match – file is unchanged." if ok else "Hashes differ – file has been modified.")
