# ShareGuard – Secure Multi-Party Data Analytics Using Secret Sharing

Several organisations (e.g. hospitals) compute joint statistics – count, sum, mean, variance –
without revealing their raw data. Each party splits its local totals into random shares and
sends one share to each computing node; nodes add shares and only the final result is reconstructed.

## Features
- Additive (n-of-n) and Shamir (t-of-n) secret sharing over GF(2^61 - 1)
- Secure count / sum / mean / variance / std-dev, verified against plaintext
- Node-failure tolerance (Shamir): works with any t online nodes
- HMAC-SHA256 tag on every share -> tampering is detected
- Statistical proof that a single share is uniformly random (chi-square)
- SHA-256 integrity check + Fernet encryption of the exported results

## Run
```bash
pip install -r requirements.txt
streamlit run app.py          # opens http://localhost:8501
python tests.py               # 14 automated tests, writes output/test_results.json
```
Click **Use sample dataset** in *Upload & Configure* (5 hospitals, 1010 synthetic patients),
or upload any CSV that has one categorical "party" column and a numeric column.

## Files
| File | Purpose |
|---|---|
| app.py | Streamlit user interface (6 modules) |
| secret_sharing.py | Additive & Shamir sharing, fixed-point encoding |
| analytics.py | Secure aggregation protocol and security experiments |
| security.py | HMAC tags, SHA-256, Fernet encryption |
| tests.py | Automated tests and experiment runner |
| data/sample_dataset.csv | Synthetic multi-hospital dataset |

## Note
Educational prototype. Computing nodes are simulated inside one Python process; it is not a
certified or networked MPC system. The sample data is synthetic.
