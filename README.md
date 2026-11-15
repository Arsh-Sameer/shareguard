# ShareGuard

Secure multi-party analytics using secret sharing. This is a mini project for CSDX540 Secure Data Science.

## What it does

Imagine five hospitals that want the average cholesterol across all their patients, but none of them is allowed to hand over its records. ShareGuard handles that.

Each hospital works out three totals from its own data: the number of records, the sum, and the sum of squares. It then splits each total into random pieces called shares and gives one share to each computing node. A single share is just a random number and tells you nothing. The nodes add up the shares they received, and only the combined totals are put back together. From those you get the count, sum, mean, variance and standard deviation, and the answer matches a normal calculation exactly.

## Main features

- Additive sharing (all nodes needed) and Shamir sharing (any t of n nodes), both over the prime field 2^61 minus 1
- Exact results, checked against a plain calculation on the same data
- With Shamir, the result still works if some nodes are offline
- Every share carries an HMAC-SHA256 tag, so a changed share gets rejected
- A chi-square test showing that one share looks uniformly random
- SHA-256 hash and Fernet encryption for the exported results

## How to run it

You need Python 3.9 or newer.

```
pip install -r requirements.txt
streamlit run app.py
```

The app opens at http://localhost:8501. Click "Use sample dataset" on the Upload & Configure page, pick `hospital` as the party column and a numeric column such as `age`, then move through the pages in the sidebar. You can also upload your own CSV, as long as it has one column that identifies the party and one numeric column.

To run the tests:

```
python tests.py
```

If `pip` or `streamlit` is blocked on your machine, use `python -m pip` and `python -m streamlit` instead.

## Files

| File | What it does |
|---|---|
| app.py | The Streamlit interface |
| secret_sharing.py | Additive and Shamir sharing, plus fixed-point encoding |
| analytics.py | The secure aggregation steps and the security experiments |
| security.py | HMAC tags, SHA-256 and Fernet encryption |
| tests.py | 14 automated checks |
| data/sample_dataset.csv | Made-up patient data from 5 hospitals |

## Limits

This is a learning project. The nodes are simulated inside one Python process, so there is no real network between them. It only handles simple statistics, it assumes the parties enter honest data, and it is not a certified security system. The sample data is synthetic.
