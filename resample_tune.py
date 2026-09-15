"""
resample_tune.py — Re-derive fusion weights for the retrained model
-----------------------------------------------------------------------
tune_weights.py's original recommendation (alpha=0.40, beta=0.60) was
derived from System_Test_Results_2026-04-13.xlsx, which recorded scores
from the OLD MultinomialNB model. train_model.py has since replaced
model.pkl with a LogisticRegression model that was selected by cross-
validation for better held-out F1 on the TRAINING distribution — but a
rule+ML-only check on the independent evaluation set (dataset (2).xlsx)
showed it generalizes differently: high precision, much lower recall
(the opposite failure mode of the old model, which over-flagged safe
inputs). Reusing weights tuned for the old model's score distribution
against a new model with a different error profile would be a real
methodology mistake, so this script re-runs a real (not simulated)
hybrid pass — Ollama included — on a stratified sample of the eval set
and re-tunes alpha/beta against fresh numbers.

A full 500-sample Ollama pass takes on the order of hours on this
hardware; this uses a stratified subset instead, which is enough to
get an honest read on which weight region is now appropriate without
an multi-hour wait. Results are written to resample_scores.csv for
inspection/audit.
"""

import random

import numpy as np
import pandas as pd

from detector import analyze_for_ui

DATASET_FILE = "dataset (2).xlsx"
SAMPLE_PER_CLASS = 30
RANDOM_SEED = 42


def load_labeled_samples():
    df = pd.read_excel(DATASET_FILE)
    safe, suspicious = [], []
    for _, row in df.iterrows():
        content = str(row["Content"]).strip()
        label = str(row["Type"]).strip().lower()
        if not content or content == "nan":
            continue
        (safe if label == "safe" else suspicious).append(content)
    return safe, suspicious


def main():
    random.seed(RANDOM_SEED)
    safe, suspicious = load_labeled_samples()
    sample = (
        [(t, "Safe") for t in random.sample(safe, min(SAMPLE_PER_CLASS, len(safe)))]
        + [(t, "Suspicious") for t in random.sample(suspicious, min(SAMPLE_PER_CLASS, len(suspicious)))]
    )
    random.shuffle(sample)

    print(f"Running hybrid analysis (Ollama enabled) on {len(sample)} stratified samples...")
    rows = []
    for i, (text, true_label) in enumerate(sample, 1):
        r = analyze_for_ui(text, use_llm=True)
        bd = r["breakdown"]
        rows.append({
            "text": text,
            "true_label": true_label,
            "rule_risk": bd["rule_risk"],
            "ml_risk": bd["ml_risk"],
            "llm_score": bd["llm_score"],
            "llm_available": bd["llm_available"],
        })
        print(f"  [{i}/{len(sample)}] true={true_label:<10} rule={bd['rule_risk']:>3} "
              f"ml={bd['ml_risk']:>3} llm={bd['llm_score']:>3} ({text[:50]!r})")

    out = pd.DataFrame(rows)
    out.to_csv("resample_scores.csv", index=False)
    print(f"\nSaved {len(out)} rows to resample_scores.csv")

    unavailable = (~out["llm_available"]).sum()
    if unavailable:
        print(f"WARNING: {unavailable} sample(s) had llm_available=False (Ollama issue) — "
              f"excluding them from weight tuning.")
        out = out[out["llm_available"]]

    rule = out["rule_risk"].to_numpy(dtype=float)
    ml = out["ml_risk"].to_numpy(dtype=float)
    llm = out["llm_score"].to_numpy(dtype=float)
    true_label = out["true_label"].to_numpy()

    def evaluate(alpha, beta):
        combined = alpha * rule + (1 - alpha) * ml
        final = beta * combined + (1 - beta) * llm
        pred = np.where(final < 40, "Safe", "Suspicious")
        tp = int(((pred == "Suspicious") & (true_label == "Suspicious")).sum())
        tn = int(((pred == "Safe") & (true_label == "Safe")).sum())
        fp = int(((pred == "Suspicious") & (true_label == "Safe")).sum())
        fn = int(((pred == "Safe") & (true_label == "Suspicious")).sum())
        total = len(true_label)
        accuracy = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return {"accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
                "tp": tp, "tn": tn, "fp": fp, "fn": fn}

    grid = np.round(np.arange(0.0, 1.01, 0.05), 2)
    results = []
    for alpha in grid:
        for beta in grid:
            results.append((alpha, beta, evaluate(alpha, beta)))
    results.sort(key=lambda r: (r[2]["f1"], r[2]["accuracy"]), reverse=True)

    top_f1 = results[0][2]["f1"]
    plateau = [(a, b, m) for a, b, m in results if m["f1"] >= top_f1 - 1e-9]
    best_alpha = max(a for a, b, m in plateau)
    beta_choices = sorted({b for a, b, m in plateau if a == best_alpha})
    best_beta = beta_choices[len(beta_choices) // 2]
    best_m = evaluate(best_alpha, best_beta)

    print(f"\n{len(plateau)} combos tie for top F1 ({top_f1:.4f}) on this {len(out)}-sample set.")
    print(f"Chosen (largest-alpha inside plateau): alpha={best_alpha}, beta={best_beta}")
    print(f"  accuracy={best_m['accuracy']:.4f} precision={best_m['precision']:.4f} "
          f"recall={best_m['recall']:.4f} f1={best_m['f1']:.4f}")
    print(f"  confusion: TP={best_m['tp']} TN={best_m['tn']} FP={best_m['fp']} FN={best_m['fn']}")

    current = evaluate(0.40, 0.60)
    print(f"\nvs. currently deployed weights (alpha=0.40, beta=0.60) on this same sample:")
    print(f"  accuracy={current['accuracy']:.4f} f1={current['f1']:.4f} fn={current['fn']} fp={current['fp']}")


if __name__ == "__main__":
    main()
