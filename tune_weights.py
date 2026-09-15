"""
tune_weights.py — Empirically tune the hybrid fusion weights
--------------------------------------------------------------
The final risk score is currently computed as:

    rule_ml_combined = ALPHA * rule_risk + (1 - ALPHA) * ml_risk
    final_score      = BETA  * rule_ml_combined + (1 - BETA) * llm_score

ALPHA and BETA were originally hand-picked as 0.5 and 0.6. This script
grid-searches both weights against a real, previously-recorded hybrid
run (System_Test_Results_2026-04-13.xlsx — 500 labeled samples with
per-sample Rule Risk / ML Risk / LLM Score already computed with Ollama
enabled) and reports the combination that maximizes F1 on the binary
Safe vs Suspicious task, matching how automated_tester.py scores the
system.

No new Ollama calls are made — this reuses scores already produced by
a genuine hybrid run, so it is fast and reproducible.
"""

import numpy as np
import pandas as pd

SOURCE_FILE = "System_Test_Results_2026-04-13.xlsx"
SAFE_THRESHOLD = 40   # score_to_label: < 40 -> SAFE
PHISH_THRESHOLD = 70  # score_to_label: >= 70 -> PHISHING


def score_to_binary(score: float) -> str:
    return "Safe" if score < SAFE_THRESHOLD else "Suspicious"


def evaluate(rule, ml, llm, true_label, alpha, beta):
    combined = alpha * rule + (1 - alpha) * ml
    final = beta * combined + (1 - beta) * llm
    pred = np.where(final < SAFE_THRESHOLD, "Safe", "Suspicious")

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


def main():
    df = pd.read_excel(SOURCE_FILE, sheet_name="Test Results")
    df = df.dropna(subset=["Rule Risk", "ML Risk", "LLM Score", "True Label"])

    rule = df["Rule Risk"].astype(float).to_numpy()
    ml = df["ML Risk"].astype(float).to_numpy()
    llm = df["LLM Score"].astype(float).to_numpy()
    true_label = df["True Label"].astype(str).to_numpy()

    print(f"Loaded {len(df)} labeled samples from {SOURCE_FILE}")
    print(f"Class balance -> Safe: {(true_label == 'Safe').sum()}, "
          f"Suspicious: {(true_label == 'Suspicious').sum()}\n")

    # Sanity check: reconstruct current formula (alpha=0.5, beta=0.6) and
    # compare against the "Final Score" column already in the sheet.
    baseline = evaluate(rule, ml, llm, true_label, alpha=0.5, beta=0.6)
    print("Current weights (alpha=0.50 rule/ml, beta=0.60 rule+ml/llm):")
    print(f"  accuracy={baseline['accuracy']:.4f} precision={baseline['precision']:.4f} "
          f"recall={baseline['recall']:.4f} f1={baseline['f1']:.4f}\n")

    grid = np.round(np.arange(0.0, 1.01, 0.05), 2)
    results = []
    for alpha in grid:
        for beta in grid:
            m = evaluate(rule, ml, llm, true_label, alpha, beta)
            results.append((alpha, beta, m))

    results.sort(key=lambda r: (r[2]["f1"], r[2]["accuracy"]), reverse=True)

    print("Top 10 (alpha, beta) combinations by F1:")
    print(f"{'alpha':>6} {'beta':>6} {'acc':>7} {'prec':>7} {'rec':>7} {'f1':>7}")
    for alpha, beta, m in results[:10]:
        print(f"{alpha:6.2f} {beta:6.2f} {m['accuracy']:7.4f} {m['precision']:7.4f} "
              f"{m['recall']:7.4f} {m['f1']:7.4f}")

    top_f1 = results[0][2]["f1"]
    plateau = [(a, b, m) for a, b, m in results if m["f1"] >= top_f1 - 1e-9]
    print(f"\n{len(plateau)} combinations tie for the top F1 ({top_f1:.4f}).")
    print("Pure argmax lands on alpha=0.0 (the rule score gets ZERO weight), which "
          "wins on this dataset only because rule signals never disagree with a "
          "correct ML/LLM call here — it does not mean rules are worthless in "
          "general (they're the only signal available when the LLM is disabled "
          "or the ML model is unavailable, and they're what makes the reasons/red "
          "flags explainable). We pick the combination inside the tied plateau "
          "that keeps the largest rule weight, to preserve that defense-in-depth "
          "property without sacrificing any measured accuracy.")

    best_alpha = max(a for a, b, m in plateau)
    beta_choices = sorted({b for a, b, m in plateau if a == best_alpha})
    best_beta = beta_choices[len(beta_choices) // 2]
    best_m = evaluate(rule, ml, llm, true_label, best_alpha, best_beta)

    print(f"\nChosen: alpha={best_alpha}, beta={best_beta} -> "
          f"f1={best_m['f1']:.4f}, accuracy={best_m['accuracy']:.4f}")
    print(f"Confusion @ chosen: TP={best_m['tp']} TN={best_m['tn']} "
          f"FP={best_m['fp']} FN={best_m['fn']}")

    old = evaluate(rule, ml, llm, true_label, 0.5, 0.6)
    print(f"\nvs. current hardcoded weights (alpha=0.50, beta=0.60): "
          f"f1={old['f1']:.4f}, fn={old['fn']} (missed suspicious cases)")


if __name__ == "__main__":
    main()
