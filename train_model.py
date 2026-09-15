"""
train_model.py — Train the ML classifier with a real evaluation pass
----------------------------------------------------------------------
Previously this script fit MultinomialNB on 100% of training_data.csv
and pickled it with no held-out evaluation at all — there was no
number anywhere confirming the model generalizes rather than
memorizing the training set.

This version:
  1) Splits the data into train/test (stratified, so class balance is
     preserved in both halves).
  2) Compares three candidate models with 5-fold cross-validation on
     the training split: Multinomial Naive Bayes (the original
     choice), Logistic Regression, and a calibrated Linear SVM.
  3) Picks the candidate with the best mean CV F1.
  4) Evaluates the chosen model on the untouched test split to get an
     honest generalization estimate (accuracy/precision/recall/F1 +
     confusion matrix).
  5) Refits the chosen model on the FULL dataset (train+test) for the
     deployed model.pkl — standard practice once the held-out numbers
     are recorded, so the shipped model doesn't waste 20% of the data
     it could have learned from.
  6) Writes training_metadata.json alongside the pickles: dataset
     size/balance, sklearn version, timestamp, every candidate's CV
     score, and the chosen model's held-out test metrics — so the
     numbers behind model.pkl are always reproducible and inspectable,
     not just asserted.
"""

import json
import pickle
import platform
from datetime import datetime, timezone

import pandas as pd
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 5


def load_dataset(path: str = "training_data.csv") -> pd.DataFrame:
    data = pd.read_csv(path)
    data = data[["text", "label"]]

    before = len(data)
    data = data.dropna(subset=["text", "label"])
    if len(data) != before:
        print(f"Removed {before - len(data)} row(s) with missing text/label.")

    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    data = data.dropna(subset=["label"])
    data["label"] = data["label"].astype(int)

    if data["label"].nunique() < 2:
        raise ValueError("Need BOTH classes (0 and 1) in training_data.csv")

    return data


def build_candidates() -> dict:
    return {
        "MultinomialNB": MultinomialNB(),
        "LogisticRegression": LogisticRegression(
            max_iter=1000, class_weight="balanced", random_state=RANDOM_STATE
        ),
        "LinearSVC (calibrated)": CalibratedClassifierCV(
            LinearSVC(class_weight="balanced", random_state=RANDOM_STATE, dual="auto"),
            cv=5,
        ),
    }


def main():
    print("=" * 60)
    print("  TRAINING — model selection with held-out evaluation")
    print("=" * 60)

    data = load_dataset()
    X, y = data["text"].astype(str), data["label"]

    print(f"\nDataset: {len(data)} rows "
          f"(label=1: {int((y == 1).sum())}, label=0: {int((y == 0).sum())})")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE
    )
    print(f"Split: {len(X_train)} train / {len(X_test)} test (stratified, {TEST_SIZE:.0%} held out)\n")

    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    candidates = build_candidates()
    cv_results = {}

    print(f"--- {CV_FOLDS}-fold cross-validation on the training split (scoring=F1) ---")
    for name, model in candidates.items():
        scores = cross_val_score(model, X_train_vec, y_train, cv=cv, scoring="f1")
        cv_results[name] = {"mean_f1": float(scores.mean()), "std_f1": float(scores.std())}
        print(f"  {name:<24} f1 = {scores.mean():.4f} (+/- {scores.std():.4f})")

    best_name = max(cv_results, key=lambda n: cv_results[n]["mean_f1"])
    print(f"\nSelected model: {best_name}")

    best_model = candidates[best_name]
    best_model.fit(X_train_vec, y_train)

    y_pred = best_model.predict(X_test_vec)
    test_metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
    }
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    print(f"\n--- Held-out test set ({len(X_test)} samples never used for training) ---")
    print(f"  accuracy  = {test_metrics['accuracy']:.4f}")
    print(f"  precision = {test_metrics['precision']:.4f}")
    print(f"  recall    = {test_metrics['recall']:.4f}")
    print(f"  f1        = {test_metrics['f1']:.4f}")
    print(f"  confusion matrix: TP={tp} TN={tn} FP={fp} FN={fn}")

    # Refit the chosen model type on the FULL dataset for deployment,
    # now that we have an honest held-out score recorded above.
    final_vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    X_full_vec = final_vectorizer.fit_transform(X)
    final_model = build_candidates()[best_name]
    final_model.fit(X_full_vec, y)

    with open("model.pkl", "wb") as f:
        pickle.dump(final_model, f)
    with open("vectorizer.pkl", "wb") as f:
        pickle.dump(final_vectorizer, f)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "dataset_size": len(data),
        "class_balance": {"label_1": int((y == 1).sum()), "label_0": int((y == 0).sum())},
        "test_size": TEST_SIZE,
        "cv_folds": CV_FOLDS,
        "candidates_cv_f1": cv_results,
        "chosen_model": best_name,
        "held_out_test_metrics": test_metrics,
        "held_out_confusion_matrix": {"tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)},
        "note": "model.pkl is refit on the FULL dataset after evaluation; "
                "held_out_test_metrics reflect the earlier train/test split, not the shipped model directly.",
    }
    with open("training_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print("\nSaved: model.pkl, vectorizer.pkl, training_metadata.json")


if __name__ == "__main__":
    main()
