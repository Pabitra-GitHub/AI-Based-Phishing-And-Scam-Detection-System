"""
PhishGuard AI - Model Training & Evaluation Pipeline
Trains baseline Logistic Regression and candidate Random Forest classifier.
Generates performance metrics and serializes the winning model artifact.
"""

import os
import json
import random
import numpy as np
import pandas as pd
import joblib
from datetime import datetime, timezone
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Relative / local imports
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from extract_features import extract_features_from_url, FEATURE_COLUMNS


def generate_curated_dataset() -> pd.DataFrame:
    """Generate a rich, balanced dataset of verified legitimate and phishing URLs."""
    legitimate_urls = [
        "https://www.google.com",
        "https://www.google.com/search?q=machine+learning+security",
        "https://www.github.com",
        "https://github.com/torvalds/linux",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://en.wikipedia.org/wiki/Machine_learning",
        "https://www.amazon.com",
        "https://www.amazon.com/gp/bestsellers",
        "https://www.microsoft.com/en-us/windows",
        "https://apple.com/iphone",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP",
        "https://www.reddit.com/r/programming",
        "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster-than-processing-an-unsorted-array",
        "https://fastapi.tiangolo.com/tutorial/first-steps/",
        "https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html",
        "https://react.dev/learn",
        "https://tailwindcss.com/docs/installation",
        "https://www.netflix.com/browse",
        "https://www.linkedin.com/feed/",
        "https://twitter.com/home",
        "https://www.nytimes.com/section/technology",
        "https://www.bbc.com/news/world",
        "https://news.ycombinator.com",
        "https://pypi.org/project/fastapi/",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://www.spotify.com/us/home/",
        "https://medium.com/tag/data-science",
        "https://www.cloudflare.com/learning/security/threats/what-is-phishing/",
        "https://www.w3schools.com/html/html_intro.asp",
        "https://www.mit.edu/research/",
        "https://www.stanford.edu/academics/",
        "https://www.harvard.edu/programs/",
        "https://www.who.int/emergencies/diseases/novel-coronavirus-2019",
        "https://www.nasa.gov/missions",
        "https://hub.docker.com/_/python",
        "https://vitejs.dev/guide/",
        "https://www.sqlite.org/docs.html",
        "https://www.postgresql.org/docs/current/index.html",
        "https://www.kaggle.com/datasets"
    ]

    phishing_urls = [
        "http://paypal-security-update.account-verification.tk/login.php?id=92834&secure=true",
        "http://appleid.apple.com.verify-billing-support.ga/signin?session=38294",
        "http://netflix-suspended-account.update-payment.xyz/renew",
        "http://192.168.1.100/admin-login/auth.html",
        "http://45.33.32.156/bankofamerica-secure-login/index.php",
        "http://www.google.com-account-recovery-security-auth.cf/identify",
        "http://secure-login-chase-bank-account.top/verify_credentials.php?token=928348",
        "http://amazon-account-lock-security.gq/login?redirect=account",
        "http://microsoft-outlook-web-app.session-login.click/auth?usr=admin",
        "http://wellsfargo.verify-personal-profile.rest/signon",
        "http://binance.com-login-wallet-recovery.surf/auth/2fa",
        "http://metamask-crypto-wallet-seed-recovery.icu/import",
        "http://coinbase-pro-security-auth-check.buzz/signin",
        "http://whatsapp-web-free-giftcard-giveaway.loan/claim?code=98213",
        "http://facebook-security-checkup-checkpoint.rest/login",
        "http://instagram-blue-tick-verification-badge.party/form",
        "http://ebay-resolution-center-case.cam/dispute?id=829314",
        "http://dhl-package-express-delivery-fee.fit/tracking/pay.php",
        "http://usps-post-redelivery-scheduled-update.download/confirm",
        "http://fedex-parcel-status-notification.racing/action?track=8492049",
        "http://xn--pypal-4ve.com/account/login",
        "http://xn--appl-coa.com/id/verify",
        "http://secure.banking-online-support.xyz/login.asp?ref=customer",
        "http://free-iphone15-pro-giveaway-winner.date/claim?user=victim",
        "http://account-validation-security-alert.review/service/verify",
        "http://paypaI-security-center.com/signin", # Homoglyph 'I' instead of 'l'
        "http://bit.ly/3xPh1shSecurityLoginUrgentAlert",
        "http://tinyurl.com/update-bank-credentials-now",
        "http://auth-server-identity-pass.gdn/signin/index.html?uuid=91283",
        "http://customer-support-helpdesk-agent.racing/ticket/view?ref=3829104"
    ]

    # Generate systematic synthetic combinations
    legit_domains = [
        "microsoft.com", "google.com", "apple.com", "amazon.com", "github.com",
        "stackoverflow.com", "nytimes.com", "wikipedia.org", "bbc.co.uk",
        "cloudflare.com", "mozilla.org", "salesforce.com", "oracle.com",
        "adobe.com", "ibm.com", "cisco.com", "dell.com", "intel.com",
        "spotify.com", "slack.com", "zoom.us", "dropbox.com", "gitlab.com",
        "atlassian.com", "stripe.com", "twillio.com", "reddit.com", "kaggle.com"
    ]
    legit_paths = [
        "/", "/about", "/contact", "/pricing", "/features", "/docs/guide",
        "/blog/2024/05/release-notes", "/products/overview", "/careers",
        "/support/kb/articles/10293", "/search?q=cybersecurity+training",
        "/legal/terms-of-service", "/legal/privacy-policy", "/api/v2/status"
    ]

    phish_brands = ["paypal", "apple", "netflix", "bankofamerica", "chase", "amazon", "microsoft", "binance", "metamask", "dhl", "usps"]
    phish_actions = ["verify", "security-update", "recover-account", "suspend-alert", "billing-problem", "confirm-identity", "unlock-profile"]
    phish_tlds = ["tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "buzz", "rest", "surf", "racing", "cam"]
    phish_paths = [
        "/login.php?session=", "/auth/verify.html?id=", "/signin/step2.php?token=",
        "/update-payment-card.html?user=", "/secure/identity-check.php?case=",
        "/recovery/wallet.html?ref=", "/dispute/resolution.php?id="
    ]

    urls = []
    labels = []

    # Add seeds
    for u in legitimate_urls:
        urls.append(u)
        labels.append(0)
    for u in phishing_urls:
        urls.append(u)
        labels.append(1)

    # Generate balanced synthetic samples (1000 each)
    random.seed(42)
    for _ in range(800):
        dom = random.choice(legit_domains)
        path = random.choice(legit_paths)
        if random.random() > 0.3:
            proto = "https://"
        else:
            proto = "http://"
        url = f"{proto}{dom}{path}"
        urls.append(url)
        labels.append(0)

    for _ in range(800):
        brand = random.choice(phish_brands)
        action = random.choice(phish_actions)
        tld = random.choice(phish_tlds)
        path = random.choice(phish_paths) + str(random.randint(10000, 999999))
        
        # Various phishing URL structures
        struct_type = random.choice(["subdomain", "hyphenated", "ip", "punycode", "deep"])
        if struct_type == "subdomain":
            url = f"http://{brand}.{action}.account-portal.{tld}{path}"
        elif struct_type == "hyphenated":
            url = f"http://{brand}-{action}-security.{tld}{path}"
        elif struct_type == "ip":
            ip_str = f"{random.randint(11, 220)}.{random.randint(10, 200)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
            url = f"http://{ip_str}/{brand}-{action}/login.html"
        elif struct_type == "punycode":
            url = f"http://xn--{brand[:3]}-8va9.{tld}/{action}.php"
        else:
            url = f"http://service.{brand}.secure.auth.{action}.{tld}{path}&retry=1&redirect_uri=auth"
        urls.append(url)
        labels.append(1)

    df = pd.DataFrame({"url": urls, "label": labels})
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    return df


def main():
    print("=" * 60)
    print("  PhishGuard AI - ML Pipeline Training & Evaluation")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_dir = os.path.join(base_dir, "datasets")
    models_dir = os.path.join(base_dir, "models")
    eval_dir = os.path.join(base_dir, "evaluation")

    os.makedirs(dataset_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(eval_dir, exist_ok=True)

    dataset_path = os.path.join(dataset_dir, "phishing_dataset.csv")

    # Step 1: Create or Load Dataset
    if os.path.exists(dataset_path):
        print(f"[*] Loading existing dataset from {dataset_path}")
        df = pd.read_csv(dataset_path)
    else:
        print("[*] Generating curated balanced phishing & benign dataset...")
        df = generate_curated_dataset()
        df.to_csv(dataset_path, index=False)
        print(f"[+] Dataset saved ({len(df)} samples) to {dataset_path}")

    required_columns = {"url", "label"}
    missing_columns = required_columns - set(df.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")
    if df[["url", "label"]].isna().any().any():
        raise ValueError("Dataset contains missing URLs or labels.")
    conflicting_urls = df.groupby("url")["label"].nunique()
    conflicting_urls = conflicting_urls[conflicting_urls > 1]
    if not conflicting_urls.empty:
        raise ValueError(
            f"Dataset has conflicting labels for {len(conflicting_urls)} duplicate URLs."
        )
    duplicate_count = int(df["url"].duplicated().sum())
    if duplicate_count:
        print(f"[*] Removing {duplicate_count} duplicate URLs before splitting.")
        df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)
    if set(df["label"].unique()) != {0, 1}:
        raise ValueError("Dataset labels must contain both binary classes 0 and 1.")

    print(f"[*] Class distribution: Legitimate (0): {sum(df['label'] == 0)}, Phishing (1): {sum(df['label'] == 1)}")

    # Step 2: Feature Extraction
    print("[*] Extracting 22 numerical/heuristic features for each URL...")
    feature_rows = []
    for url in df["url"]:
        feats = extract_features_from_url(url)
        feature_rows.append([feats[col] for col in FEATURE_COLUMNS])

    X = np.array(feature_rows, dtype=np.float64)
    y = df["label"].values

    # Step 3: Train / Val / Test Split (70% Train, 15% Val, 15% Test)
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=np.asarray(y, dtype=np.int64)
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.1765, random_state=42, stratify=y_train_val # 0.1765 of 85% is ~15%
    )

    print(f"[*] Split sizes -> Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

    # Step 4: Train Baseline Model (Logistic Regression)
    print("\n--- Training Baseline Model: Logistic Regression ---")
    baseline_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42))
    ])
    baseline_pipeline.fit(X_train, y_train)

    y_val_base_pred = baseline_pipeline.predict(X_val)
    y_val_base_prob = baseline_pipeline.predict_proba(X_val)[:, 1]
    base_acc = accuracy_score(y_val, y_val_base_pred)
    base_f1 = f1_score(y_val, y_val_base_pred)
    base_roc = roc_auc_score(y_val, y_val_base_prob)
    print(f"Baseline Validation Metrics -> Accuracy: {base_acc:.4f}, F1: {base_f1:.4f}, ROC-AUC: {base_roc:.4f}")

    # Step 5: Train Candidate Model (Random Forest)
    print("\n--- Training Candidate Model: Random Forest Classifier ---")
    candidate_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=4,
            random_state=42,
            n_jobs=1
        ))
    ])
    candidate_pipeline.fit(X_train, y_train)

    y_val_cand_pred = candidate_pipeline.predict(X_val)
    y_val_cand_prob = candidate_pipeline.predict_proba(X_val)[:, 1]
    cand_acc = accuracy_score(y_val, y_val_cand_pred)
    cand_prec = precision_score(y_val, y_val_cand_pred)
    cand_rec = recall_score(y_val, y_val_cand_pred)
    cand_f1 = f1_score(y_val, y_val_cand_pred)
    cand_roc = roc_auc_score(y_val, y_val_cand_prob)
    print(f"Candidate Validation Metrics -> Accuracy: {cand_acc:.4f}, Precision: {cand_prec:.4f}, Recall: {cand_rec:.4f}, F1: {cand_f1:.4f}, ROC-AUC: {cand_roc:.4f}")

    # Step 6: Evaluate Selected Model on Holdout Test Set
    best_model = candidate_pipeline if cand_f1 >= base_f1 else baseline_pipeline
    model_name = "RandomForestClassifier" if cand_f1 >= base_f1 else "LogisticRegression"
    print(f"\n[*] Winning Selected Model: {model_name}")

    y_test_pred = best_model.predict(X_test)
    y_test_prob = best_model.predict_proba(X_test)[:, 1]

    test_accuracy = accuracy_score(y_test, y_test_pred)
    test_precision = precision_score(y_test, y_test_pred)
    test_recall = recall_score(y_test, y_test_pred)
    test_f1 = f1_score(y_test, y_test_pred)
    test_roc_auc = roc_auc_score(y_test, y_test_prob)
    cm = confusion_matrix(y_test, y_test_pred).tolist()

    print("\n--- Final Test Set Evaluation Report ---")
    print(f"Accuracy:  {test_accuracy * 100:.2f}%")
    print(f"Precision: {test_precision * 100:.2f}%")
    print(f"Recall:    {test_recall * 100:.2f}%")
    print(f"F1-Score:  {test_f1 * 100:.2f}%")
    print(f"ROC-AUC:   {test_roc_auc:.4f}")
    print("Confusion Matrix [[TN, FP], [FN, TP]]:", cm)

    # Feature Importance for Random Forest
    rf_clf = candidate_pipeline.named_steps["classifier"]
    importances = rf_clf.feature_importances_
    feat_importance_dict = {
        col: round(float(imp), 4)
        for col, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True)
    }

    # Step 7: Serialize Model Artifact & Metadata
    model_export_path = os.path.join(models_dir, "phishing_model.joblib")
    metadata_export_path = os.path.join(models_dir, "model_metadata.json")
    metrics_export_path = os.path.join(eval_dir, "metrics.json")

    joblib.dump(best_model, model_export_path)
    print(f"[+] Serialized model artifact saved to {model_export_path}")

    metadata = {
        "model_version": "v1.0.0",
        "model_type": model_name,
        "features": FEATURE_COLUMNS,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "test_accuracy": round(float(test_accuracy), 4),
            "test_precision": round(float(test_precision), 4),
            "test_recall": round(float(test_recall), 4),
            "test_f1": round(float(test_f1), 4),
            "test_roc_auc": round(float(test_roc_auc), 4),
            "confusion_matrix": cm
        },
        "feature_importances": feat_importance_dict
    }

    with open(metadata_export_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    evaluation_metrics = {
        "accuracy": float(test_accuracy),
        "precision": float(test_precision),
        "recall": float(test_recall),
        "f1": float(test_f1),
        "roc_auc": float(test_roc_auc),
        "confusion_matrix": cm,
        "test_set_size": len(y_test),
        "model_version": metadata["model_version"],
        "model_type": model_name,
        "timestamp": metadata["created_at"],
    }
    with open(metrics_export_path, "w", encoding="utf-8") as f:
        json.dump(evaluation_metrics, f, indent=2)

    print(f"[+] Metadata & Evaluation metrics saved successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
