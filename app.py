import os
import joblib
import numpy as np
import pandas as pd
import streamlit as st

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")

RF_PATH = os.path.join(MODELS_DIR, "rf_attack_prediction_model.pkl")
ENCODER_PATH = os.path.join(MODELS_DIR, "rf_encoders.pkl")
FEATURE_COLS_PATH = os.path.join(MODELS_DIR, "rf_feature_columns.pkl")

st.set_page_config(page_title="Predict_Attack", layout="wide")
st.title("Predict_Attack — Top-5 Cyberattack Prediction (Random Forest)")
st.caption("Upload a vulnerability list (CSV). The model outputs Top-5 predicted cyberattacks with probabilities.")

# ---- Advanced / Analyst Tools ----
with st.expander("⚙️ Advanced diagnostics (analyst only)"):
    st.write("BASE_DIR:", BASE_DIR)
    st.write("MODELS_DIR exists:", os.path.exists(MODELS_DIR))
    if os.path.exists(MODELS_DIR):
        st.write("Files in models/:", os.listdir(MODELS_DIR))
    st.write("RF_PATH exists:", os.path.exists(RF_PATH))
    st.write("ENCODER_PATH exists:", os.path.exists(ENCODER_PATH))
    st.write("FEATURE_COLS_PATH exists:", os.path.exists(FEATURE_COLS_PATH))
# ----------------------------------

@st.cache_resource
def load_assets():
    rf = joblib.load(RF_PATH)
    encoders = joblib.load(ENCODER_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
    return rf, encoders, feature_cols

rf, encoders, feature_cols = load_assets()

REQUIRED_COLS = ["cvss_score", "severity", "family", "verified_flag", "bank_relevance"]

def safe_label_transform(le, series: pd.Series) -> np.ndarray:
    """Transform with LabelEncoder; unknown categories -> 'UNKNOWN'."""
    series = series.astype(str).fillna("UNKNOWN")
    classes = set(le.classes_.tolist())
    if "UNKNOWN" not in classes:
        le.classes_ = np.append(le.classes_, "UNKNOWN")
        classes.add("UNKNOWN")
    series = series.map(lambda v: v if v in classes else "UNKNOWN")
    return le.transform(series)

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Build X with exactly the same columns used during training."""
    df = df.copy()

    # Normalize column names (user may upload different casing)
    df.columns = [c.strip().lower() for c in df.columns]

    missing = [c for c in REQUIRED_COLS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    # Ensure correct types
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce").fillna(5.0)
    df["verified_flag"] = pd.to_numeric(df["verified_flag"], errors="coerce").fillna(0).astype(int)

    # Encode categorical columns exactly as training
    df["severity"] = safe_label_transform(encoders["severity"], df["severity"])
    df["family"] = safe_label_transform(encoders["family"], df["family"])
    df["bank_relevance"] = safe_label_transform(encoders["bank_relevance"], df["bank_relevance"])

    X_user = df[["cvss_score", "severity", "family", "verified_flag", "bank_relevance"]].copy()

    # Enforce feature column order used in training
    # (feature_cols should match the 5 above; but we enforce anyway)
    for c in feature_cols:
        if c not in X_user.columns:
            X_user[c] = 0
    X_user = X_user[feature_cols]

    return X_user

def top_k_from_proba(mean_proba: np.ndarray, class_ids: np.ndarray, k=5):
    idx = np.argsort(mean_proba)[::-1][:k]
    return [(class_ids[i], float(mean_proba[i])) for i in idx]

# Downloadable template for users
template_df = pd.DataFrame({
    "cvss_score": [9.8, 7.5, 5.3],
    "severity": ["CRITICAL", "HIGH", "MEDIUM"],
    "family": ["Web Servers", "Databases", "General"],
    "verified_flag": [1, 0, 0],
    "bank_relevance": ["HIGH", "MEDIUM", "LOW"]
})

with st.expander("Download CSV template (recommended for prototype v1)"):
    st.download_button(
        "Download template.csv",
        data=template_df.to_csv(index=False).encode("utf-8"),
        file_name="instreamlight_template.csv",
        mime="text/csv"
    )
    st.dataframe(template_df, use_container_width=True)

uploaded = st.file_uploader("Upload your vulnerability list (CSV)", type=["csv"])

if uploaded:
    df_in = pd.read_csv(uploaded)
    st.subheader("Uploaded data preview")
    st.dataframe(df_in.head(20), use_container_width=True)

    if st.button("Predict Top-5 Cyberattacks"):
        try:
            X_user = build_features(df_in)

            # RF probabilities per row, then aggregate (mean) across the uploaded list
            proba = rf.predict_proba(X_user)
            mean_proba = proba.mean(axis=0)

            # rf.classes_ are encoded class ids (integers)
            class_ids = rf.classes_

            # decode class ids -> attack labels using attack_type encoder
            attack_le = encoders["attack_type"]
            decoded_labels = attack_le.inverse_transform(class_ids)

            top5 = top_k_from_proba(mean_proba, decoded_labels, k=5)
            top5_df = pd.DataFrame(top5, columns=["Attack Type", "Probability"])

            c1, c2 = st.columns([2, 1])

            with c1:
                st.subheader("Top-5 Predicted Cyberattacks")
                st.dataframe(top5_df, use_container_width=True)

            with c2:
                st.subheader("Summary")
                st.metric("Rows analysed", len(df_in))
                st.metric("Top prediction", top5_df.iloc[0]["Attack Type"])

            st.subheader("Probability chart (Top-5)")
            st.bar_chart(top5_df.set_index("Attack Type")["Probability"])

        except Exception as e:
            st.error(str(e))
            st.info("Tip: Use the template format first to confirm the pipeline works end-to-end.")
