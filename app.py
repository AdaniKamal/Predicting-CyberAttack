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
st.title("Top 5 Cyberattack Prediction")
st.caption("Upload a Vulnerability Asssessment Result (CSV). The model outputs Top-5 predicted cyberattacks with probabilities.")

# ---------- UI Controls ----------
st.sidebar.header("Settings")
show_diag = st.sidebar.toggle("🛠 Diagnostics", value=False)

# Keep sidebar collapsed feel by putting minimal items here
def diagnostics_panel():
    with st.expander("⚙️ Diagnostics"):
        st.write("BASE_DIR:", BASE_DIR)
        st.write("MODELS_DIR exists:", os.path.exists(MODELS_DIR))
        if os.path.exists(MODELS_DIR):
            st.write("Files in models/:", os.listdir(MODELS_DIR))
        st.write("RF_PATH exists:", os.path.exists(RF_PATH))
        st.write("ENCODER_PATH exists:", os.path.exists(ENCODER_PATH))
        st.write("FEATURE_COLS_PATH exists:", os.path.exists(FEATURE_COLS_PATH))

if show_diag:
    diagnostics_panel()
# ----------------------------------

@st.cache_resource
def load_assets():
    rf = joblib.load(RF_PATH)
    encoders = joblib.load(ENCODER_PATH)
    feature_cols = joblib.load(FEATURE_COLS_PATH)
    return rf, encoders, feature_cols

rf, encoders, feature_cols = load_assets()

REQUIRED_COLS = ["cvss_score", "severity", "family", "verified_flag"] #Required columns

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

    # verified_flag: support 1/0, True/False, Yes/No (case-insensitive)
    df["verified_flag"] = (
        df["verified_flag"]
        .astype(str)
        .str.strip()
        .str.lower()
        .isin(["1", "true", "yes", "y"])
        .astype(int)
     )

    # Encode categorical columns exactly as training
    df["severity"] = safe_label_transform(encoders["severity"], df["severity"])
    df["family"] = safe_label_transform(encoders["family"], df["family"])
   
    X_user = df[["cvss_score", "severity", "family", "verified_flag"]].copy()

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
    "verified_flag": [1, 0, 0]
})

# ------------------------- GUIDE -----------------------------
with st.expander("📘 How to use Predict Attack (Guide)"):
    st.markdown("""
### Required columns (case-insensitive)

Your CSV must include these **5 columns**:

- `cvss_score`: numeric (0.0 – 10.0)
- `severity`: LOW / MEDIUM / HIGH / CRITICAL
- `family`: vulnerability family or technology domain (e.g., Web Servers, Databases, General)
- `verified_flag`: 1 = exploit available/verified, 0 = no known exploit

### Notes
- Extra columns are **ignored**.
- Missing values:
  - `cvss_score` will default to **5.0**
  - `verified_flag` will default to **0**
- For categorical fields (severity / family), unseen values are mapped to **UNKNOWN**.

### How prediction works
Predict_Attack calculates probabilities for each row and then **aggregates (mean)** across all uploaded vulnerabilities to produce the **Top-5 predicted cyberattack types**.
""")
    st.download_button(
        "Download example.csv",
        data=template_df.to_csv(index=False).encode("utf-8"),
        file_name="predict_attack_example.csv",
        mime="text/csv"
    )
    st.dataframe(template_df, use_container_width=True)
# ----------------------------------

# ------------------------- Helper function - Smarter Upload Validation -----------------------------
def validate_input_df(df: pd.DataFrame):
    df2 = df.copy()

    # Normalize column names (case-insensitive)
    df2.columns = [c.strip().lower() for c in df2.columns]

    # Column alias mapping
    alias_map = {
        "cvss": "cvss_score",
        "cvssbase": "cvss_score",
        "exploit": "verified_flag",
        "exploit_available": "verified_flag",
        "exploitability": "verified_flag"
    }

    for alias, canonical in alias_map.items():
        if alias in df2.columns and canonical not in df2.columns:
            df2[canonical] = df2[alias]

    missing = [c for c in REQUIRED_COLS if c not in df2.columns]
    extra = [c for c in df2.columns if c not in REQUIRED_COLS]

    return df2, missing, extra

# ----------------------------------

# ------------------------- Upload - Smarter Upload Validation -----------------------------
uploaded = st.file_uploader("Upload your vulnerability list (CSV)", type=["csv"])

ready = False
df_norm = None

if uploaded:
    df_raw = pd.read_csv(uploaded)

    st.subheader("Uploaded data preview")
    st.dataframe(df_raw.head(20), use_container_width=True)

    df_norm, missing_cols, extra_cols = validate_input_df(df_raw)

    st.subheader("Input validation")

    if missing_cols:
        st.error(f"Missing required columns: {missing_cols}")
        st.info("Tip: Download the example CSV in the Input Guide and follow the same column names.")
        ready = False
    else:
        st.success("✅ Input format looks good. Ready to predict.")
        ready = True

    if extra_cols:
        st.warning(f"Extra columns will be ignored: {extra_cols[:12]}" + (" ..." if len(extra_cols) > 12 else ""))

    predict_clicked = st.button("Predict Top-5 Cyberattacks", disabled=not ready)

    if predict_clicked:
        try:
            X_user = build_features(df_norm)

            proba = rf.predict_proba(X_user)
            mean_proba = proba.mean(axis=0)

            class_ids = rf.classes_

            attack_le = encoders["attack_type"]
            decoded_labels = attack_le.inverse_transform(class_ids)

            top5 = top_k_from_proba(mean_proba, decoded_labels, k=5)
            top5_df = pd.DataFrame(top5, columns=["Attack Type", "Probability"])

            # Format probability nicely for display
            top5_df["Probability (%)"] = (top5_df["Probability"] * 100).round(2)
            top5_df_display = top5_df[["Attack Type", "Probability (%)"]].copy()

            top_attack = top5_df_display.iloc[0]["Attack Type"]
            top_prob = top5_df_display.iloc[0]["Probability (%)"]

            c1, c2 = st.columns([2, 1])

            with c1:
                st.subheader("Top-5 Predicted Cyberattacks")
                st.dataframe(top5_df_display, use_container_width=True)

            with c2:
                st.subheader("Summary")
                st.metric("Rows analysed", len(df_norm))
                st.metric("Top prediction", top5_df.iloc[0]["Attack Type"])

            st.subheader("Probability chart (Top-5)")
            st.bar_chart(top5_df.set_index("Attack Type")["Probability"])

            # ------------------------- Interpretation -----------------------------
            st.subheader("Interpretation")
            st.write(
                f"The model indicates the most probable attack pattern is **{top_attack}** "
                f"with an aggregated confidence of **{top_prob}%** based on the uploaded vulnerability list."
            )

            st.subheader("Recommended next steps (bank workflow)")
            st.markdown("""
            1. **Validate exposure**: confirm affected assets are internet-facing or reachable from high-risk network segments.
            2. **Prioritize patching**: start with vulnerabilities that have **exploit availability** and higher CVSS.
            3. **Compensating controls**: apply WAF rules / IPS signatures / segmentation where patching is delayed.
            4. **Threat hunting**: search for IOCs and suspicious activity aligned to the Top-5 attack patterns.
            5. **Retest**: rerun VA after remediation and compare Top-5 shifts over time.
            """)
            # -------------------------

        except KeyError:
            st.error("Model encoder key mismatch. (attack_type encoder not found). Tell the developer to align encoder keys.")
        except Exception as e:
            st.error(str(e))
            st.info("Tip: Use the example CSV first to confirm the pipeline works end-to-end.")
   # ----------------------------------
