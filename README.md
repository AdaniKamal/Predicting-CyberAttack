# Predicting-Vulnerability

## Overview
Its about my Master project. This Github mainly used for stored all the related files, versioning controls and prototype.

## Dataset
Contains raw and processed vulnerability assessment datasets from Kaggle, NVD, Exploit-DB, Tenable

## Methodology
Random Forest vs Neural Network Classification

## Project Structure

```text
📦 Predicting-Vulnerability-Susceptibility
├── 📁 data
│   ├── ExploitDB
│   │   └── exploitdb_with_cve_exploded.csv
│   └── Kaggle
│   │   └── kaggle.csv
|   └── NVD
│   │   └── cve_2025.csv
│   └── Tenable
│   │   └── tenable_2025.csv
│   └── processed
│       ├── exploitdb_clean.csv
│       ├── kaggle_clean.csv
│       ├── nvd_clean.csv
│       └── tenable_clean.csv
│
├── 📁 scripts
│   ├── 01_data_overview.ipynb
│   ├── ExploitDB.ipynb
│   ├── ExploitDB_CVE_extractor.ipynb
│   ├── Tenable_CVE_extractor.ipynb
│   ├── cve.ipynb
│   └── tenable.ipynb
│
├── 📁 models
│   ├── rf_attack_prediction_model.pkl
│   ├── rf_encoders.pkl
│   └── rf_feature_columns.pkl
│
├── 📁 streamlit_app
│   ├── app.py
│   ├── app_v1.py
│   ├── app_v2.py
│   ├── app_v3.py
│   └── app_v4.py
│
├── 📁 docs
│   ├── CSP760 - Week 2.pdf
│   ├── CSP760 - Week 3.pdf
│   ├── CSP760 - Week 4.pdf
│   ├── CSP760 - Week 7.pdf
│   ├── CSP760 - Week 8.pdf
│   └── CSP760 - Week 10.pdf
│
├── requirements.txt
└── README.md
```

## How to Run
[(OPEN)](https://predict-attack.streamlit.app/)


### UPDATE
App.py --> Will always use this name for Streamlit (Latest files)
|File|Dates|Description|
|----|-----|-----------|
|app_v1.py|19/12/2025|Ori file|
|app_v2.py|20/12/2025|Update debug part|
|app_v3.py|20/12/2025|Update rm expander block|
|app_v4.py|20/12/2025|Update Guide|
|app.py|20/12/2025|Update - Smarter Upload Validation|

Thank You



