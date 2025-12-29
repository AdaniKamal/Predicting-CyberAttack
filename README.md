# Predicting-Vulnerability

## Overview
Its about my Master project. This Github mainly used for stored all the related files, versioning controls and prototype.

## Dataset
Contains raw and processed vulnerability assessment datasets from Kaggle, NVD, Exploit-DB, Tenable

## Methodology
Random Forest vs Neural Network Classification

## Project Structure
## Project Structure

```text
📦 Predicting-Vulnerability-Susceptibility
├── 📁 data
│   ├── raw
│   │   ├── kaggle_vulnerability_data.csv
│   │   └── tenable_plugins.csv
│   └── processed
│       ├── cleaned_vulnerability_data.csv
│       └── merged_vulnerability_data.csv
│
├── 📁 notebooks
│   ├── 01_data_exploration.ipynb
│   ├── 02_data_cleaning.ipynb
│   ├── 03_model_training.ipynb
│   └── 04_model_evaluation.ipynb
│
├── 📁 models
│   ├── random_forest_model.pkl
│   └── neural_network_model.h5
│
├── 📁 streamlit_app
│   └── app.py
│
├── 📁 docs
│   ├── proposal.pdf
│   ├── week2_update.pdf
│   └── week3_update.pdf
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



