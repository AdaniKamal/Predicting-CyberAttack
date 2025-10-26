# Pure-Orange script: add "Severity" from "CVSS Score" (works in 3.39)
import numpy as np
from Orange.data import Table, Domain, DiscreteVariable

# ---- CONFIG ----
CANDIDATE_NAMES = ["CVSS Score", "cvss_score", "CVSS_Score", "cvss", "cvss3"]

# 1) Locate the CVSS column in attributes, class vars, or metas
dom = in_data.domain

def find_column(varnames, candidates):
    for i, v in enumerate(varnames):
        if v in candidates or v.lower().replace(" ", "_") in candidates:
            return i
    return None

attr_names = [v.name for v in dom.attributes]
class_names = [v.name for v in dom.class_vars]
meta_names = [v.name for v in dom.metas]

col_src = None
col_idx = find_column(attr_names, CANDIDATE_NAMES)
if col_idx is not None:
    col_src = ("X", col_idx)
else:
    col_idx = find_column(class_names, CANDIDATE_NAMES)
    if col_idx is not None:
        col_src = ("Y", col_idx)
    else:
        col_idx = find_column(meta_names, CANDIDATE_NAMES)
        if col_idx is not None:
            col_src = ("M", col_idx)

if col_src is None:
    raise ValueError(
        f"Could not find a CVSS column. Columns available: "
        f"{attr_names + class_names + meta_names}"
    )

# 2) Extract numeric CVSS values as a 1-D numpy array
src, idx = col_src
if src == "X":
    cvss_vals = in_data.X[:, idx]
elif src == "Y":
    # If class var, Y can be 1-D or 2-D; ensure 1-D
    y = in_data.Y
    if y.ndim == 2 and y.shape[1] > 1:
        cvss_vals = y[:, idx]
    else:
        cvss_vals = y.ravel()
else:  # metas
    cv = in_data.metas[:, idx]
    # metas are stored as objects; coerce to float where possible
    def safe_float(x):
        try:
            return float(x)
        except Exception:
            return np.nan
    cvss_vals = np.array([safe_float(x) for x in cv], dtype=float)

# 3) Map CVSS -> Severity index (0..4)
sev_names = ["None", "Low", "Medium", "High", "Critical"]

def map_severity(s):
    if s != s or s is None:   # NaN check
        return 0  # "None"
    if s >= 9.0:  return 4   # "Critical"
    if s >= 7.0:  return 3   # "High"
    if s >= 4.0:  return 2   # "Medium"
    if s >  0.0:  return 1   # "Low"
    return 0

sev_idx = np.array([map_severity(float(x)) for x in cvss_vals], dtype=float).reshape(-1, 1)

# 4) Build new domain with the new Discrete attribute (not class yet)
sev_var = DiscreteVariable("Severity", values=sev_names)
new_domain = Domain(tuple(dom.attributes) + (sev_var,), dom.class_vars, dom.metas)

# 5) Assemble new Table (append the new column to X)
new_X = np.column_stack([in_data.X, sev_idx])
out_data = Table(new_domain, new_X, in_data.Y, in_data.metas)

# other (unused) outputs
out_learner = None
out_classifier = None
out_object = None
