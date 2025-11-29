import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
import joblib
import os

# 1) Load the CSV
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(BASE_DIR, "dataset.csv")

print("Loading dataset from:", csv_path)
df = pd.read_csv(csv_path)

print("Rows in dataset:", len(df))
print(df.head())

# 2) Create a simple target label:
#    is_attack = 1 if statusCode >= 400 OR label_rule is high_risk
df["is_attack"] = (
    (df["statusCode"] >= 400) |
    (df["label_rule"].isin(["high_risk"]))
).astype(int)

print("Attack label distribution:\n", df["is_attack"].value_counts())

# 3) Features we will use
feature_cols = ["method", "path", "role", "userId", "userAgent", "risk_rule"]
X = df[feature_cols]
y = df["is_attack"]

# Separate categorical and numeric columns
categorical_cols = ["method", "path", "role", "userId", "userAgent"]
numeric_cols = ["risk_rule"]

# 4) Build preprocessing + model pipeline
preprocess = ColumnTransformer(
    transformers=[
        ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_cols),
        ("num", "passthrough", numeric_cols),
    ]
)

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

clf = Pipeline(steps=[
    ("preprocess", preprocess),
    ("model", model)
])

# 5) Train / test split (even if tiny, just for structure)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42, stratify=y
)

print("Training shape:", X_train.shape, " Test shape:", X_test.shape)

# 6) Fit the model
clf.fit(X_train, y_train)

# 7) Evaluate quickly
train_score = clf.score(X_train, y_train)
test_score = clf.score(X_test, y_test)
print(f"Train accuracy: {train_score:.3f}")
print(f"Test  accuracy: {test_score:.3f}")

# 8) Save the model
model_path = os.path.join(BASE_DIR, "model.joblib")
joblib.dump(clf, model_path)
print("Saved model to:", model_path)
