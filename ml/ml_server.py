from fastapi import FastAPI
import joblib
import uvicorn
import os
from pydantic import BaseModel

# -------- Load trained ML model --------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.joblib")
model = joblib.load(model_path)

app = FastAPI(title="AI-NGFW ML Scoring Service")

# -------- Request schema --------
class RequestContext(BaseModel):
    method: str
    path: str
    role: str
    userId: str
    userAgent: str
    risk_rule: float

# -------- Scoring endpoint --------
@app.post("/score")
def score(context: RequestContext):

    # Make a dataframe with a single row
    row = {
        "method": context.method,
        "path": context.path,
        "role": context.role,
        "userId": context.userId,
        "userAgent": context.userAgent,
        "risk_rule": context.risk_rule,
    }

    import pandas as pd
    df = pd.DataFrame([row])

    # Predict probabilities
    proba = model.predict_proba(df)[0][1]   # probability of is_attack == 1

    # Labeling
    if proba < 0.3:
        label = "normal"
    elif proba < 0.6:
        label = "medium_risk"
    else:
        label = "high_risk"

    return {
        "ml_risk": float(proba),
        "ml_label": label
    }

# -------- Run server --------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
