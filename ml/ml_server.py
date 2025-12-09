from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import joblib
import os

# ---------- App ----------
app = FastAPI(title="AI-NGFW ML Scoring Service", version="1.0")

# ---------- CORS (optional but recommended for production) ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Load Model ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.joblib")

try:
    model = joblib.load(MODEL_PATH)
except Exception as e:
    raise Exception(f"❌ Failed to load model.joblib: {e}")


# ---------- Request Schema ----------
class RequestContext(BaseModel):
    method: str
    path: str
    role: str
    userId: str
    userAgent: str
    risk_rule: float


# ---------- Health Check ----------
@app.get("/")
def health():
    return {"status": "ok", "service": "AI-NGFW ML model"}


# ---------- Scoring API ----------
@app.post("/score")
def score(context: RequestContext):
    try:
        row = {
            "method": context.method,
            "path": context.path,
            "role": context.role,
            "userId": context.userId,
            "userAgent": context.userAgent,
            "risk_rule": context.risk_rule,
        }

        df = pd.DataFrame([row])

        # Predict probability of attack
        proba = model.predict_proba(df)[0][1]

        # Risk label
        if proba < 0.3:
            label = "normal"
        elif proba < 0.6:
            label = "medium_risk"
        else:
            label = "high_risk"

        return {"ml_risk": float(proba), "ml_label": label}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------- Run ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
