# AI-Powered SOC Dashboard — V1

First working backend prototype.

## Pipeline
Security Event Simulator -> FastAPI -> SQLite -> Detection -> Correlation -> Risk Scoring -> Response Recommendation

## Run
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload

Open http://127.0.0.1:8000/docs

In another terminal:
pip install requests
python simulator/bruteforce_demo.py

The simulator sends only synthetic events to localhost.
