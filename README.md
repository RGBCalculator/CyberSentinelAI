# CyberSentinel AI
An AI-Powered Unified Cybersecurity Platform for Real-Time Threat Detection, Website Security Analysis, Threat Intelligence and Explainable AI.

## Project Description
CyberSentinel AI is a commercial-grade cybersecurity platform that integrates advanced threat detection mechanisms. It utilizes Machine Learning models for analyzing URLs, detecting phishing and malware, alongside offering a comprehensive suite of security tools including SSL Analysis, WHOIS lookup, and more.

## Architecture
The platform is designed as a modular, microservices-ready architecture:
- **Frontend**: A React application built with Vite and TailwindCSS for a responsive and dynamic user experience.
- **Backend**: A scalable FastAPI application handling API requests, business logic, and security workflows.
- **Machine Learning**: Dedicated modules for training and serving predictive models using scikit-learn, XGBoost, TensorFlow, and Explainable AI (SHAP, LIME).
- **Database**: MongoDB for flexible, high-performance data storage.
- **Threat Intelligence**: Integrations with VirusTotal, PhishTank, OpenPhish, and AbuseIPDB.

## Folder Structure
- `/frontend`: React + Vite + TailwindCSS application.
- `/backend`: FastAPI backend and services.
- `/machine_learning`: ML models, training scripts, and explainability modules.
- `/documentation`: Architecture, API specs, and project docs.
- `/docker`: Docker and deployment configurations.
- `/database`, `/datasets`, `/browser_extension`, `/scripts`, `/tests`, `/logs`: Supporting directories.

## Tech Stack
- **Frontend**: React, Vite, TailwindCSS, Framer Motion, React Router, Axios, React Hook Form, Chart.js.
- **Backend**: Python, FastAPI, Pydantic, Uvicorn, JWT, bcrypt.
- **Database**: MongoDB, Motor.
- **Machine Learning**: Scikit-Learn, Random Forest, XGBoost, SHAP, LIME, TensorFlow, PyTorch, OpenCV, pyzbar.
- **Deployment**: Docker, Docker Compose, GitHub, Render.

## CyberSentinel AI SOC Capabilities
The unified Security Operations Center (SOC) dashboard includes:
- **SOC Executive Overview**: Real-time risk scoring, posture distribution, scanner health, recent detections, and operational shortcuts.
- **URL Threat Scanner**: Real-time multi-stage threat detection engine combining static heuristics, rule engines, live threat feeds, and AI analysis.
- **Website Security & Trust Intelligence**: Deep SSL/TLS certificate analysis, domain provenance, DNS inspection, and calculated trust ratings.
- **Threat Intelligence Hub**: Provider status matrix and live indicator lookup for VirusTotal, PhishTank, OpenPhish, and AbuseIPDB.
- **Findings Explorer**: High-density findings management with severity filters, asset drilldowns, and remediation guidance.
- **Explainable AI (XAI) Workbench**: Feature attribution waterfall charts, local feature weights, and calibrated probability scoring.
- **Executive Security Reports**: Printable briefings and downloadable JSON audits.
- **SSRF Safety Engine**: Protection against loopback, cloud metadata (AWS/GCP/Azure `169.254.169.254`), and RFC1918 subnets.

## Installation & Running Locally

### Option A: Docker Compose (Recommended)
```bash
docker compose up -d --build
```
- Frontend: `http://localhost:3000`
- Backend API & Swagger: `http://localhost:8000/docs`
- MongoDB: `localhost:27017`

### Option B: Local Development
```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

## Running Unit Tests
```bash
python -m pytest -o pythonpath="backend ." tests/unit -v
```

