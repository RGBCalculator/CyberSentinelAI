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

## CyberSentinel AI SOC 2.0 Capabilities
The unified Security Operations Center (SOC) dashboard includes:
- **SOC Executive Overview**: Real-time risk scoring with transparent mathematical formula explanation, animated KPI count-ups, scanner health, recent detections, and operational shortcuts.
- **Deep SSL/TLS & Website Security**: Full X.509 certificate telemetry (SANs, SHA-256 fingerprint, days to expiration, key size/algorithm, TLS version, cipher suite, HTTP-to-HTTPS redirect test, verification error breakdowns).
- **Curated BadSSL Test Cases**: Controlled test targets (`neverssl.com`, `expired.badssl.com`, `self-signed.badssl.com`, `wrong.host.badssl.com`, `untrusted-root.badssl.com`) labeled as *Certificate Test Cases — Not Confirmed Malicious*.
- **SSRF Defense-in-Depth (V2)**: Comprehensive protection against dword/octal/hex IPs, link-local/cloud metadata (`169.254.169.254`, `fd00:ec2::254`), IPv4-mapped IPv6, restricted internal ports, redirect re-validation, and response size limits.
- **Fake Login Page & Phishing Detection**: Sandboxed DOM analysis detecting brand impersonation (Microsoft, Google, Apple, etc.), cross-origin form submissions, raw IP destinations, and credential harvesting patterns (`POST /api/v1/scan/fake-login`).
- **Manifest V3 Browser Extension**: Client sensor in `browser-extension/` allowing one-click active tab scanning with links back to the SOC dashboard.
- **Threat Intelligence Hub**: In-memory bounded TTL caching (15 min) and honest connector status for VirusTotal, PhishTank, OpenPhish, and AbuseIPDB.
- **Defensive API Hardening**: Automated security headers middleware (`X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`, `Permissions-Policy`), `/ready` MongoDB readiness probe, and `/health` liveness probe.

## Installation & Running Locally

### Option A: Docker Compose (Recommended)
```bash
docker compose up -d --build
```
- Frontend: `http://localhost:3000`
- Backend API & Swagger: `http://localhost:8000/docs`
- Readiness Probe: `http://localhost:8000/ready`
- Liveness Probe: `http://localhost:8000/health`
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

### Loading the Browser Extension (Chrome / Edge)
1. Open `chrome://extensions/` in your browser.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select the folder `browser-extension/`.

## Running the Automated Test Suite
```bash
$env:PYTHONPATH="backend;."; pytest tests/unit -v
```
All 40 unit and regression tests validate SSRF protection, certificate extraction, brand impersonation detection, API security headers, and extension contracts.

