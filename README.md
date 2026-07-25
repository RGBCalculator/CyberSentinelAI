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

## Installation
1. Clone the repository.
2. Setup environment variables using `.env.example`.
3. Start backend services: `cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload`
4. Start frontend app: `cd frontend && npm install && npm run dev`
5. (Optional) Run via Docker: `docker-compose up -d`

## Future Modules
- Browser Extension for real-time protection.
- QR Code Phishing Detection.
- Deep Learning based Fake Login Page Detection.
- Automated Report Generation & Advanced Analytics Dashboard.

## Development Roadmap
See `documentation/Roadmap.md` for a detailed phased approach.
