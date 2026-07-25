# High Level Architecture

CyberSentinel AI is built on a modern, microservice-ready architecture to ensure scalability, maintainability, and enterprise-grade performance. 

## 1. Components
- **Frontend Layer**: React SPA communicating via REST APIs.
- **Backend API Layer**: FastAPI handles incoming requests, authentication, and routing.
- **Core Processing Layer**: Scanners, ML prediction engines, and Threat Intelligence orchestrators.
- **Data Layer**: MongoDB for storing users, scan histories, and analytics data.
- **Machine Learning Layer**: Offline training pipeline and online inference APIs.

## 2. Folder Explanation
- `frontend/`: Contains the React UI with state management, hooks, components, and Tailwind styling.
- `backend/`: Contains the FastAPI application, modularized into routers, services, ml integration, and database operations.
- `machine_learning/`: Responsible for training models, data generation (datasets), feature engineering, and saving models to `saved_models/`.
- `browser_extension/`: Source code for the future real-time protection browser plugin.
- `datasets/` & `database/`: Local data storage and raw datasets.
- `docker/`: Contains advanced docker-compose setups or Kubernetes manifests for deployment.

## 3. Data Flow
1. User requests a scan via Frontend UI or Browser Extension.
2. API Gateway (FastAPI) authenticates the request using JWT.
3. Scanner Service checks Threat Intelligence APIs (VirusTotal, PhishTank, AbuseIPDB).
4. Scanner Service extracts features (URL, HTML, JS).
5. ML Service runs predictions (Random Forest, XGBoost, Deep Learning).
6. Explainability Service (SHAP/LIME) generates feature importance for the verdict.
7. Results are aggregated, stored in MongoDB, and returned to the client.
8. Frontend renders results on the Analytics Dashboard.

## 4. Microservice Readiness
While starting as a modular monolith in the `backend` folder, the architecture strictly separates concerns (`api`, `core`, `ml`, `scanner`). These modules can easily be extracted into separate microservices communicating via message brokers (e.g., Kafka or RabbitMQ) as the platform scales.

## 5. Scalability
- **Compute**: Stateless FastAPI backend horizontally scales behind a load balancer.
- **Data**: MongoDB allows sharding for massive scan history storage.
- **ML**: Model inference can be deployed on specialized GPU nodes using TensorFlow Serving or standard Docker containers.

## 6. Future Modules
- Browser Extension for real-time protection.
- QR Code Phishing Detection using pyzbar and OpenCV.
- Deep Learning Fake Login Detection using computer vision.
