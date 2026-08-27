from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class PredictionRequest(BaseModel):
    """
    Standardized input request for all AI inferences.
    """
    model_name: str = Field(..., description="The registered name of the model.")
    model_version: Optional[str] = Field(None, description="Specific version of the model to target.")
    raw_data: Dict[str, Any] = Field(..., description="The raw features or payload for prediction.")
    request_explanation: bool = Field(default=False, description="Whether to compute and return explainability metrics (SHAP/LIME).")

class PredictionResponse(BaseModel):
    """
    Standardized output response for all AI inferences.
    """
    model_name: str
    model_version: str
    confidence: float = Field(..., description="Confidence score from 0.0 to 1.0.")
    is_malicious: bool = Field(..., description="Binary classification result.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata from the prediction (e.g., latency, framework).")
    explanation: Optional[Dict[str, Any]] = Field(None, description="Explainability payload if requested.")

class ModelMetadata(BaseModel):
    """
    Metadata associated with a registered AI Model.
    """
    name: str
    version: str
    framework: str = Field(..., description="E.g., tensorflow, pytorch, xgboost, onnx")
    required_features: List[str] = Field(default_factory=list, description="List of keys expected in PredictionRequest.raw_data")
    target_latency_ms: float = Field(default=100.0, description="SLA for prediction latency")
