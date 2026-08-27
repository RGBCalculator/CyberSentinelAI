import time
import logging
from typing import Optional, Dict
from ai_platform.core.schemas import PredictionRequest, PredictionResponse
from ai_platform.core.interfaces import FeatureExtractor, ExplanationProvider
from ai_platform.engine.registry import ModelRegistry

logger = logging.getLogger(__name__)

class InferenceEngine:
    """
    The coordinator for all AI predictions.
    Validates requests, orchestrates feature extraction, delegates to the ModelRegistry,
    and handles explainability.
    """
    def __init__(self, registry: ModelRegistry):
        self.registry = registry
        self.extractors: Dict[str, FeatureExtractor] = {}
        self.explainers: Dict[str, ExplanationProvider] = {}

    def register_extractor(self, model_name: str, extractor: FeatureExtractor) -> None:
        """Registers a FeatureExtractor for a specific model."""
        self.extractors[model_name] = extractor

    def register_explainer(self, model_name: str, explainer: ExplanationProvider) -> None:
        """Registers an ExplanationProvider for a specific model."""
        self.explainers[model_name] = explainer

    async def predict(self, request: PredictionRequest) -> PredictionResponse:
        """
        Executes the full inference pipeline.
        """
        start_time = time.time()

        provider = self.registry.get_provider(request.model_name, request.model_version)
        if not provider:
            raise ValueError(f"Model {request.model_name} v{request.model_version or 'latest'} not found.")

        metadata = provider.metadata()

        # 1. Feature Extraction
        extractor = self.extractors.get(request.model_name)
        if not extractor:
            raise ValueError(f"No FeatureExtractor registered for model {request.model_name}.")

        try:
            features = extractor.extract(request.raw_data)
        except Exception as e:
            raise ValueError(f"Feature extraction failed: {e}")

        # 2. Prediction
        try:
            confidence, is_malicious = await provider.predict(features)
        except Exception as e:
            logger.error(f"Prediction failed for {request.model_name}: {e}", exc_info=True)
            raise RuntimeError(f"Prediction execution failed: {e}")

        # 3. Explainability
        explanation = None
        if request.request_explanation:
            explainer = self.explainers.get(request.model_name)
            if explainer:
                try:
                    explanation = await explainer.explain(provider, features)
                except Exception as e:
                    logger.warning(f"Explainability generation failed for {request.model_name}: {e}")
            else:
                logger.warning(f"Explanation requested but no Explainer registered for {request.model_name}")

        latency_ms = (time.time() - start_time) * 1000

        return PredictionResponse(
            model_name=metadata.name,
            model_version=metadata.version,
            confidence=confidence,
            is_malicious=is_malicious,
            metadata={
                "latency_ms": latency_ms,
                "framework": metadata.framework,
            },
            explanation=explanation
        )
