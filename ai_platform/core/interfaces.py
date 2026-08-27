from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple
from ai_platform.core.schemas import ModelMetadata

class FeatureExtractor(ABC):
    """
    Interface for transforming raw prediction request data into framework-specific tensors/arrays.
    """
    @abstractmethod
    def extract(self, raw_data: Dict[str, Any]) -> Any:
        """
        Transforms raw data dictionary into the model's required input type.

        Args:
            raw_data: The raw input dictionary from the PredictionRequest.

        Returns:
            The framework-specific input (e.g., numpy array, torch tensor).
        """
        pass

class ModelProvider(ABC):
    """
    Abstract Base Class for all ML Models (TensorFlow, PyTorch, XGBoost, etc.).
    Business logic must never import ML frameworks directly; they interact only via this interface.
    """
    @abstractmethod
    def metadata(self) -> ModelMetadata:
        """
        Returns the metadata associated with this model provider.
        """
        pass

    @abstractmethod
    async def predict(self, extracted_features: Any) -> Tuple[float, bool]:
        """
        Executes a prediction using the underlying ML framework.

        Args:
            extracted_features: The output from a FeatureExtractor.

        Returns:
            Tuple containing:
            - confidence (float): Score between 0.0 and 1.0.
            - is_malicious (bool): Binary classification result.
        """
        pass

    @abstractmethod
    async def load(self) -> None:
        """
        Loads the model weights from storage into memory.
        Must be implemented in a non-blocking or background-safe manner.
        """
        pass

    @abstractmethod
    async def unload(self) -> None:
        """
        Unloads the model weights from memory, freeing resources.
        """
        pass

class ExplanationProvider(ABC):
    """
    Interface for model explainability engines (e.g., SHAP, LIME).
    """
    @abstractmethod
    async def explain(self, provider: ModelProvider, extracted_features: Any) -> Dict[str, Any]:
        """
        Generates feature importance or explanations for a specific prediction.

        Args:
            provider: The ModelProvider instance that made the prediction.
            extracted_features: The features used for the prediction.

        Returns:
            Dictionary containing the explanation metrics.
        """
        pass

class HealthProvider(ABC):
    """
    Interface for checking system and model health status.
    """
    @abstractmethod
    async def check_system_health(self) -> Dict[str, Any]:
        """Returns overall AI Platform health metrics."""
        pass

    @abstractmethod
    async def check_model_health(self, model_name: str, model_version: str) -> bool:
        """Returns True if the specific model is loaded and ready for inference."""
        pass
