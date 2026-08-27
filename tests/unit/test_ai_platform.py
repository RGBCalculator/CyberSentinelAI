import pytest
from ai_platform.core.schemas import PredictionRequest, PredictionResponse, ModelMetadata
from ai_platform.core.interfaces import ModelProvider, FeatureExtractor
from ai_platform.engine.registry import ModelRegistry
from ai_platform.engine.manager import ModelManager
from ai_platform.engine.inference import InferenceEngine

class DummyProvider(ModelProvider):
    def metadata(self) -> ModelMetadata:
        return ModelMetadata(name="dummy", version="1.0", framework="custom")

    async def predict(self, extracted_features) -> tuple[float, bool]:
        return (0.95, True)

    async def load(self) -> None:
        pass

    async def unload(self) -> None:
        pass

class DummyExtractor(FeatureExtractor):
    def extract(self, raw_data):
        return [raw_data.get("value", 0)]

@pytest.mark.asyncio
async def test_ai_platform_pipeline():
    registry = ModelRegistry()
    manager = ModelManager(registry)
    engine = InferenceEngine(registry)

    provider = DummyProvider()
    extractor = DummyExtractor()

    # 1. Load model via manager
    success = await manager.load_model_async(provider)
    assert success is True

    # 2. Register extractor
    engine.register_extractor("dummy", extractor)

    # 3. Predict via engine
    req = PredictionRequest(model_name="dummy", raw_data={"value": 42})
    res = await engine.predict(req)

    assert res.model_name == "dummy"
    assert res.confidence == 0.95
    assert res.is_malicious is True
    assert res.metadata["framework"] == "custom"
    assert "latency_ms" in res.metadata

    # 4. Unload model
    success = await manager.unload_model("dummy", "1.0")
    assert success is True
