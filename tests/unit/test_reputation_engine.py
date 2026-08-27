import pytest

from app.scanner.trust.reputation.engine import ReputationEngine
from app.scanner.trust.reputation.base import BaseReputationProvider
from app.scanner.trust.reputation.schemas import ReputationFinding, ProviderMetadata

class MockProvider(BaseReputationProvider):
    def __init__(self, name: str, malicious: bool, confidence: float):
        self._name = name
        self._malicious = malicious
        self._confidence = confidence

    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(name=self._name, version="1.0", enabled=True, reliability=0.9)

    async def lookup(self, indicator: str):
        return ReputationFinding(
            provider=self._name,
            malicious=self._malicious,
            confidence=self._confidence,
            details={}
        )

class FailingProvider(BaseReputationProvider):
    @property
    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(name="Failing", version="1.0", enabled=True, reliability=0.9)

    async def lookup(self, indicator: str):
        raise Exception("Simulated failure")

@pytest.mark.asyncio
async def test_reputation_engine_empty():
    engine = ReputationEngine()
    result = await engine.analyze("example.com")
    assert result.provider_count == 0
    assert result.malicious is False
    assert result.confidence == 0.0

@pytest.mark.asyncio
async def test_reputation_engine_with_providers():
    engine = ReputationEngine()
    engine.registry.register(MockProvider("Prov1", malicious=False, confidence=0.8))
    engine.registry.register(MockProvider("Prov2", malicious=True, confidence=0.9))

    result = await engine.analyze("example.com")

    assert result.provider_count == 2
    assert result.malicious_count == 1
    assert result.malicious is True
    assert result.confidence == pytest.approx(0.85)
    assert len(result.findings) == 2

@pytest.mark.asyncio
async def test_reputation_engine_resilience():
    engine = ReputationEngine()
    engine.registry.register(MockProvider("Prov1", malicious=False, confidence=0.8))
    engine.registry.register(FailingProvider())

    result = await engine.analyze("example.com")

    assert result.provider_count == 2
    assert result.malicious_count == 0
    assert len(result.findings) == 1
    assert result.findings[0].provider == "Prov1"
