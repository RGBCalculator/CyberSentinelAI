import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.scanner.trust.providers.common.http_client import EnterpriseHTTPClient

@pytest.mark.asyncio
async def test_http_client_initialization():
    client = EnterpriseHTTPClient(timeout=5.0)
    assert client._client is not None
    assert client._client.timeout.read == 5.0
    await client.close()

@pytest.mark.asyncio
async def test_http_client_get_success():
    client = EnterpriseHTTPClient()
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.raise_for_status = MagicMock()

    with patch.object(client._client, "request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_response
        response = await client.get("https://example.com")

        assert response is not None
        assert response.status_code == 200
        mock_request.assert_called_once_with("GET", "https://example.com", params=None, headers=None)

    await client.close()

@pytest.mark.asyncio
async def test_http_client_get_timeout():
    client = EnterpriseHTTPClient()

    with patch.object(client._client, "request", new_callable=AsyncMock) as mock_request:
        mock_request.side_effect = httpx.TimeoutException("Timeout")
        response = await client.get("https://example.com")

        assert response is None

    await client.close()

@pytest.mark.asyncio
async def test_http_client_post_success():
    client = EnterpriseHTTPClient()
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 201
    mock_response.raise_for_status = MagicMock()

    with patch.object(client._client, "request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = mock_response
        payload = {"test": "data"}
        response = await client.post("https://example.com", json=payload)

        assert response is not None
        assert response.status_code == 201
        mock_request.assert_called_once_with("POST", "https://example.com", json=payload, data=None, headers=None)

    await client.close()

@pytest.mark.asyncio
async def test_http_client_http_status_error():
    client = EnterpriseHTTPClient()

    with patch.object(client._client, "request", new_callable=AsyncMock) as mock_request:
        mock_request.side_effect = httpx.HTTPStatusError("404 Not Found", request=MagicMock(), response=MagicMock(status_code=404))
        response = await client.get("https://example.com/not-found")

        assert response is None

    await client.close()

@pytest.mark.asyncio
async def test_http_client_request_error():
    client = EnterpriseHTTPClient()

    with patch.object(client._client, "request", new_callable=AsyncMock) as mock_request:
        mock_request.side_effect = httpx.RequestError("Connection Refused", request=MagicMock())
        response = await client.get("https://example.com")

        assert response is None

    await client.close()
