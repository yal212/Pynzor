import pytest
import asyncio
from modules import scanner


@pytest.mark.asyncio
async def test_port_scanner_localhost():
    result = await scanner.scan("127.0.0.1", ports=[80, 443], timeout=2.0)
    assert result.target == "127.0.0.1"
    assert len(result.ports) > 0


@pytest.mark.asyncio
async def test_port_scanner_no_target():
    result = await scanner.scan("127.0.0.1")
    assert result.target == "127.0.0.1"
    assert result.ports is not None
