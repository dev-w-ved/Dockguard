from pathlib import Path
import pytest

ROOT = Path(__file__).parents[1]

@pytest.fixture
def sample_root():
    return ROOT / "samples"
