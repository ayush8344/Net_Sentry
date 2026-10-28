import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
ARTIFACTS_DIR = BASE_DIR / "artifacts"
DATA_RAW_DIR = BASE_DIR / "data_raw"
THREAT_LOG_PATH = ARTIFACTS_DIR / "threat_log.csv"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-5")
MAX_LLM_CALLS = int(os.getenv("MAX_LLM_CALLS", "20"))

TARGET_TPR = 0.95
MAX_FPR = 0.02

RANDOM_STATE = 42

DATASET_PROFILES = ("cicids2018", "iscx_vpn", "caida", "sample")

ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
for _name in DATASET_PROFILES:
    (DATA_RAW_DIR / _name).mkdir(parents=True, exist_ok=True)
