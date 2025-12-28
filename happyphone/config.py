"""Happy Phone Configuration"""

import os
from pathlib import Path

# Server configuration
SIGNALING_URL = os.environ.get("HAPPYPHONE_SIGNAL_URL", "https://signal.happy.land")

# TURN server (for voice calls through NAT)
TURN_SERVER = os.environ.get("HAPPYPHONE_TURN_SERVER", "turn:turn.happy.land:3478")
TURN_USERNAME = os.environ.get("HAPPYPHONE_TURN_USER", "happyphone")
TURN_PASSWORD = os.environ.get("HAPPYPHONE_TURN_PASS", "")

STUN_SERVER = "stun:turn.happy.land:3478"

# Local storage
DATA_DIR = Path(os.environ.get("HAPPYPHONE_DATA_DIR", Path.home() / ".happyphone"))
DB_PATH = DATA_DIR / "data.db"

# Crypto parameters
ARGON2_OPS_LIMIT = 3
ARGON2_MEM_LIMIT = 67108864  # 64 MB

# Audio settings
AUDIO_SAMPLE_RATE = 48000
AUDIO_CHANNELS = 1
AUDIO_CHUNK_SIZE = 960  # 20ms at 48kHz

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)
