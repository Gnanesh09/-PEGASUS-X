import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip()
POSTGRES_DSN = os.getenv("POSTGRES_DSN", "").strip()
POSTGRES_TEST_DSN = os.getenv("POSTGRES_TEST_DSN", "").strip()
ENABLE_LAB_TESTS = os.getenv("PEGASUS_ENABLE_LAB_TESTS", "false").strip().lower() == "true"
LAB_HOST = os.getenv("PEGASUS_LAB_HOST", "").strip()
MODE = os.getenv("PEGASUS_MODE", "simulation").strip().lower()
ROUND_INTERVAL_SECONDS = max(1, int(os.getenv("ROUND_INTERVAL_SECONDS", "3")))
MAX_ROUNDS = max(1, int(os.getenv("MAX_ROUNDS", "10")))
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "pegasus.sqlite3")
