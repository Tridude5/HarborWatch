import os

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://localhost:9200")
EVENTS_INDEX = os.getenv("EVENTS_INDEX", "hw-events")
ALERTS_INDEX = os.getenv("ALERTS_INDEX", "hw-alerts")
API_KEY = os.getenv("API_KEY", "devkey")
