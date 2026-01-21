from opensearchpy import OpenSearch
from .config import OPENSEARCH_URL

def get_client() -> OpenSearch:
    # Security plugin is disabled in compose; no auth needed.
    return OpenSearch(OPENSEARCH_URL)
