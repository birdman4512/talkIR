from elasticsearch import AsyncElasticsearch
from .config import settings

_client: AsyncElasticsearch | None = None


def get_es_client() -> AsyncElasticsearch:
    global _client
    if _client is None:
        _client = AsyncElasticsearch(
            settings.es_host,
            basic_auth=(settings.es_user, settings.es_password),
            ca_certs=settings.es_ca_cert_path,
            verify_certs=True,
        )
    return _client


async def close_es_client() -> None:
    global _client
    if _client is not None:
        await _client.close()
        _client = None
