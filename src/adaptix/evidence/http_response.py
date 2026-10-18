"""Rebuild a fully-decoded HTTP response without stale transfer headers.

Streaming adapters consume already-decoded bytes. Copying the original
``content-encoding`` onto the rebuilt response makes httpx decode a second time
and raise ``httpx.DecodingError``. Dropping the wire-body headers keeps status,
content type and application headers while preventing double decoding.
"""
import httpx

# Headers that describe the on-the-wire body, not the decoded representation.
WIRE_HEADERS = ('content-encoding', 'content-length', 'transfer-encoding', 'content-md5')


def decoded_response(response, data):
    """Return a standalone response over already-decoded bytes and safe headers."""
    headers = [(name, value) for name, value in response.headers.multi_items()
               if name.lower() not in WIRE_HEADERS]
    return httpx.Response(response.status_code, headers=headers,
                          content=bytes(data), request=response.request)
