# Static deployment

Serve web/ as static content only over HTTPS, with application/wasm MIME for .wasm. No server API receives keys/plaintext. No third-party assets, analytics, service worker or storage. Keep index/app/glue cache versions coherent. Verify all three modes on the final HTTPS host before calling deployment ready. Domain and hosting are pending. Repository remains private.

Recommended response headers:
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

Only project code/copy and benchmark-relevant environment fields belong in the public web root. No credentials or private operational context. This document is not authorization to change a host or DNS.
