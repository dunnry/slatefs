NBD TLS test certificates
=========================

These PEM fixtures are used by the in-crate STARTTLS and mutual-TLS wire tests.
They are intentionally test-only and were generated with `regenerate.sh`.

The CA is self-signed. `server.pem` has `serverAuth` for `localhost` and
`127.0.0.1`; `client.pem` has `clientAuth`.
