# Consumer API v1 errors

Every non-success JSON response uses the stable envelope below. New optional
fields may be added in v1; clients must ignore fields they do not understand.

```json
{
  "error": {
    "code": "not_found",
    "message": "entry was not found",
    "request_id": "req-01J00000000000000000000000",
    "details": {}
  }
}
```

| HTTP | Code | Meaning |
| ---: | --- | --- |
| 401 | `authentication_required` | Tenant credential is missing, invalid, or expired. |
| 403 | `permission_denied` | The authenticated VFS identity cannot perform the operation. Cross-tenant guesses may also use 403 or 404 without confirming existence. |
| 404 | `not_found` | Volume or entry is not visible to the authenticated tenant. |
| 409 | `conflict` | A name exists, a type conflicts, or another version operation holds the lease. |
| 412 | `precondition_failed` | `If-Match` is stale; reload or save as a new file. |
| 400 | `malformed_range` | A byte range is malformed or requests multiple ranges. |
| 416 | `range_not_satisfiable` | The requested byte range is outside the file. |
| 422 | `invalid_path`, `invalid_request` | The selector, path, name, type, or request shape is invalid. |
| 422 | `read_only_view` | A mutation selected a snapshot or version view. |
| 429 | `rate_limited` | Retry after the response's `Retry-After` delay. |
| 500 | `internal` | Unexpected server failure. Report the request ID. |
| 503 | `primary_unavailable` | The writer is fenced or unavailable; retry without implying data loss. |
| 507 | `quota_exceeded` | Byte or inode quota is exhausted. |

`message` is for people and may change. Programs branch on `code` and HTTP
status. `request_id` is copied from `X-Request-Id` when supplied. `details` is
an object reserved for code-specific, non-secret structured context; it must
never contain tenant credentials, bearer tokens, or file content.
