# Harbor API / Swagger Definition Issues

Scanned on 2026-06-27. All open and closed issues in goharbor/harbor-cli related to the Harbor API, swagger spec, or errors caused by the Harbor API definition.

---

## Core Pattern: Swagger Spec Status Code Mismatch

The go-swagger-generated client errors on HTTP status codes the Harbor API actually returns but that are not defined in the swagger spec, producing:

> `response status code does not match any response statuses defined for this endpoint in the swagger spec (status NNN): {}`

| # | Title | State | Root cause |
|---|-------|-------|------------|
| [#981](https://github.com/goharbor/harbor-cli/issues/981) | Delete is failing on some projects | **OPEN** | Status 412 not in swagger spec for delete endpoint |
| [#808](https://github.com/goharbor/harbor-cli/issues/808) | Login fails with unhelpful swagger error when `/users/current` unavailable | CLOSED | Status 502 not in swagger spec; also `users/current` not in OIDC allowlist |
| [#557](https://github.com/goharbor/harbor-cli/issues/557) | Applying config with empty fields throws error | CLOSED | Harbor returns unexpected status when sending empty fields |
| [#419](https://github.com/goharbor/harbor-cli/issues/419) | Force Delete fails on immutable images (status 412) | CLOSED | Status 412 not in swagger spec for repo delete endpoint |
| [#342](https://github.com/goharbor/harbor-cli/issues/342) | 401 Errors on Project Deletion as admin | CLOSED | Swagger spec error surfacing instead of meaningful message |
| [#341](https://github.com/goharbor/harbor-cli/issues/341) | Error when setting page size | CLOSED | Status 422 not in swagger spec when page-size too large |

---

## Nil Pointer / Unchecked API Response Issues

The generated API client returns nil payloads or swallows errors, causing panics downstream.

| # | Title | State | Root cause |
|---|-------|-------|------------|
| [#1021](https://github.com/goharbor/harbor-cli/issues/1021) | preheat policy update panics on empty/nil server payload | **OPEN** | No nil check on API response before dereferencing |
| [#1003](https://github.com/goharbor/harbor-cli/issues/1003) | GetLabel swallows all errors and returns nil, causing potential nil deref | **OPEN** | Error from API client discarded |
| [#997](https://github.com/goharbor/harbor-cli/issues/997) | robot view panics when robot has empty permissions | **OPEN** | API returns empty permissions field, not handled |
| [#927](https://github.com/goharbor/harbor-cli/issues/927) | GetRobot error discarded in robot create/update output path | **OPEN** | API error ignored on output path causing nil panic |
| [#933](https://github.com/goharbor/harbor-cli/issues/933) | GetRegistryIdByName returns `(0, nil)` for non-existent registry | **OPEN** | API 404 not propagated; callers operate on ID 0 |
| [#819](https://github.com/goharbor/harbor-cli/issues/819) | Fix user lookup bug causing operations on UserID 0 | CLOSED | Same pattern: API 404 → ID 0 used silently |
| [#862](https://github.com/goharbor/harbor-cli/issues/862) | project robot list can panic instead of returning error | CLOSED | API error not checked |
| [#309](https://github.com/goharbor/harbor-cli/issues/309) | Force Project deletion does not work by ID | CLOSED | API 404 on `/projects/{project_name}/repositories` when int passed |

---

## API Error Parsing / Message Quality

| # | Title | State | Root cause |
|---|-------|-------|------------|
| [#858](https://github.com/goharbor/harbor-cli/issues/858) | ParseHarborErrorMsg silently drops multiple API validation errors | CLOSED | Error parser only surfaces first error from API response |
| [#889](https://github.com/goharbor/harbor-cli/issues/889) | CreateProject silently discards invalid `--registry-id` / `--storage-limit` | CLOSED | API validation errors not propagated |
| [#886](https://github.com/goharbor/harbor-cli/issues/886) | Registry ID Validation (Proxy Cache) | **OPEN** | Invalid registry IDs sent to API without client-side check |

---

## Login / Auth API Issues

| # | Title | State | Root cause |
|---|-------|-------|------------|
| [#743](https://github.com/goharbor/harbor-cli/issues/743) | Password change command only supports system admin | CLOSED | `PUT /users/{id}/password` swagger spec doesn't allow non-admin callers to change own password |
| [#941](https://github.com/goharbor/harbor-cli/issues/941) | Avoid false login failures for robot accounts | CLOSED | `/users/current` returns 412 for robot accounts — API behavior not in spec |

---

## Schema / Input Validation vs API

| # | Title | State | Notes |
|---|-------|-------|-------|
| [#784](https://github.com/goharbor/harbor-cli/issues/784) | Discussion: Validating Loaded JSON/YAML inputs using schemas | **OPEN** | Proposal to add JSON Schema validation before sending to Harbor API |

---

## Summary

The single biggest recurring source of pain is that the go-swagger client treats any HTTP status code not enumerated in the Harbor OpenAPI spec as a fatal error with a cryptic message. Issues #981, #808, #557, #419, #342, #341 all share this root cause — Harbor legitimately returns 412, 422, 502, etc., but the spec doesn't document them, so the CLI surfaces a raw, unhelpful swagger library error instead of a meaningful one.

The second major pattern is unchecked API responses: errors or nil payloads from the generated client are silently discarded or not nil-checked, causing panics far from the actual API call site.
