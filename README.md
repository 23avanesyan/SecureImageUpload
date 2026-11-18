# SecureImageUpload

An ASP.NET Core (.NET 10) upload endpoint that takes **PNG and JPEG only** (`.png`, `.jpg`, `.jpeg`).

The uploaded file is never stored. It goes through several independent checks, then gets decoded into pixels, and the server writes a brand-new file built from those pixels. Anything that isn't a pixel — metadata, comments, ICC profiles, trailing garbage, polyglot payloads — physically never reaches storage.


## Running it

```powershell
# tests: 85 scenarios, attacks and legitimate uploads mixed together
dotnet test

# run locally
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run --project src/SecureImageUpload.Api

# local JWT for testing
dotnet user-jwts create --project src/SecureImageUpload.Api --name alice
```

```bash
curl -H "Authorization: Bearer <token>" -F "file=@photo.jpg;type=image/jpeg" http://localhost:5154/api/images
```

## Swagger UI (manual testing)

Swagger runs **in Development only**. It describes the whole API surface, so there's no reason to expose it in production.

1. `dotnet run --project src/SecureImageUpload.Api` (the `http` profile opens the browser for you) and go to <http://localhost:5154/swagger>.
2. Get a token: `dotnet user-jwts create --project src/SecureImageUpload.Api --name alice`.
3. Hit **Authorize** and paste the token without the `Bearer` prefix.
4. `POST /api/images` → **Try it out** → pick a file → **Execute**. Take the returned `id` and use it with `GET /api/images/{id}`.

The OpenAPI document lives at <http://localhost:5154/openapi/v1.json>. Uploads are limited to 10 per minute per user (`UploadsPerMinutePerUser`), so if you test in a loop you'll start getting `429`.

## API

| Method | Path | What it does |
|---|---|---|
| `POST` | `/api/images` | `multipart/form-data` with exactly one part named `file`. Returns `201` with `id`, `contentType`, `width`, `height`, `size`. |
| `GET` | `/api/images/{id}` | Returns the image, but only to the user who uploaded it. Someone else's `id`, or one that doesn't exist, gets `404`. |

Both endpoints require a JWT bearer token. Error codes are deliberately coarse, so that a client can't use the responses as an oracle:

| HTTP | `error` | When |
|---|---|---|
| 400 | `bad_request` | not multipart, extra parts, no file, empty file |
| 401 | — | missing or invalid token |
| 413 | `file_too_large` | size limit exceeded |
| 415 | `unsupported_type` | name, extension, Content-Type or magic bytes say it isn't PNG/JPEG, or they disagree |
| 422 | `invalid_image` | broken structure, active content, canary token, dimension limits, decoder failure |
| 429 | — | per-user upload limit hit |

The exact reason for a rejection only goes to the server log.


## Settings (`Upload` section in appsettings)

| Setting | Default | Purpose |
|---|---|---|
| `StorageRoot` | — (required) | Storage directory. Must be outside the web root; checked at startup |
| `MaxFileBytes` | 10 MB | Maximum file size |
| `MaxWidth` / `MaxHeight` | 8000 | Maximum dimensions |
| `MaxPixels` | 40,000,000 | Pixel cap. Decoding costs roughly 8 bytes of RAM per pixel |
| `MaxConcurrentDecodes` | 2 | Concurrent decodes |
| `ProcessingTimeoutSeconds` | 15 | Per-file processing timeout |
| `DecoderMemoryLimitMegabytes` | 512 | Single decoder allocation cap |
| `JpegQuality` | 90 | JPEG re-encode quality |
| `UploadsPerMinutePerUser` | 10 | Rate limit |
| `RejectTrailingData` | `false` | JPEG only: reject data after `EOI`. Turning it on rejects real phone photos |
| `RejectExternalUrls` | `false` | Reject images whose metadata references external URLs |
| `ExtraCanaryDomains` | `[]` | Additional domains to block |

JWT is configured the standard way under `Authentication:Schemes:Bearer`.

## Log events

| EventId | Level | Meaning |
|---|---|---|
| 4001 `UploadSecurityEvent` | Warning | Looks like an attack: type mismatch, trailing data, active content, canary token, external URL (under the strict policy). Worth an alert in your SIEM |
| 4002 `UploadRejected` | Information | An ordinary rejection: broken file, size, name |


