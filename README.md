# SecureImageUpload

An ASP.NET Core (.NET 10) upload endpoint that takes **PNG and JPEG only** (`.png`, `.jpg`, `.jpeg`). I built it around one rule: don't trust a single byte that comes from the client.

The uploaded file is never stored. It goes through several independent checks, then gets decoded into pixels, and the server writes a brand-new file built from those pixels. Anything that isn't a pixel — metadata, comments, ICC profiles, trailing garbage, polyglot payloads — physically never reaches storage.

A quick note on why it's built this way: checking an extension and calling it a day is how most image-upload bugs happen. Validating the container helps, but the only thing that really removes embedded junk is re-encoding the image yourself.

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

## The layers

An upload has to pass **all** of them. Each one stands on its own and doesn't assume the previous one did its job.

| # | Layer | What it does | Where |
|---|---|---|---|
| 0 | Transport | Body size cap at the Kestrel/IIS level, header limits, per-user rate limit, mandatory authentication | [Program.cs](src/SecureImageUpload.Api/Program.cs) |
| 1 | Multipart | Hand-written streaming parser: exactly one `file` part, limits on part headers, real byte counting (no trust in `Content-Length`), rejects mismatched `filename` / `filename*` | [MultipartFileReader.cs](src/SecureImageUpload.Api/Endpoints/MultipartFileReader.cs) |
| 2 | File name | Extension allowlist, NFKC normalization, no control or invisible characters, separators, `:` `;` `%`, double extensions, reserved Windows names | [FileNameValidator.cs](src/SecureImageUpload.Api/Validation/FileNameValidator.cs) |
| 3 | Content-Type | Must be `image/png` or `image/jpeg` and must match the extension | [ImageUploadService.cs](src/SecureImageUpload.Api/Services/ImageUploadService.cs) |
| 4 | Magic bytes | Signature must be PNG or JPEG and must match the extension | [ImageFormat.cs](src/SecureImageUpload.Api/Validation/ImageFormat.cs) |
| 5 | Structure | Full container walk without decoding pixels (details below) | [PngStructureValidator.cs](src/SecureImageUpload.Api/Validation/PngStructureValidator.cs), [JpegStructureValidator.cs](src/SecureImageUpload.Api/Validation/JpegStructureValidator.cs) |
| 6 | Byte scanner | Looks for active content, canary tokens and external URLs | [ThreatScanner.cs](src/SecureImageUpload.Api/Validation/ThreatScanner.cs) |
| 7 | Rebuild (CDR) | Decode with a controlled decoder where only PNG and JPEG are registered; copy pixels into a new image; encode again. With a timeout, memory cap and concurrency limit | [ImageSanitizer.cs](src/SecureImageUpload.Api/Services/ImageSanitizer.cs) |
| 8 | Result check | The rebuilt image is checked against the structural rules again, in strict mode | [ImageUploadService.cs](src/SecureImageUpload.Api/Services/ImageUploadService.cs) |
| 9 | Storage | Random name (128-bit CSPRNG), server picks the extension, per-user directory, `CreateNew`, path verified to stay inside the root | [ImageStorage.cs](src/SecureImageUpload.Api/Services/ImageStorage.cs) |
| 10 | Delivery | `nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Cross-Origin-Resource-Policy`, type taken from the server | [ImageEndpoints.cs](src/SecureImageUpload.Api/Endpoints/ImageEndpoints.cs) |

### Structural check (layer 5)

**PNG:** length and CRC for every chunk; `IHDR` first and only once; valid bit-depth / color-type combinations; `IDAT` chunks in sequence; `PLTE` before `IDAT`; `IEND` required; APNG (`acTL`, `fcTL`, `fdAT`) and unknown critical chunks rejected; `zTXt` / `iTXt` / `iCCP` decompressed with a 2 MB cap (zip-bomb guard) and handed to the scanner.

**JPEG:** only SOF0/SOF1/SOF2 (baseline, extended, progressive), 8-bit, 1/3/4 components; exactly one frame; at most 64 scans (keeps a progressive file from burning CPU); lossless, hierarchical and arithmetic variants rejected, as are duplicate SOI and DNL; `EOI` required.

**Both:** dimensions are read from the header and compared against the limits **before** decoding. In PNG, any byte after `IEND` is always a rejection. In JPEG, data after `EOI` is allowed by default, because that's how phone photos work (Samsung trailers, Android Ultra HDR gain maps, motion photos). It gets checked for known signatures and removed by the rebuild. Set `RejectTrailingData = true` if you'd rather reject those files.

## Attacks this was tested against

| Attack | What stops it |
|---|---|
| `shell.php`, `image.svg`, `image.gif` | extension allowlist (layer 2) |
| `image.png.exe`, `image.jpg.bak`, `image.pngx` | the name must **end** with `.png`, `.jpg` or `.jpeg`: only the last segment after the final dot is checked |
| `shell.php.jpg`, `shell.pHp5.png` | dangerous segments are banned anywhere in the name, case-insensitive |
| `shell.php%00.jpg`, `shell.php\0.jpg` | `%` and control characters banned |
| `a.asp;.jpg`, `a.jpg::$DATA`, `a.jpg.`, `a.jpg ` | `;`, `:`, trailing dots and spaces banned |
| `../../a.jpg`, `..\a.jpg` | separators banned; the client's name is never used in a path anyway |
| RTLO (`gpj.exe`), zero-width chars, fullwidth `．ｐｈｐ` | Unicode Format category banned, NFKC normalization applied |
| Content-Type spoofing | cross-checked against the extension and the signature |
| `GIF89a<?php …`, a file that's only magic bytes | signature plus a full structural walk |
| PNG content named `.jpg` and vice versa | extension, Content-Type, signature and decoder all have to agree |
| Polyglots: PNG+ZIP, JPEG+PHAR, JPEG+HTML, appended trailers | PNG: anything after `IEND` is rejected. JPEG: the tail is scanned for known signatures (PHP, HTML, scripts, canary domains) and never stored — only the rebuilt image is written |
| PHP/JS in EXIF, XMP, COM, `tEXt`, ICC | the scanner reads it (including UTF-16 and compressed `zTXt` / `iTXt`), and the rebuild drops all metadata |
| XXE in XMP (`<!ENTITY`) | caught by the scanner; XML is never parsed anywhere |
| Pixel flood / decompression bomb | header dimensions checked before decoding, pixel cap, decoder memory cap, timeout |
| Zip bomb in `zTXt` / `iCCP` | decompression with a hard cap |
| JPEG with thousands of scans, APNG with thousands of frames | scan limit; APNG banned; `MaxFrames = 1` |
| Exploit in an exotic codec (TIFF, WebP, BMP…) | only PNG and JPEG are registered in the decoder, and the decoder is fully managed (no native code) |
| Multiple files, extra fields, huge part headers | exactly one part, `MultipartReader` limits |
| Fake `Content-Length`, chunked body | server limit plus the parser's own byte count |
| Overwriting someone else's file, guessing names | random `id`, `FileMode.CreateNew`, per-user directory |
| IDOR on download | the path is derived from a hash of the user id, so another user's `id` simply doesn't resolve |
| Stored XSS via content sniffing | `nosniff`, CSP `sandbox`, fixed `Content-Type` |
| Log injection through the file name | only letters, digits and `. - _` reach the log |
| CSRF | bearer token instead of a cookie |
| Upload floods, CPU/RAM exhaustion | per-user rate limit, decode semaphore, timeout |

## Canary tokens and external URLs

A canary token is a URL, DNS name or UNC path hidden in image metadata that "calls home" when the file is opened or processed. The attacker learns that the file was viewed and from which IP, and on Windows a UNC path can leak an NTLM hash.

What the service does about it:

1. **Known domains** (canarytokens.com/.org/.net, interact.sh, oast.\*, oastify.com, burpcollaborator.net, dnslog.cn, webhook.site, requestbin, ngrok and others) are searched for across the whole file, case-insensitive, in both ASCII and UTF-16. A hit means a `CanaryToken` rejection and a security event in the log. The list can be extended with `ExtraCanaryDomains`.
2. **Any external URL** in metadata (`http(s)://`, `ftp://`, `file://`, `smb://`, `ldap://`, `\\host\share`, IP addresses) is extracted and logged. With `RejectExternalUrls = true` those uploads are rejected. XMP namespace identifiers (`ns.adobe.com`, `www.w3.org` and similar) are allowlisted.
3. The rebuild **removes all metadata** regardless of what the scan found, so the stored file contains no links.
4. The service **never makes an outbound request.** No URL from a file is ever resolved or fetched.

One limitation worth being honest about: a token on the attacker's own domain won't match any list. It'll show up as an "external URL" (point 2). The real protection is points 3 and 4 — the scanner is for detection and alerting.

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

Each entry carries the reason, details, user, sanitized file name, size and the SHA-256 of the original. The original itself isn't stored anywhere.

## What this doesn't solve

- **ImageSharp licensing.** This uses SixLabors.ImageSharp 4.x. Debug builds run without a key, but a **Release build needs a Six Labors license** (commercial one for a company). I picked it because the decoder is fully managed. If the license doesn't work for you, there's one class to replace — `ImageSanitizer` (SkiaSharp under MIT is an option, but it's native code with a different risk profile).
- **Phone photos and data after EOI.** Samsung, Android Ultra HDR and motion photos append data after the end of the JPEG, so by default that data is allowed and removed by the rebuild. The HDR gain map and the motion video are lost in the process — what you get back is a plain SDR image. Strict mode (`RejectTrailingData = true`) rejects these files instead.
- **Size limits.** The defaults are 10 MB, 8000 px per side and 40 MP. A 50 MP or 200 MP shot won't get through.
- **Steganography.** PNG is re-encoded losslessly, so data hidden in the low bits of the pixels survives. JPEG re-encoding mostly destroys it. If you need it gone for certain, you have to change the pixels: resize or add noise.
- **Payloads inside the pixels themselves.** There are known images crafted so that the compressed output of a re-encode contains something like PHP code. That's why the storage directory must never be served by a web server that executes scripts, and why nothing should ever `include` files from it. This service keeps storage outside the web root and serves files only through the endpoint.
- **Color.** The ICC profile is dropped, so photos in Display P3 or Adobe RGB will look slightly less saturated. EXIF orientation is applied to the pixels before it's removed.
- **Decoder leniency.** If a PNG declares more rows than it contains, the decoder pads the image instead of rejecting it. The result is still a clean image within the limits (there's a test for it).
- **Antivirus.** Not wired in. If policy requires it, it goes between layers 6 and 7 (ClamAV, ICAP, AMSI).
- **Rate limiting is in-process.** With several instances each one counts separately. A global limit belongs on the load balancer or API gateway.
- **Reverse proxy.** Body size limits and timeouts need to be repeated in nginx / IIS / your WAF, otherwise large bodies still reach the app.
- **Serving domain.** User content is better served from a separate domain with no cookies from the main application.
- **Updates.** The decoder is the main attack surface here. Keep an eye on ImageSharp security releases.
