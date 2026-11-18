using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using SecureImageUpload.Api.Validation;

namespace SecureImageUpload.Api.Services;

public sealed record StoredImage(string Id, ImageFormat Format, int Width, int Height, long Size);

/// <summary>The validation pipeline. Every layer is independent; an upload must pass all of them.</summary>
public sealed class ImageUploadService(
    IOptions<UploadOptions> options,
    ImageSanitizer sanitizer,
    ImageStorage storage,
    ILogger<ImageUploadService> logger)
{
    private static readonly EventId SecurityEvent = new(4001, "UploadSecurityEvent");
    private static readonly EventId Rejected = new(4002, "UploadRejected");

    private readonly UploadOptions _options = options.Value;
    private readonly SemaphoreSlim _decodeGate = new(options.Value.MaxConcurrentDecodes);

    public async Task<StoredImage> ProcessAsync(string userId, string? fileName, string? contentType, byte[] data, CancellationToken cancellationToken)
    {
        try
        {
            return await ProcessCoreAsync(userId, fileName, contentType, data, cancellationToken);
        }
        catch (UploadRejectedException ex)
        {
            logger.Log(
                ex.IsSecurityEvent ? LogLevel.Warning : LogLevel.Information,
                ex.IsSecurityEvent ? SecurityEvent : Rejected,
                "Upload rejected. Reason={Reason} Detail={Detail} User={User} File={File} Size={Size} Sha256={Sha256}",
                ex.Reason, ex.Message, userId, ForLog(fileName), data.Length, Convert.ToHexStringLower(SHA256.HashData(data)));
            throw;
        }
    }

    private async Task<StoredImage> ProcessCoreAsync(string userId, string? fileName, string? contentType, byte[] data, CancellationToken cancellationToken)
    {
        // 1. Size (the transport layer already enforced this while streaming; re-check the real byte count).
        if (data.Length == 0) throw new UploadRejectedException(RejectReason.BadRequest, "empty file");
        if (data.Length > _options.MaxFileBytes) throw new UploadRejectedException(RejectReason.TooLarge, "file exceeds limit");

        // 2. File name and extension allow-list.
        ImageFormat declared = FileNameValidator.Validate(fileName);

        // 3. Declared Content-Type must agree with the extension (client-controlled, so only a consistency check).
        if (!MediaTypeHeaderValue.TryParse(contentType, out MediaTypeHeaderValue? mediaType)
            || !string.Equals(mediaType.MediaType.Value, ImageSignature.ContentType(declared), StringComparison.OrdinalIgnoreCase))
            throw new UploadRejectedException(RejectReason.TypeMismatch, "Content-Type does not match extension");

        // 4. Magic bytes must be PNG or JPEG and agree with the extension.
        ImageFormat detected = ImageSignature.Detect(data)
            ?? throw new UploadRejectedException(RejectReason.UnsupportedType, "magic bytes are not PNG or JPEG");
        if (detected != declared) throw new UploadRejectedException(RejectReason.TypeMismatch, "magic bytes do not match extension");

        // 5. Full structural walk: container integrity, dimensions before decoding, polyglot/trailer rejection.
        ImageStructure structure = detected == ImageFormat.Png
            ? PngStructureValidator.Validate(data, _options)
            : JpegStructureValidator.Validate(data, _options);

        // 6. Byte-level scan for embedded active content, canary tokens and external references.
        ScanReport scan = ThreatScanner.Scan(data, structure.MetadataRegions, _options);
        if (scan.ActiveContent.Count > 0)
            throw new UploadRejectedException(RejectReason.ActiveContent, "signatures: " + string.Join(", ", scan.ActiveContent));
        if (scan.CanaryHits.Count > 0)
            throw new UploadRejectedException(RejectReason.CanaryToken, "callback domains: " + string.Join(", ", scan.CanaryHits));
        if (scan.ExternalUrls.Count > 0)
        {
            if (_options.RejectExternalUrls)
                throw new UploadRejectedException(RejectReason.ExternalUrl, "external references: " + string.Join(", ", scan.ExternalUrls));
            logger.LogInformation("Upload metadata references external hosts (stripped): {Hosts} User={User}", string.Join(", ", scan.ExternalUrls), userId);
        }

        // 7. Decode and re-encode under a concurrency gate and a hard timeout.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(_options.ProcessingTimeoutSeconds));

        byte[] clean;
        int width, height;
        try
        {
            await _decodeGate.WaitAsync(timeout.Token);
            try
            {
                (clean, width, height) = await sanitizer.SanitizeAsync(data, detected, timeout.Token);
            }
            finally
            {
                _decodeGate.Release();
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new UploadRejectedException(RejectReason.Timeout, "processing timed out");
        }

        // 8. The sanitized output must itself be a canonical file of the same type with no trailer.
        if (ImageSignature.Detect(clean) != detected) throw new InvalidOperationException("Sanitizer produced an unexpected format.");
        var strict = new UploadOptions
        {
            MaxWidth = _options.MaxWidth, MaxHeight = _options.MaxHeight, MaxPixels = _options.MaxPixels, RejectTrailingData = true,
        };
        _ = detected == ImageFormat.Png ? PngStructureValidator.Validate(clean, strict) : JpegStructureValidator.Validate(clean, strict);

        // 9. Store under a random server-generated name with a server-chosen extension.
        string id = await storage.SaveAsync(userId, detected, clean, cancellationToken);
        logger.LogInformation("Upload stored. Id={Id} User={User} Format={Format} {Width}x{Height} Size={Size}", id, userId, detected, width, height, clean.Length);
        return new StoredImage(id, detected, width, height, clean.Length);
    }

    /// <summary>Client strings go to logs only after neutralising CR/LF and other log-forging characters.</summary>
    private static string ForLog(string? value) => value is null
        ? "<null>"
        : new string([.. value.Take(100).Select(c => char.IsLetterOrDigit(c) ? c : '?')]);
}
