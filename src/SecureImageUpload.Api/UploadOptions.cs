namespace SecureImageUpload.Api;

/// <summary>All upload limits and policies. Bound from the "Upload" configuration section.</summary>
public sealed class UploadOptions
{
    public const string Section = "Upload";

    /// <summary>Absolute directory for stored images. Must be outside any web-served folder.</summary>
    public string StorageRoot { get; set; } = "";

    public long MaxFileBytes { get; set; } = 10 * 1024 * 1024;
    public int MaxWidth { get; set; } = 8000;
    public int MaxHeight { get; set; } = 8000;

    /// <summary>Pixel-count cap (decompression-bomb guard). Decoding costs roughly 8 bytes of RAM per pixel.</summary>
    public long MaxPixels { get; set; } = 40_000_000;

    public int MaxConcurrentDecodes { get; set; } = 2;
    public int ProcessingTimeoutSeconds { get; set; } = 15;
    public int DecoderMemoryLimitMegabytes { get; set; } = 512;
    public int JpegQuality { get; set; } = 90;
    public int UploadsPerMinutePerUser { get; set; } = 10;

    /// <summary>
    /// JPEG only (data after PNG IEND is always rejected).
    /// false (default): data after EOI is scanned for known signatures and dropped by re-encoding. Needed for
    /// phone photos (Samsung trailers, Android Ultra HDR gain maps, motion photos).
    /// true: any byte after EOI rejects the upload.
    /// </summary>
    public bool RejectTrailingData { get; set; }

    /// <summary>true: reject images whose metadata references any non-allowlisted external URL / UNC path.</summary>
    public bool RejectExternalUrls { get; set; }

    /// <summary>Extra callback/canary domains to block, in addition to the built-in list.</summary>
    public string[] ExtraCanaryDomains { get; set; } = [];
}
