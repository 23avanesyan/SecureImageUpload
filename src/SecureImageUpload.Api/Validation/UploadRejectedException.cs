namespace SecureImageUpload.Api.Validation;

public enum RejectReason
{
    BadRequest,
    TooLarge,
    BadFileName,
    UnsupportedType,
    TypeMismatch,
    MalformedImage,
    TrailingData,
    DimensionsExceeded,
    ActiveContent,
    CanaryToken,
    ExternalUrl,
    DecodeFailed,
    Timeout,
}

/// <summary>
/// Thrown by every validation layer. <see cref="Exception.Message"/> is for server logs only;
/// the client only ever sees the coarse <see cref="ClientError"/> so the checks cannot be used as an oracle.
/// </summary>
public sealed class UploadRejectedException(RejectReason reason, string detail) : Exception(detail)
{
    public RejectReason Reason { get; } = reason;

    public (int Status, string Code) ClientError => Reason switch
    {
        RejectReason.BadRequest => (400, "bad_request"),
        RejectReason.TooLarge => (413, "file_too_large"),
        RejectReason.BadFileName or RejectReason.UnsupportedType or RejectReason.TypeMismatch => (415, "unsupported_type"),
        _ => (422, "invalid_image"),
    };

    /// <summary>Rejections that indicate a deliberate attack rather than a broken file.</summary>
    public bool IsSecurityEvent => Reason is RejectReason.TypeMismatch or RejectReason.TrailingData
        or RejectReason.ActiveContent or RejectReason.CanaryToken or RejectReason.ExternalUrl;
}
