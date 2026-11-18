using System.Globalization;
using System.Text;

namespace SecureImageUpload.Api.Validation;

/// <summary>
/// Validates the client-supplied file name. The name is never used to build a storage path;
/// this check exists to reject obvious bypass attempts early and to derive the declared format.
/// </summary>
public static class FileNameValidator
{
    private static readonly HashSet<string> DangerousSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "pht", "phps", "inc",
        "asp", "aspx", "ashx", "asmx", "ascx", "asa", "cer", "cshtml", "vbhtml", "config", "razor",
        "jsp", "jspx", "jspf", "war", "jar", "cfm", "cgi", "pl", "py", "rb", "sh", "bash",
        "exe", "dll", "com", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "hta", "scr", "msi", "lnk", "url", "scf", "reg",
        "html", "htm", "xhtml", "shtml", "svg", "svgz", "xml", "xsl", "swf", "htaccess", "htpasswd",
    };

    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    };

    public static ImageFormat Validate(string? fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName)) throw Bad("empty file name");
        if (fileName.Length > 255) throw Bad("file name too long");

        // Fullwidth / compatibility characters ("shell．ｐｈｐ") collapse to ASCII under NFKC,
        // so every check below runs on the normalized form.
        string name;
        try
        {
            name = fileName.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            throw Bad("file name is not valid Unicode");
        }

        foreach (char c in name)
        {
            // NUL and control chars (truncation), separators and ':' (traversal, NTFS streams "a.asp::$DATA"),
            // ';' (IIS "a.asp;.jpg"), '%' (double-decoding "%00"), shell/wildcard characters.
            if (c is '/' or '\\' or ':' or ';' or '%' or '<' or '>' or '"' or '|' or '?' or '*' or '\'' or '`' or '$' or '&')
                throw Bad("forbidden character in file name");

            // Format chars cover RTLO (U+202E "gpj.exe") and zero-width characters.
            if (CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.Control or UnicodeCategory.Format
                or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                or UnicodeCategory.PrivateUse or UnicodeCategory.OtherNotAssigned)
                throw Bad("control or invisible character in file name");
        }

        // Windows silently strips trailing dots and spaces ("shell.php." becomes "shell.php").
        if (name != name.Trim() || name.EndsWith('.') || name.StartsWith('.'))
            throw Bad("file name starts or ends with dot/space");

        string[] segments = name.Split('.');
        if (segments.Length < 2) throw Bad("file name has no extension");
        if (segments.Any(s => s.Length == 0 || s != s.Trim())) throw Bad("empty or padded name segment");
        if (ReservedDeviceNames.Contains(segments[0])) throw Bad("reserved device name");

        // Double extensions: "shell.php.jpg" executes on servers with multi-extension handlers.
        if (segments[..^1].Any(DangerousSegments.Contains)) throw Bad("dangerous double extension");

        return segments[^1].ToLowerInvariant() switch
        {
            "png" => ImageFormat.Png,
            "jpg" or "jpeg" => ImageFormat.Jpeg,
            _ => throw new UploadRejectedException(RejectReason.UnsupportedType, "extension is not png/jpg/jpeg"),
        };
    }

    private static UploadRejectedException Bad(string detail) => new(RejectReason.BadFileName, detail);
}
