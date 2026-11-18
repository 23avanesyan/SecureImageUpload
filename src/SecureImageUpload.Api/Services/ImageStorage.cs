using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using SecureImageUpload.Api.Validation;

namespace SecureImageUpload.Api.Services;

/// <summary>
/// Stores sanitized images under server-generated names in a per-user directory.
/// No client-controlled string ever becomes part of a path.
/// </summary>
public sealed partial class ImageStorage
{
    private readonly string _root;

    public ImageStorage(IOptions<UploadOptions> options)
    {
        if (string.IsNullOrWhiteSpace(options.Value.StorageRoot))
            throw new InvalidOperationException("Upload:StorageRoot must be configured.");
        _root = Path.GetFullPath(options.Value.StorageRoot);
        Directory.CreateDirectory(_root);
    }

    public string Root => _root;

    public async Task<string> SaveAsync(string userId, ImageFormat format, byte[] data, CancellationToken cancellationToken)
    {
        string id = RandomNumberGenerator.GetHexString(32, lowercase: true); // 128 bits from the CSPRNG
        string path = ResolvePath(userId, id, format);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var fileOptions = new FileStreamOptions
        {
            Mode = FileMode.CreateNew, // never overwrite
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous,
        };
        if (!OperatingSystem.IsWindows()) fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite; // no execute bit

        try
        {
            await using var stream = new FileStream(path, fileOptions);
            await stream.WriteAsync(data, cancellationToken);
        }
        catch
        {
            File.Delete(path);
            throw;
        }

        return id;
    }

    /// <summary>Opens an image owned by <paramref name="userId"/>. Other users' ids simply do not resolve.</summary>
    public (Stream Stream, ImageFormat Format)? TryOpen(string userId, string id)
    {
        if (!IdPattern().IsMatch(id)) return null;

        foreach (ImageFormat format in Enum.GetValues<ImageFormat>())
        {
            string path = ResolvePath(userId, id, format);
            if (File.Exists(path))
                return (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, FileOptions.Asynchronous), format);
        }

        return null;
    }

    private string ResolvePath(string userId, string id, ImageFormat format)
    {
        string userDirectory = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(userId)))[..32];
        string path = Path.GetFullPath(Path.Combine(_root, userDirectory, id + ImageSignature.Extension(format)));

        // Defence in depth: both components are server-generated hex, but verify containment anyway.
        if (!path.StartsWith(_root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidOperationException("Resolved path escapes the storage root.");
        return path;
    }

    [GeneratedRegex("^[0-9a-f]{32}$")]
    private static partial Regex IdPattern();
}
