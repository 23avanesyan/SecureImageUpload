namespace SecureImageUpload.Api.Validation;

public enum ImageFormat
{
    Png,
    Jpeg,
}

/// <summary>Result of a structural walk: real dimensions plus every byte range that is not pixel data.</summary>
public sealed record ImageStructure(int Width, int Height, IReadOnlyList<ReadOnlyMemory<byte>> MetadataRegions);

public static class ImageSignature
{
    private static ReadOnlySpan<byte> PngMagic => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>Detects the format from magic bytes only. Anything that is not PNG or JPEG returns null.</summary>
    public static ImageFormat? Detect(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 8 && data[..8].SequenceEqual(PngMagic)) return ImageFormat.Png;
        if (data.Length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF) return ImageFormat.Jpeg;
        return null;
    }

    public static string Extension(ImageFormat format) => format == ImageFormat.Png ? ".png" : ".jpg";

    public static string ContentType(ImageFormat format) => format == ImageFormat.Png ? "image/png" : "image/jpeg";
}

public static class Crc32
{
    private static readonly uint[] Table = BuildTable();

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte b in data) crc = Table[(crc ^ b) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }
}
