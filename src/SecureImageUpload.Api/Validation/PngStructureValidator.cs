using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace SecureImageUpload.Api.Validation;

/// <summary>
/// Walks every PNG chunk without decoding pixels: verifies lengths, CRCs, ordering and the IHDR,
/// rejects animation and unknown critical chunks, and refuses anything after IEND.
/// </summary>
public static class PngStructureValidator
{
    private const int MaxChunks = 20_000;
    private const int MaxInflatedMetadataBytes = 2 * 1024 * 1024;

    public static ImageStructure Validate(byte[] data, UploadOptions options)
    {
        var regions = new List<ReadOnlyMemory<byte>>();
        int pos = 8, chunks = 0, width = 0, height = 0;
        byte colorType = 0;
        bool seenIhdr = false, seenPlte = false, seenIdat = false, idatEnded = false, seenIend = false;

        while (pos < data.Length && !seenIend)
        {
            if (++chunks > MaxChunks) throw Malformed("too many chunks");
            if (data.Length - pos < 12) throw Malformed("truncated chunk header");

            uint declaredLength = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));
            if (declaredLength > (uint)(data.Length - pos - 12)) throw Malformed("chunk length exceeds file size");
            int length = (int)declaredLength;

            ReadOnlySpan<byte> typeBytes = data.AsSpan(pos + 4, 4);
            foreach (byte b in typeBytes)
            {
                if (!((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z'))) throw Malformed("invalid chunk type");
            }

            string type = Encoding.ASCII.GetString(typeBytes);
            int bodyStart = pos + 8;
            uint storedCrc = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(bodyStart + length));
            if (Crc32.Compute(data.AsSpan(pos + 4, 4 + length)) != storedCrc) throw Malformed($"bad CRC in {type}");

            if (!seenIhdr && type != "IHDR") throw Malformed("first chunk is not IHDR");
            if (seenIdat && type != "IDAT") idatEnded = true;

            switch (type)
            {
                case "IHDR":
                    if (seenIhdr || length != 13) throw Malformed("duplicate or invalid IHDR");
                    seenIhdr = true;
                    (width, height, colorType) = ParseHeader(data.AsSpan(bodyStart, length), options);
                    break;

                case "PLTE":
                    if (seenPlte || seenIdat || length == 0 || length % 3 != 0 || length > 768) throw Malformed("invalid PLTE");
                    seenPlte = true;
                    break;

                case "IDAT":
                    if (idatEnded) throw Malformed("IDAT chunks are not consecutive");
                    seenIdat = true;
                    break;

                case "IEND":
                    if (length != 0 || !seenIdat) throw Malformed("invalid IEND or no image data");
                    seenIend = true;
                    break;

                case "acTL" or "fcTL" or "fdAT":
                    throw Malformed("animated PNG is not allowed");

                default:
                    // Bit 5 of the first byte clear = critical chunk. Unknown critical chunks must not be accepted.
                    if ((typeBytes[0] & 0x20) == 0) throw Malformed($"unknown critical chunk {type}");
                    regions.Add(data.AsMemory(bodyStart, length));
                    AddInflatedPayload(type, data, bodyStart, length, regions);
                    break;
            }

            pos = bodyStart + length + 4;
        }

        if (!seenIend) throw Malformed("missing IEND");
        if (colorType == 3 && !seenPlte) throw Malformed("indexed PNG without palette");

        // Always strict for PNG: no camera or editor legitimately appends data after IEND.
        if (pos != data.Length)
            throw new UploadRejectedException(RejectReason.TrailingData, $"{data.Length - pos} bytes after IEND");

        return new ImageStructure(width, height, regions);
    }

    private static (int Width, int Height, byte ColorType) ParseHeader(ReadOnlySpan<byte> ihdr, UploadOptions options)
    {
        uint width = BinaryPrimitives.ReadUInt32BigEndian(ihdr);
        uint height = BinaryPrimitives.ReadUInt32BigEndian(ihdr[4..]);
        byte bitDepth = ihdr[8], colorType = ihdr[9];

        if (width == 0 || height == 0) throw Malformed("zero dimension");
        if (width > (uint)options.MaxWidth || height > (uint)options.MaxHeight || (long)width * height > options.MaxPixels)
            throw new UploadRejectedException(RejectReason.DimensionsExceeded, $"{width}x{height}");

        bool depthValid = colorType switch
        {
            0 => bitDepth is 1 or 2 or 4 or 8 or 16,
            3 => bitDepth is 1 or 2 or 4 or 8,
            2 or 4 or 6 => bitDepth is 8 or 16,
            _ => false,
        };
        if (!depthValid) throw Malformed("invalid color type / bit depth");
        if (ihdr[10] != 0 || ihdr[11] != 0 || ihdr[12] > 1) throw Malformed("invalid compression, filter or interlace method");

        return ((int)width, (int)height, colorType);
    }

    /// <summary>zTXt, iTXt and iCCP hide their payload behind zlib; inflate it (bounded) so it can be scanned.</summary>
    private static void AddInflatedPayload(string type, byte[] data, int start, int length, List<ReadOnlyMemory<byte>> regions)
    {
        if (type is not ("zTXt" or "iTXt" or "iCCP")) return;

        ReadOnlySpan<byte> body = data.AsSpan(start, length);
        int keywordEnd = body.IndexOf((byte)0);
        if (keywordEnd < 1 || keywordEnd > 79) throw Malformed($"invalid keyword in {type}");

        int offset;
        if (type == "iTXt")
        {
            if (keywordEnd + 3 > body.Length) throw Malformed("truncated iTXt");
            byte compressed = body[keywordEnd + 1];
            if (compressed > 1) throw Malformed("invalid iTXt compression flag");
            if (compressed == 0) return;
            if (body[keywordEnd + 2] != 0) throw Malformed("unknown iTXt compression method");

            offset = keywordEnd + 3;
            for (int i = 0; i < 2; i++) // language tag, translated keyword
            {
                int end = body[offset..].IndexOf((byte)0);
                if (end < 0) throw Malformed("truncated iTXt");
                offset += end + 1;
            }
        }
        else
        {
            if (keywordEnd + 2 > body.Length) throw Malformed($"truncated {type}");
            if (body[keywordEnd + 1] != 0) throw Malformed($"unknown {type} compression method");
            offset = keywordEnd + 2;
        }

        try
        {
            using var input = new MemoryStream(data, start + offset, length - offset, writable: false);
            using var zlib = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = zlib.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + read > MaxInflatedMetadataBytes) throw Malformed($"{type} expands beyond limit (zip bomb)");
                output.Write(buffer, 0, read);
            }
            regions.Add(output.ToArray());
        }
        catch (InvalidDataException)
        {
            throw Malformed($"corrupt compressed data in {type}");
        }
    }

    private static UploadRejectedException Malformed(string detail) => new(RejectReason.MalformedImage, "PNG: " + detail);
}
