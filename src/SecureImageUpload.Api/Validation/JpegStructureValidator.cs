using System.Buffers.Binary;

namespace SecureImageUpload.Api.Validation;

/// <summary>
/// Walks every JPEG segment without decoding pixels: only baseline/extended/progressive Huffman frames,
/// exactly one frame, bounded scan count, mandatory EOI and nothing after it.
/// </summary>
public static class JpegStructureValidator
{
    private const int MaxSegments = 10_000;
    private const int MaxScans = 64; // progressive files with thousands of scans are a CPU DoS

    public static ImageStructure Validate(byte[] data, UploadOptions options)
    {
        var regions = new List<ReadOnlyMemory<byte>>();
        int pos = 2, width = 0, height = 0, scans = 0, segments = 0;
        bool seenFrame = false, seenEoi = false;

        while (pos < data.Length)
        {
            if (data[pos] != 0xFF) throw Malformed("expected marker");
            while (pos < data.Length && data[pos] == 0xFF) pos++; // fill bytes
            if (pos >= data.Length) throw Malformed("truncated marker");

            byte marker = data[pos++];
            if (++segments > MaxSegments) throw Malformed("too many segments");

            if (marker == 0xD9)
            {
                seenEoi = true;
                break;
            }

            // Stuffing, TEM, a second SOI or restart markers are illegal between segments.
            if (marker is 0x00 or 0x01 or 0xD8 or (>= 0xD0 and <= 0xD7)) throw Malformed($"unexpected marker 0x{marker:X2}");

            if (data.Length - pos < 2) throw Malformed("truncated segment length");
            int length = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos));
            if (length < 2 || length > data.Length - pos) throw Malformed("segment length exceeds file size");
            ReadOnlyMemory<byte> payload = data.AsMemory(pos + 2, length - 2);

            switch (marker)
            {
                case 0xC0 or 0xC1 or 0xC2: // SOF0 baseline, SOF1 extended, SOF2 progressive
                    if (seenFrame) throw Malformed("multiple frames");
                    seenFrame = true;
                    (width, height) = ParseFrame(payload.Span, options);
                    break;

                case 0xC4 or 0xDB or 0xDD: // DHT, DQT, DRI
                    break;

                case 0xDA: // SOS
                    if (!seenFrame) throw Malformed("scan before frame header");
                    if (++scans > MaxScans) throw Malformed("too many scans");
                    pos = SkipEntropyCodedData(data, pos + length);
                    continue;

                case >= 0xE0 and <= 0xEF or 0xFE: // APPn (EXIF, XMP, ICC, ...) and COM
                    regions.Add(payload);
                    break;

                default:
                    // Lossless, hierarchical and arithmetic-coded frames, DNL, DHP, EXP and reserved markers.
                    throw Malformed($"unsupported marker 0x{marker:X2}");
            }

            pos += length;
        }

        if (!seenEoi) throw Malformed("missing EOI");
        if (!seenFrame || scans == 0) throw Malformed("no image data");

        if (pos != data.Length)
        {
            if (options.RejectTrailingData)
                throw new UploadRejectedException(RejectReason.TrailingData, $"{data.Length - pos} bytes after EOI");

            // Tolerated: phone cameras append HDR gain maps, depth maps and motion-photo video here.
            // The tail is binary, so it is not scanned with the short metadata patterns (false positives);
            // the whole-file signatures and canary domains still cover it, and re-encoding drops it.
        }

        return new ImageStructure(width, height, regions);
    }

    private static (int Width, int Height) ParseFrame(ReadOnlySpan<byte> sof, UploadOptions options)
    {
        if (sof.Length < 6) throw Malformed("truncated frame header");
        int height = BinaryPrimitives.ReadUInt16BigEndian(sof[1..]);
        int width = BinaryPrimitives.ReadUInt16BigEndian(sof[3..]);
        int components = sof[5];

        if (sof[0] != 8) throw Malformed("only 8-bit precision is allowed");
        if (width == 0 || height == 0) throw Malformed("zero dimension");
        if (components is not (1 or 3 or 4) || sof.Length != 6 + 3 * components) throw Malformed("invalid component count");

        for (int i = 0; i < components; i++)
        {
            int sampling = sof[6 + 3 * i + 1];
            int h = sampling >> 4, v = sampling & 0x0F;
            if (h is < 1 or > 4 || v is < 1 or > 4 || sof[6 + 3 * i + 2] > 3) throw Malformed("invalid component parameters");
        }

        if (width > options.MaxWidth || height > options.MaxHeight || (long)width * height > options.MaxPixels)
            throw new UploadRejectedException(RejectReason.DimensionsExceeded, $"{width}x{height}");

        return (width, height);
    }

    /// <summary>Returns the offset of the 0xFF that starts the next real marker after a scan.</summary>
    private static int SkipEntropyCodedData(byte[] data, int pos)
    {
        while (true)
        {
            int next = data.AsSpan(pos).IndexOf((byte)0xFF);
            if (next < 0 || pos + next + 1 >= data.Length) throw Malformed("truncated scan data");
            pos += next;

            byte following = data[pos + 1];
            if (following == 0x00 || (following >= 0xD0 && following <= 0xD7)) pos += 2; // stuffed byte or RSTn
            else if (following == 0xFF) pos += 1;                                          // fill byte
            else return pos;
        }
    }

    private static UploadRejectedException Malformed(string detail) => new(RejectReason.MalformedImage, "JPEG: " + detail);
}
