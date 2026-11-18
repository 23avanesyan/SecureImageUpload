using Microsoft.Extensions.Options;
using SecureImageUpload.Api.Validation;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.Memory;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using ImageFormat = SecureImageUpload.Api.Validation.ImageFormat;

namespace SecureImageUpload.Api.Services;

/// <summary>
/// Content disarm and reconstruction: decodes the upload to raw pixels with a fully managed decoder,
/// copies only the pixels into a brand-new image and encodes that. Nothing from the original file
/// (metadata, comments, profiles, trailers, unusual encodings) reaches storage.
/// </summary>
public sealed class ImageSanitizer
{
    private readonly UploadOptions _options;
    private readonly Configuration _configuration;

    public ImageSanitizer(IOptions<UploadOptions> options)
    {
        _options = options.Value;

        // Only the PNG and JPEG codecs are registered, so no other decoder (GIF, BMP, TIFF, WebP...) is reachable.
        _configuration = new Configuration(new PngConfigurationModule(), new JpegConfigurationModule())
        {
            MemoryAllocator = MemoryAllocator.Create(new MemoryAllocatorOptions
            {
                AllocationLimitMegabytes = _options.DecoderMemoryLimitMegabytes,
            }),
        };
    }

    public async Task<(byte[] Data, int Width, int Height)> SanitizeAsync(byte[] data, ImageFormat expected, CancellationToken cancellationToken)
    {
        try
        {
            var decoderOptions = new DecoderOptions { Configuration = _configuration, MaxFrames = 1 };
            using var input = new MemoryStream(data, writable: false);
            using Image<Rgba32> source = await Image.LoadAsync<Rgba32>(decoderOptions, input, cancellationToken);

            bool formatMatches = expected == ImageFormat.Png
                ? source.Metadata.DecodedImageFormat is PngFormat
                : source.Metadata.DecodedImageFormat is JpegFormat;
            if (!formatMatches) throw new UploadRejectedException(RejectReason.TypeMismatch, "decoder disagrees with detected format");

            // Bake the EXIF orientation into the pixels before the metadata is thrown away.
            source.Mutate(x => x.AutoOrient());

            if (source.Width > _options.MaxWidth || source.Height > _options.MaxHeight || (long)source.Width * source.Height > _options.MaxPixels)
                throw new UploadRejectedException(RejectReason.DimensionsExceeded, $"decoded {source.Width}x{source.Height}");

            using var clean = new Image<Rgba32>(_configuration, source.Width, source.Height);
            source.ProcessPixelRows(clean, static (from, to) =>
            {
                for (int y = 0; y < from.Height; y++) from.GetRowSpan(y).CopyTo(to.GetRowSpan(y));
            });

            using var output = new MemoryStream();
            if (expected == ImageFormat.Png)
            {
                var encoder = new PngEncoder
                {
                    ChunkFilter = PngChunkFilter.ExcludeAll,
                    ColorType = PngColorType.RgbWithAlpha,
                    BitDepth = PngBitDepth.Bit8,
                };
                await clean.SaveAsync(output, encoder, cancellationToken);
            }
            else
            {
                await clean.SaveAsync(output, new JpegEncoder { Quality = _options.JpegQuality }, cancellationToken);
            }

            return (output.ToArray(), clean.Width, clean.Height);
        }
        catch (Exception ex) when (ex is not (UploadRejectedException or OperationCanceledException))
        {
            // Any decoder failure - corrupt data, unsupported feature, allocation limit - is a rejection, never a 500.
            throw new UploadRejectedException(RejectReason.DecodeFailed, $"{ex.GetType().Name}: {ex.Message}");
        }
    }
}
