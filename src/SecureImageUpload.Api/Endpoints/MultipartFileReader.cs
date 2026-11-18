using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using SecureImageUpload.Api.Validation;

namespace SecureImageUpload.Api.Endpoints;

/// <summary>
/// Reads exactly one file part named "file" from a multipart request, streaming with a hard byte cap.
/// The framework's form binder is deliberately not used: it buffers to disk and accepts arbitrary extra parts.
/// </summary>
public static class MultipartFileReader
{
    public const string FieldName = "file";

    public static async Task<(string? FileName, string? ContentType, byte[] Data)> ReadSingleFileAsync(
        HttpRequest request, long maxFileBytes, CancellationToken cancellationToken)
    {
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out MediaTypeHeaderValue? requestType)
            || !requestType.MediaType.Equals("multipart/form-data", StringComparison.OrdinalIgnoreCase))
            throw Bad("request is not multipart/form-data");

        string? boundary = HeaderUtilities.RemoveQuotes(requestType.Boundary).Value;
        if (string.IsNullOrWhiteSpace(boundary) || boundary.Length > 70) throw Bad("missing or oversized multipart boundary");

        // Content-Length is only a hint; the counting loop below is what actually enforces the limit.
        if (request.ContentLength > maxFileBytes + 16 * 1024) throw new UploadRejectedException(RejectReason.TooLarge, "Content-Length exceeds limit");

        var reader = new MultipartReader(boundary, request.Body)
        {
            HeadersCountLimit = 8,
            HeadersLengthLimit = 4096,
            BodyLengthLimit = maxFileBytes + 1,
        };

        (string?, string?, byte[])? result = null;
        try
        {
            while (await reader.ReadNextSectionAsync(cancellationToken) is { } section)
            {
                if (result is not null) throw Bad("more than one multipart section");

                if (!ContentDispositionHeaderValue.TryParse(section.ContentDisposition, out ContentDispositionHeaderValue? disposition)
                    || !disposition.DispositionType.Equals("form-data", StringComparison.OrdinalIgnoreCase)
                    || HeaderUtilities.RemoveQuotes(disposition.Name).Value != FieldName)
                    throw Bad("unexpected multipart section");

                // "filename" and "filename*" disagreeing is a classic parser-differential trick.
                string? fileName = HeaderUtilities.RemoveQuotes(disposition.FileName).Value;
                string? fileNameStar = HeaderUtilities.RemoveQuotes(disposition.FileNameStar).Value;
                if (fileName is null && fileNameStar is null) throw Bad("section is not a file");
                if (fileName is not null && fileNameStar is not null && fileName != fileNameStar) throw Bad("conflicting filename parameters");

                using var buffer = new MemoryStream();
                byte[] chunk = new byte[81920];
                int read;
                while ((read = await section.Body.ReadAsync(chunk, cancellationToken)) > 0)
                {
                    if (buffer.Length + read > maxFileBytes) throw new UploadRejectedException(RejectReason.TooLarge, "file exceeds limit");
                    buffer.Write(chunk, 0, read);
                }

                result = (fileNameStar ?? fileName, section.ContentType, buffer.ToArray());
            }
        }
        catch (BadHttpRequestException ex) // server-level body limit; must precede IOException, its base type
        {
            throw new UploadRejectedException(ex.StatusCode == 413 ? RejectReason.TooLarge : RejectReason.BadRequest, ex.Message);
        }
        catch (InvalidDataException ex)
        {
            throw Bad("multipart limits exceeded: " + ex.Message);
        }
        catch (IOException ex)
        {
            throw Bad("malformed multipart body: " + ex.Message);
        }

        return result ?? throw Bad("no file section");
    }

    private static UploadRejectedException Bad(string detail) => new(RejectReason.BadRequest, detail);
}
