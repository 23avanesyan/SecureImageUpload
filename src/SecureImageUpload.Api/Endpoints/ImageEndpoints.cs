using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;
using SecureImageUpload.Api.Services;
using SecureImageUpload.Api.Validation;

namespace SecureImageUpload.Api.Endpoints;

public static class ImageEndpoints
{
    public const string UploadRateLimitPolicy = "upload";

    public static void MapImageEndpoints(this IEndpointRouteBuilder app)
    {
        RouteGroupBuilder group = app.MapGroup("/api/images").RequireAuthorization();
        group.MapPost("/", UploadAsync)
            .RequireRateLimiting(UploadRateLimitPolicy)
            .WithSummary("Upload one PNG or JPEG image (.png, .jpg, .jpeg)")
            .Produces(StatusCodes.Status201Created)
            .Produces(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status413PayloadTooLarge)
            .Produces(StatusCodes.Status415UnsupportedMediaType)
            .Produces(StatusCodes.Status422UnprocessableEntity)
            .Produces(StatusCodes.Status429TooManyRequests)
            .AddOpenApiOperationTransformer((operation, _, _) =>
            {
                // The handler parses multipart itself, so the body has to be described by hand.
                operation.RequestBody = new OpenApiRequestBody
                {
                    Required = true,
                    Content = new Dictionary<string, OpenApiMediaType>
                    {
                        ["multipart/form-data"] = new()
                        {
                            Schema = new OpenApiSchema
                            {
                                Type = JsonSchemaType.Object,
                                Required = new HashSet<string> { MultipartFileReader.FieldName },
                                Properties = new Dictionary<string, IOpenApiSchema>
                                {
                                    [MultipartFileReader.FieldName] = new OpenApiSchema { Type = JsonSchemaType.String, Format = "binary" },
                                },
                            },
                        },
                    },
                };
                return Task.CompletedTask;
            });

        group.MapGet("/{id}", Download)
            .WithSummary("Download an image you uploaded")
            .Produces(StatusCodes.Status200OK, contentType: "image/png", additionalContentTypes: "image/jpeg")
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status404NotFound);
    }

    public static string? GetUserId(ClaimsPrincipal user) =>
        user.FindFirstValue(ClaimTypes.NameIdentifier) ?? user.FindFirstValue("sub");

    private static async Task<IResult> UploadAsync(
        HttpContext context, ImageUploadService uploads, IOptions<UploadOptions> options, CancellationToken cancellationToken)
    {
        string? userId = GetUserId(context.User);
        if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

        try
        {
            (string? fileName, string? contentType, byte[] data) =
                await MultipartFileReader.ReadSingleFileAsync(context.Request, options.Value.MaxFileBytes, cancellationToken);

            StoredImage image = await uploads.ProcessAsync(userId, fileName, contentType, data, cancellationToken);

            return Results.Created($"/api/images/{image.Id}", new
            {
                id = image.Id,
                contentType = ImageSignature.ContentType(image.Format),
                width = image.Width,
                height = image.Height,
                size = image.Size,
            });
        }
        catch (UploadRejectedException ex)
        {
            // Coarse code only: the precise reason stays in the server log.
            (int status, string code) = ex.ClientError;
            return Results.Json(new { error = code }, statusCode: status);
        }
    }

    private static IResult Download(string id, HttpContext context, ImageStorage storage)
    {
        string? userId = GetUserId(context.User);
        if (string.IsNullOrEmpty(userId)) return Results.Unauthorized();

        if (storage.TryOpen(userId, id) is not var (stream, format)) return Results.NotFound();

        // Even a sanitized image is served as inert data: no sniffing, no scripting, no embedding elsewhere.
        IHeaderDictionary headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers.ContentSecurityPolicy = "default-src 'none'; sandbox";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";
        headers.CacheControl = "private, no-store";
        headers.ContentDisposition = $"inline; filename=\"{id}{ImageSignature.Extension(format)}\"";

        return Results.Stream(stream, ImageSignature.ContentType(format));
    }
}
