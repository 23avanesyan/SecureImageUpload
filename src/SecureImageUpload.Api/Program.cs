using System.Threading.RateLimiting;
using Microsoft.OpenApi;
using SecureImageUpload.Api;
using SecureImageUpload.Api.Endpoints;
using SecureImageUpload.Api.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOptions<UploadOptions>()
    .BindConfiguration(UploadOptions.Section)
    .Validate(o => !string.IsNullOrWhiteSpace(o.StorageRoot), "Upload:StorageRoot must be configured.")
    .Validate(o => o.MaxFileBytes is > 0 and <= 100 * 1024 * 1024, "Upload:MaxFileBytes is out of range.")
    .Validate(o => o.MaxWidth > 0 && o.MaxHeight > 0 && o.MaxPixels > 0 && o.MaxConcurrentDecodes > 0, "Upload limits must be positive.")
    .ValidateOnStart();

UploadOptions uploadOptions = builder.Configuration.GetSection(UploadOptions.Section).Get<UploadOptions>() ?? new UploadOptions();
long maxRequestBytes = uploadOptions.MaxFileBytes + 64 * 1024; // file + multipart framing

// Transport-level cap: the server aborts oversized bodies before application code buffers them.
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.Limits.MaxRequestBodySize = maxRequestBytes;
    kestrel.Limits.MaxRequestHeadersTotalSize = 16 * 1024;
    kestrel.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
});
builder.Services.Configure<IISServerOptions>(iis => iis.MaxRequestBodySize = maxRequestBytes);

// Bearer tokens (not cookies) keep the upload endpoint out of reach of CSRF.
// Configure the issuer under "Authentication:Schemes:Bearer"; for local testing use `dotnet user-jwts create`.
builder.Services.AddAuthentication().AddJwtBearer();
builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(limiter =>
{
    limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    limiter.AddPolicy(ImageEndpoints.UploadRateLimitPolicy, context => RateLimitPartition.GetFixedWindowLimiter(
        ImageEndpoints.GetUserId(context.User) ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = uploadOptions.UploadsPerMinutePerUser,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
});

// OpenAPI document with a Bearer scheme, so Swagger UI shows the "Authorize" button.
builder.Services.AddOpenApi(openApi => openApi.AddDocumentTransformer((document, _, _) =>
{
    document.Info.Title = "SecureImageUpload";
    document.Components ??= new OpenApiComponents();
    document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
    document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        Description = "JWT without the 'Bearer ' prefix. Local token: dotnet user-jwts create --project src/SecureImageUpload.Api",
    };
    document.Security = [new OpenApiSecurityRequirement { [new OpenApiSecuritySchemeReference("Bearer", document)] = [] }];
    return Task.CompletedTask;
}));

builder.Services.AddSingleton<ImageSanitizer>();
builder.Services.AddSingleton<ImageStorage>();
builder.Services.AddSingleton<ImageUploadService>();

var app = builder.Build();

// Uploaded files must never be reachable through static-file serving.
string storageRoot = app.Services.GetRequiredService<ImageStorage>().Root;
string? webRoot = app.Environment.WebRootPath;
if (!string.IsNullOrEmpty(webRoot) && storageRoot.StartsWith(Path.GetFullPath(webRoot), StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("Upload:StorageRoot must not be inside the web root.");

// Swagger is a testing aid: it describes the API surface, so it is exposed in Development only.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(ui =>
    {
        ui.SwaggerEndpoint("/openapi/v1.json", "SecureImageUpload v1");
        ui.EnablePersistAuthorization();
    });
}

if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.MapImageEndpoints();

app.Run();

public partial class Program;
