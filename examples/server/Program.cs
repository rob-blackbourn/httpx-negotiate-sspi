using Microsoft.AspNetCore.Authentication.Negotiate;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = options.DefaultPolicy;
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Authenticated ASP.NET Core application");

app.MapGet("/whoami", (HttpContext context) =>
{
    var user = context.User;

    return Results.Ok(new
    {
        Name = user.Identity?.Name,
        IsAuthenticated = user.Identity?.IsAuthenticated,
        AuthenticationType = user.Identity?.AuthenticationType,
        Claims = user.Claims.Select(c => new
        {
            c.Type,
            c.Value
        })
    });
});

app.Run();
