using azure_auth_SAML_dotnet8;

var builder = WebApplication.CreateBuilder(args);

var configuration = builder.Configuration;

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("Login", () =>
{
    try
    {
        var issuer = configuration["SAML:issuer"];
        var assertionConsumerServiceUrl = configuration["SAML:AssertionConsumerServiceURL"];
        var samlUrl = configuration["SAML:URL"];

        if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(assertionConsumerServiceUrl) || string.IsNullOrEmpty(samlUrl))
        {
            return Results.Unauthorized();
        }

        var request = new SAMLAuthRequest(issuer, assertionConsumerServiceUrl);
        var stringRequest = request.GetRedirectUrl(samlUrl);

        return Results.Redirect(stringRequest);
    }
    catch (Exception)
    {
        return Results.Unauthorized();
    }
})
.WithName("Login")
.WithOpenApi();


// Se estiver utilizando mvc pode passar direto por parametro '[FromForm(Name = "SAMLResponse")] string samlResponse, [FromQuery] string callback'
app.MapPost("Consume", async (HttpRequest request) =>
{
    try
    {
        var certificate = configuration["SAML:Certificate"];
        if (string.IsNullOrEmpty(certificate))
        {
            return Results.Unauthorized();
        }

        var form = await request.ReadFormAsync();
        var samlResponse = form["SAMLResponse"];

        if (string.IsNullOrEmpty(samlResponse))
        {
            return Results.Unauthorized();
        }

        SAMLResponse response = new SAMLResponse(certificate, samlResponse);

        if (response.IsValid())
        {
            return Results.Ok($"Email: {response.GetEmail()} - LOGADO !");
        }

        return Results.Unauthorized();
    }
    catch (Exception)
    {
        return Results.Unauthorized();
    }
})
.WithName("Consume")
.WithOpenApi();

app.Run();