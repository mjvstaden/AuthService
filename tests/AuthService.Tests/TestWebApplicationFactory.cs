using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using AuthService.Infrastructure.Data;
using AuthService.API;

namespace AuthService.Tests;

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Set environment to Testing
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            // Remove the app's DbContext registration
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<AuthDbContext>));

            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            // Add DbContext using an in-memory database for testing
            services.AddDbContext<AuthDbContext>(options =>
            {
                options.UseInMemoryDatabase("TestDb");
            });

            // Configure test settings
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Jwt:Key"] = "YourSuperSecretKeyForTestingThatIsAtLeast32BytesLong",
                    ["Jwt:Issuer"] = "test-issuer",
                    ["Jwt:Audience"] = "test-audience",
                    ["ExternalAuth:Google:ClientId"] = "test-client-id",
                    ["ExternalAuth:Google:ClientSecret"] = "test-client-secret",
                    ["ExternalAuth:Google:RedirectUri"] = "https://localhost:5001/api/auth/external-callback/google"
                })
                .Build();

            services.AddSingleton<IConfiguration>(configuration);

            // Build the service provider
            var sp = services.BuildServiceProvider();

            // Create a scope to obtain a reference to the database context
            using (var scope = sp.CreateScope())
            {
                var scopedServices = scope.ServiceProvider;
                var db = scopedServices.GetRequiredService<AuthDbContext>();

                // Ensure the database is created
                db.Database.EnsureCreated();
            }
        });
    }
} 