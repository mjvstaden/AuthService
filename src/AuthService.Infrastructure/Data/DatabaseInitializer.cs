using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthService.Infrastructure.Data;

public static class DatabaseInitializer
{
    public static async Task InitializeDatabaseAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var services = scope.ServiceProvider;
        try
        {
            var context = services.GetRequiredService<AuthDbContext>();
            var logger = services.GetRequiredService<ILogger<AuthDbContext>>();
            
            logger.LogInformation("Starting database migration...");
            await context.Database.MigrateAsync();
            logger.LogInformation("Database migration completed successfully.");
        }
        catch (Exception ex)
        {
            var logger = services.GetRequiredService<ILogger<AuthDbContext>>();
            logger.LogError(ex, "An error occurred while initializing the database.");
            throw;
        }
    }
} 