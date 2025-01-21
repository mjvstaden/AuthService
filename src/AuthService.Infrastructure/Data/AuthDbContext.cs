using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AuthService.Domain.Entities;

namespace AuthService.Infrastructure.Data;

public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
        : base(options)
    {
    }

    public DbSet<ExternalLogin> ExternalLogins { get; set; }
    public DbSet<Organization> Organizations { get; set; }
    public DbSet<OrganizationUser> OrganizationUsers { get; set; }
    public DbSet<OrganizationRole> OrganizationRoles { get; set; }
    public DbSet<OrganizationUserRole> OrganizationUserRoles { get; set; }
    public DbSet<Permission> Permissions { get; set; }
    public DbSet<OrganizationRolePermission> OrganizationRolePermissions { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ExternalLogin>(entity =>
        {
            entity.HasKey(e => new { e.Provider, e.ProviderUserId });
            
            entity.HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // Configure Organization relationships
        builder.Entity<OrganizationUser>(entity =>
        {
            entity.HasKey(e => new { e.OrganizationId, e.UserId });

            entity.HasOne(e => e.Organization)
                .WithMany(o => o.OrganizationUsers)
                .HasForeignKey(e => e.OrganizationId);

            entity.HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId);
        });

        builder.Entity<OrganizationUserRole>(entity =>
        {
            entity.HasKey(e => new { e.OrganizationId, e.UserId, e.RoleId });

            entity.HasOne(e => e.OrganizationUser)
                .WithMany(ou => ou.UserRoles)
                .HasForeignKey(e => new { e.OrganizationId, e.UserId })
                .OnDelete(DeleteBehavior.NoAction);

            entity.HasOne(e => e.Role)
                .WithMany(r => r.UserRoles)
                .HasForeignKey(e => e.RoleId)
                .OnDelete(DeleteBehavior.NoAction);
        });

        builder.Entity<OrganizationRolePermission>(entity =>
        {
            entity.HasKey(e => new { e.RoleId, e.PermissionId });

            entity.HasOne(e => e.Role)
                .WithMany(r => r.RolePermissions)
                .HasForeignKey(e => e.RoleId);

            entity.HasOne(e => e.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(e => e.PermissionId);
        });
    }
} 