using AuthService.Domain.Entities;
using AuthService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Application.Services;

public class OrganizationService : IOrganizationService
{
    private readonly AuthDbContext _context;

    public OrganizationService(AuthDbContext context)
    {
        _context = context;
    }

    public async Task<Organization> CreateOrganizationAsync(string name, string? description)
    {
        var organization = new Organization
        {
            Name = name,
            Description = description
        };

        _context.Organizations.Add(organization);
        await _context.SaveChangesAsync();
        return organization;
    }

    public async Task<Organization?> GetOrganizationByIdAsync(string id)
    {
        return await _context.Organizations
            .Include(o => o.OrganizationUsers)
            .Include(o => o.OrganizationRoles)
            .FirstOrDefaultAsync(o => o.Id == id);
    }

    public async Task<IEnumerable<Organization>> GetUserOrganizationsAsync(string userId)
    {
        return await _context.OrganizationUsers
            .Where(ou => ou.UserId == userId)
            .Include(ou => ou.Organization)
            .Select(ou => ou.Organization)
            .ToListAsync();
    }

    public async Task AddUserToOrganizationAsync(string organizationId, string userId)
    {
        var exists = await _context.OrganizationUsers
            .AnyAsync(ou => ou.OrganizationId == organizationId && ou.UserId == userId);

        if (!exists)
        {
            var organization = await _context.Organizations.FindAsync(organizationId) 
                ?? throw new InvalidOperationException("Organization not found");
            var user = await _context.Users.FindAsync(userId)
                ?? throw new InvalidOperationException("User not found");

            _context.OrganizationUsers.Add(new OrganizationUser
            {
                OrganizationId = organizationId,
                UserId = userId,
                Organization = organization,
                User = user
            });
            await _context.SaveChangesAsync();
        }
    }

    public async Task RemoveUserFromOrganizationAsync(string organizationId, string userId)
    {
        var organizationUser = await _context.OrganizationUsers
            .FirstOrDefaultAsync(ou => ou.OrganizationId == organizationId && ou.UserId == userId);

        if (organizationUser != null)
        {
            _context.OrganizationUsers.Remove(organizationUser);
            await _context.SaveChangesAsync();
        }
    }

    public async Task AssignRoleToUserAsync(string organizationId, string userId, string roleId)
    {
        var exists = await _context.OrganizationUserRoles
            .AnyAsync(our => our.OrganizationId == organizationId && 
                            our.UserId == userId && 
                            our.RoleId == roleId);

        if (!exists)
        {
            var organizationUser = await _context.OrganizationUsers
                .FirstOrDefaultAsync(ou => ou.OrganizationId == organizationId && ou.UserId == userId)
                ?? throw new InvalidOperationException("User is not a member of the organization");
                
            var role = await _context.OrganizationRoles.FindAsync(roleId)
                ?? throw new InvalidOperationException("Role not found");

            _context.OrganizationUserRoles.Add(new OrganizationUserRole
            {
                OrganizationId = organizationId,
                UserId = userId,
                RoleId = roleId,
                OrganizationUser = organizationUser,
                Role = role
            });
            await _context.SaveChangesAsync();
        }
    }

    public async Task RemoveRoleFromUserAsync(string organizationId, string userId, string roleId)
    {
        var userRole = await _context.OrganizationUserRoles
            .FirstOrDefaultAsync(our => our.OrganizationId == organizationId && 
                                      our.UserId == userId && 
                                      our.RoleId == roleId);

        if (userRole != null)
        {
            _context.OrganizationUserRoles.Remove(userRole);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<OrganizationRole> CreateRoleAsync(string organizationId, string name, string? description)
    {
        var organization = await _context.Organizations.FindAsync(organizationId)
            ?? throw new InvalidOperationException("Organization not found");

        var role = new OrganizationRole
        {
            OrganizationId = organizationId,
            Name = name,
            Description = description,
            Organization = organization
        };

        _context.OrganizationRoles.Add(role);
        await _context.SaveChangesAsync();
        return role;
    }

    public async Task<IEnumerable<OrganizationRole>> GetOrganizationRolesAsync(string organizationId)
    {
        return await _context.OrganizationRoles
            .Where(r => r.OrganizationId == organizationId)
            .Include(r => r.RolePermissions)
                .ThenInclude(rp => rp.Permission)
            .ToListAsync();
    }

    public async Task<IEnumerable<Permission>> GetRolePermissionsAsync(string roleId)
    {
        return await _context.OrganizationRolePermissions
            .Where(rp => rp.RoleId == roleId)
            .Include(rp => rp.Permission)
            .Select(rp => rp.Permission)
            .ToListAsync();
    }

    public async Task AssignPermissionToRoleAsync(string roleId, string permissionId)
    {
        var exists = await _context.OrganizationRolePermissions
            .AnyAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

        if (!exists)
        {
            var role = await _context.OrganizationRoles.FindAsync(roleId)
                ?? throw new InvalidOperationException("Role not found");
            var permission = await _context.Permissions.FindAsync(permissionId)
                ?? throw new InvalidOperationException("Permission not found");

            _context.OrganizationRolePermissions.Add(new OrganizationRolePermission
            {
                RoleId = roleId,
                PermissionId = permissionId,
                Role = role,
                Permission = permission
            });
            await _context.SaveChangesAsync();
        }
    }

    public async Task RemovePermissionFromRoleAsync(string roleId, string permissionId)
    {
        var rolePermission = await _context.OrganizationRolePermissions
            .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

        if (rolePermission != null)
        {
            _context.OrganizationRolePermissions.Remove(rolePermission);
            await _context.SaveChangesAsync();
        }
    }

    public async Task<bool> UserHasPermissionAsync(string organizationId, string userId, string permissionName)
    {
        return await _context.OrganizationUserRoles
            .Where(our => our.OrganizationId == organizationId && our.UserId == userId)
            .Include(our => our.Role)
                .ThenInclude(r => r.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
            .AnyAsync(our => our.Role.RolePermissions
                .Any(rp => rp.Permission.Name == permissionName));
    }
} 