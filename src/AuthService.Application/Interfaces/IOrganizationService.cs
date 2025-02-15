using AuthService.Domain.Entities;

namespace AuthService.Application.Interfaces;

public interface IOrganizationService
{
    Task<Organization> CreateOrganizationAsync(string name, string? description);
    Task<Organization?> GetOrganizationByIdAsync(string id);
    Task<IEnumerable<Organization>> GetUserOrganizationsAsync(string userId);
    Task AddUserToOrganizationAsync(string organizationId, string userId);
    Task RemoveUserFromOrganizationAsync(string organizationId, string userId);
    Task AssignRoleToUserAsync(string organizationId, string userId, string roleId);
    Task RemoveRoleFromUserAsync(string organizationId, string userId, string roleId);
    Task<OrganizationRole> CreateRoleAsync(string organizationId, string name, string? description);
    Task<IEnumerable<OrganizationRole>> GetOrganizationRolesAsync(string organizationId);
    Task<IEnumerable<Permission>> GetRolePermissionsAsync(string roleId);
    Task AssignPermissionToRoleAsync(string roleId, string permissionId);
    Task RemovePermissionFromRoleAsync(string roleId, string permissionId);
    Task<bool> UserHasPermissionAsync(string organizationId, string userId, string permissionName);
    Task<Permission> CreatePermissionAsync(string name, string? description);
    Task DeletePermissionAsync(string permissionId);
    Task<Permission?> GetPermissionByIdAsync(string permissionId);
    Task<Organization> UpdateOrganizationAsync(string organizationId, string? name, string? description);
    Task<OrganizationRole> UpdateRoleAsync(string roleId, string? name, string? description);
    Task<Permission> UpdatePermissionAsync(string permissionId, string? name, string? description);
} 