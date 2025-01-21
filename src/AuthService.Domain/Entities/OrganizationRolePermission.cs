namespace AuthService.Domain.Entities;

public class OrganizationRolePermission
{
    public required string RoleId { get; set; }
    public required string PermissionId { get; set; }
    
    // Navigation properties
    public required OrganizationRole Role { get; set; }
    public required Permission Permission { get; set; }
} 