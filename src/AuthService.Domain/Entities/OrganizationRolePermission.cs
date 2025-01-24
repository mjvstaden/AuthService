using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities;

public class OrganizationRolePermission
{
    public required string RoleId { get; set; }
    public required string PermissionId { get; set; }
    
    // Navigation properties
    [JsonIgnore]
    public required OrganizationRole Role { get; set; }
    [JsonIgnore]
    public required Permission Permission { get; set; }
} 