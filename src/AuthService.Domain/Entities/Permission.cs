using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities;

public class Permission
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    [JsonIgnore]
    public ICollection<OrganizationRolePermission> RolePermissions { get; set; } = new List<OrganizationRolePermission>();
} 