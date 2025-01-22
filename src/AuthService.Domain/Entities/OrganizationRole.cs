using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities;

public class OrganizationRole
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string OrganizationId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    // Navigation properties
    [JsonIgnore]
    public Organization Organization { get; set; } = null!;
    [JsonIgnore]
    public ICollection<OrganizationUserRole> UserRoles { get; set; } = new List<OrganizationUserRole>();
    [JsonIgnore]
    public ICollection<OrganizationRolePermission> RolePermissions { get; set; } = new List<OrganizationRolePermission>();
} 