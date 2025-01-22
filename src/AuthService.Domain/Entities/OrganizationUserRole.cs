using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities;

public class OrganizationUserRole
{
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    public required string RoleId { get; set; }
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    [JsonIgnore]
    public required OrganizationUser OrganizationUser { get; set; }
    [JsonIgnore]
    public required OrganizationRole Role { get; set; }
} 