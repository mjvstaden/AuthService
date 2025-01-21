namespace AuthService.Domain.Entities;

public class OrganizationUserRole
{
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    public required string RoleId { get; set; }
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    public required OrganizationUser OrganizationUser { get; set; }
    public required OrganizationRole Role { get; set; }
} 