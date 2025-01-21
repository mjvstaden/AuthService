namespace AuthService.Domain.Entities;

public class OrganizationUser
{
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    public DateTime JoinedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    public required Organization Organization { get; set; }
    public required ApplicationUser User { get; set; }
    public ICollection<OrganizationUserRole> UserRoles { get; set; } = new List<OrganizationUserRole>();
} 