using System;

namespace AuthService.Domain.Entities;

public class Organization
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    public ICollection<OrganizationUser> OrganizationUsers { get; set; } = new List<OrganizationUser>();
    public ICollection<OrganizationRole> OrganizationRoles { get; set; } = new List<OrganizationRole>();
} 