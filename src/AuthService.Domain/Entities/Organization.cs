using System;
using System.Text.Json.Serialization;

namespace AuthService.Domain.Entities;

public class Organization
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
    
    // Navigation properties
    [JsonIgnore]
    public ICollection<OrganizationUser> OrganizationUsers { get; set; } = new List<OrganizationUser>();
    
    [JsonIgnore]
    public ICollection<OrganizationRole> OrganizationRoles { get; set; } = new List<OrganizationRole>();
} 