using System;

namespace AuthService.Domain.Entities;

public class ExternalLogin
{
    public required string UserId { get; set; }
    public required string Provider { get; set; }
    public required string ProviderUserId { get; set; }
    public required DateTime CreatedAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    
    public required ApplicationUser User { get; set; }
} 