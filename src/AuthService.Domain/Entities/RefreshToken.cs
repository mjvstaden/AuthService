using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AuthService.Domain.Entities;

public class RefreshToken
{
    [Key]
    public required string Token { get; set; }
    
    [Required]
    public required string UserId { get; set; }
    
    [Required]
    public required DateTime ExpiresAt { get; set; }
    
    [Required]
    public DateTime CreatedAt { get; set; }
    
    [Required]
    public bool IsRevoked { get; set; }
    
    [ForeignKey(nameof(UserId))]
    public required ApplicationUser User { get; set; }
} 