using System.ComponentModel.DataAnnotations;

namespace AuthService.Application.Models.ExternalAuth;

public class ExternalAuthRequest
{
    public required string Provider { get; set; }
    public required string ReturnUrl { get; set; }
} 