namespace AuthService.Application.Models.ExternalAuth;

public class ExternalAuthCallback
{
    public string? Code { get; set; }
    public string? State { get; set; }
    public string? Error { get; set; }
} 