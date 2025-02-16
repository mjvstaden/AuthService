namespace AuthService.Application.Models;

public record RequestPasswordResetRequest
{
    public required string Email { get; init; }
}

public record ResetPasswordRequest
{
    public required string Email { get; init; }
    public required string Token { get; init; }
    public required string NewPassword { get; init; }
}

public record PasswordResetResponse
{
    public required bool Success { get; init; }
    public string? Message { get; init; }
} 