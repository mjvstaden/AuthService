namespace AuthService.Application.Models;

public record RegisterRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
    public required string FirstName { get; init; }
    public required string LastName { get; init; }
    public string? PhoneNumber { get; init; }
}

public record LoginRequest
{
    public required string Email { get; init; }
    public required string Password { get; init; }
}

public record AuthenticationResponse
{
    public required string Token { get; init; }
    public required string RefreshToken { get; init; }
    public required DateTime ExpiresAt { get; init; }
}

public record RefreshTokenRequest
{
    public required string RefreshToken { get; init; }
} 