using AuthService.Application.Models;
using AuthService.Application.Models.ExternalAuth;

namespace AuthService.Application.Services;

public interface IAuthenticationService
{
    Task<AuthenticationResponse> RegisterAsync(RegisterRequest request);
    Task<AuthenticationResponse> LoginAsync(LoginRequest request);
    Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken);
    string GetExternalAuthorizationUrl(ExternalAuthRequest request);
    Task<AuthenticationResponse> HandleExternalAuthCallbackAsync(string provider, ExternalAuthCallback callback);
    Task<bool> LogoutAsync(string userId);
} 