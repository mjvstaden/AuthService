using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Application.Models;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using AuthService.Application.Models.ExternalAuth;
using System.Security.Cryptography;
using AuthService.Infrastructure.Data;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using System.Net.Http.Json;
using AuthService.Application.Interfaces;

namespace AuthService.Application.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly AuthDbContext _context;
    private readonly HttpClient _httpClient;

    public AuthenticationService(
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        AuthDbContext context)
    {
        ArgumentNullException.ThrowIfNull(userManager);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(context);
        
        _userManager = userManager;
        _configuration = configuration;
        _context = context;
        _httpClient = new HttpClient();
    }

    public async Task<AuthenticationResponse> RegisterAsync(RegisterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if (existingUser != null)
        {
            throw new InvalidOperationException("User with this email already exists");
        }

        var user = new ApplicationUser
        {
            Email = request.Email,
            UserName = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            PhoneNumber = request.PhoneNumber ?? string.Empty,
            CreatedAt = DateTime.UtcNow.AddHours(2),
            IsActive = true
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed to create user: {errors}");
        }

        return await GenerateAuthenticationResponseAsync(user);
    }

    public async Task<AuthenticationResponse> LoginAsync(LoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            throw new InvalidOperationException("Invalid email or password");
        }

        if (!user.IsActive)
        {
            throw new InvalidOperationException("Account is deactivated");
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!isPasswordValid)
        {
            throw new InvalidOperationException("Invalid email or password");
        }

        user.LastLoginAt = DateTime.UtcNow.AddHours(2);
        await _userManager.UpdateAsync(user);

        return await GenerateAuthenticationResponseAsync(user);
    }

    public async Task<AuthenticationResponse> RefreshTokenAsync(string refreshToken)
    {
        ArgumentNullException.ThrowIfNull(refreshToken);
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtKey = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT key is not configured");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            ValidIssuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT issuer is not configured"),
            ValidAudience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT audience is not configured")
        };

        try
        {
            var principal = tokenHandler.ValidateToken(refreshToken, tokenValidationParameters, out var validatedToken);
            var jwtToken = validatedToken as JwtSecurityToken;
            
            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
            {
                throw new SecurityTokenException("Invalid token");
            }

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                throw new SecurityTokenException("Invalid token");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null || !user.IsActive)
            {
                throw new SecurityTokenException("User not found or inactive");
            }

            return await GenerateAuthenticationResponseAsync(user);
        }
        catch (Exception)
        {
            throw new InvalidOperationException("Invalid refresh token");
        }
    }

    private async Task<AuthenticationResponse> GenerateAuthenticationResponseAsync(ApplicationUser user)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(user.Email);
        
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.GivenName, user.FirstName),
            new(ClaimTypes.Surname, user.LastName)
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var jwtKey = _configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT key is not configured");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var utcNow = DateTime.UtcNow.AddHours(2);

        var issuer = _configuration["Jwt:Issuer"] ?? throw new InvalidOperationException("JWT issuer is not configured");
        var audience = _configuration["Jwt:Audience"] ?? throw new InvalidOperationException("JWT audience is not configured");

        // Generate access token
        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: utcNow.AddHours(3),
            signingCredentials: credentials
        );

        // Generate refresh token as a JWT that expires in 7 days
        var refreshTokenExpiry = utcNow.AddDays(7);
        var refreshToken = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("tokenType", "refresh")
            },
            expires: refreshTokenExpiry,
            signingCredentials: credentials
        );

        return new AuthenticationResponse
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken),
            ExpiresAt = utcNow.AddHours(3)
        };
    }

    public string GetExternalAuthorizationUrl(ExternalAuthRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        
        var provider = request.Provider.ToLower();
        var config = _configuration.GetSection($"ExternalAuth:{request.Provider}");
        if (!config.Exists())
        {
            throw new InvalidOperationException($"Provider {request.Provider} is not configured");
        }

        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        
        var queryParams = new Dictionary<string, string>
        {
            ["client_id"] = config["ClientId"] ?? throw new InvalidOperationException("Client ID is not configured"),
            ["redirect_uri"] = config["RedirectUri"] ?? throw new InvalidOperationException("Redirect URI is not configured"),
            ["state"] = state,
            ["response_type"] = "code"
        };

        var baseUrl = provider switch
        {
            "google" => "https://accounts.google.com/o/oauth2/v2/auth",
            "github" => "https://github.com/login/oauth/authorize",
            _ => throw new InvalidOperationException($"Provider {request.Provider} is not supported")
        };

        if (provider == "google")
        {
            queryParams["scope"] = "openid email profile";
        }
        else if (provider == "github")
        {
            queryParams["scope"] = "user:email";
        }

        var queryString = string.Join("&", queryParams.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
        return $"{baseUrl}?{queryString}";
    }

    public async Task<AuthenticationResponse> HandleExternalAuthCallbackAsync(string provider, ExternalAuthCallback callback)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(callback);
        ArgumentNullException.ThrowIfNull(callback.Code);
        
        if (!string.IsNullOrEmpty(callback.Error))
        {
            throw new InvalidOperationException($"External authentication error: {callback.Error}");
        }

        var config = _configuration.GetSection($"ExternalAuth:{provider}");
        if (!config.Exists())
        {
            throw new InvalidOperationException($"Provider {provider} is not configured");
        }

        var clientId = config["ClientId"] ?? throw new InvalidOperationException("Client ID is not configured");
        var clientSecret = config["ClientSecret"] ?? throw new InvalidOperationException("Client Secret is not configured");
        var redirectUri = config["RedirectUri"] ?? throw new InvalidOperationException("Redirect URI is not configured");

        // Exchange code for tokens
        var tokenEndpoint = provider.ToLower() switch
        {
            "google" => "https://oauth2.googleapis.com/token",
            "github" => "https://github.com/login/oauth/access_token",
            _ => throw new InvalidOperationException($"Provider {provider} is not supported")
        };

        var tokenResponse = await _httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["code"] = callback.Code,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code"
        }));

        if (!tokenResponse.IsSuccessStatusCode)
        {
            throw new InvalidOperationException("Failed to exchange authorization code for tokens");
        }

        // Get user info from provider
        var userInfo = await GetUserInfoFromProviderAsync(provider, await tokenResponse.Content.ReadAsStringAsync());
        
        // Find or create user
        var externalLogin = await _context.ExternalLogins
            .FirstOrDefaultAsync(e => e.Provider == provider && e.ProviderUserId == userInfo.Id);

        ApplicationUser user;
        if (externalLogin == null)
        {
            // Create new user
            user = new ApplicationUser
            {
                Email = userInfo.Email,
                UserName = userInfo.Email,
                FirstName = userInfo.FirstName,
                LastName = userInfo.LastName,
                CreatedAt = DateTime.UtcNow.AddHours(2),
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException("Failed to create user account");
            }

            // Create external login
            externalLogin = new ExternalLogin
            {
                UserId = user.Id,
                Provider = provider,
                ProviderUserId = userInfo.Id,
                CreatedAt = DateTime.UtcNow.AddHours(2),
                User = user
            };
            _context.ExternalLogins.Add(externalLogin);
            await _context.SaveChangesAsync();
        }
        else
        {
            user = await _userManager.FindByIdAsync(externalLogin.UserId);
            if (user == null)
            {
                throw new InvalidOperationException("Associated user account not found");
            }

            externalLogin.LastUsedAt = DateTime.UtcNow.AddHours(2);
            await _context.SaveChangesAsync();
        }

        return await GenerateAuthenticationResponseAsync(user);
    }

    private async Task<(string Id, string Email, string FirstName, string LastName)> GetUserInfoFromProviderAsync(
        string provider, string tokenResponse)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(tokenResponse);
        
        var accessToken = ParseAccessToken(tokenResponse);
        
        if (provider.ToLower() == "google")
        {
            var userInfoResponse = await _httpClient.GetAsync(
                $"https://www.googleapis.com/oauth2/v2/userinfo?access_token={accessToken}");
            if (!userInfoResponse.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("Failed to get user info from Google");
            }

            var googleUser = await userInfoResponse.Content.ReadFromJsonAsync<GoogleUserInfo>();
            if (googleUser == null)
            {
                throw new InvalidOperationException("Failed to parse user info from Google");
            }
            
            // Use email prefix as default name if GivenName is not provided
            var defaultName = googleUser.Email.Split('@')[0];
            return (googleUser.Id, googleUser.Email, 
                   googleUser.GivenName ?? defaultName, 
                   googleUser.FamilyName ?? "");
        }
        else if (provider.ToLower() == "github")
        {
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            
            var userInfoResponse = await _httpClient.GetAsync("https://api.github.com/user");
            if (!userInfoResponse.IsSuccessStatusCode)
            {
                throw new InvalidOperationException("Failed to get user info from GitHub");
            }

            var githubUser = await userInfoResponse.Content.ReadFromJsonAsync<GitHubUserInfo>();
            if (githubUser == null)
            {
                throw new InvalidOperationException("Failed to parse user info from GitHub");
            }
            
            var names = githubUser.Name?.Split(' ', 2) ?? new[] { githubUser.Login, "" };
            return (githubUser.Id, githubUser.Email, names[0], names.Length > 1 ? names[1] : "");
        }

        throw new InvalidOperationException($"Provider {provider} is not supported");
    }

    private string ParseAccessToken(string tokenResponse)
    {
        ArgumentNullException.ThrowIfNull(tokenResponse);
        
        // Parse the token response based on the format (JSON or form-encoded)
        try
        {
            if (tokenResponse.StartsWith("{"))
            {
                var json = JsonSerializer.Deserialize<JsonElement>(tokenResponse);
                var token = json.GetProperty("access_token").GetString();
                if (token == null)
                {
                    throw new InvalidOperationException("Access token not found in response");
                }
                return token;
            }
            else
            {
                var pairs = tokenResponse.Split('&')
                    .Select(pair => pair.Split('='))
                    .Where(split => split.Length == 2)
                    .ToDictionary(split => split[0], split => split[1]);

                if (!pairs.TryGetValue("access_token", out var token))
                {
                    throw new InvalidOperationException("Access token not found in response");
                }
                return token;
            }
        }
        catch (Exception ex) when (ex is not InvalidOperationException)
        {
            throw new InvalidOperationException("Failed to parse access token from response", ex);
        }
    }

    private class GoogleUserInfo
    {
        public required string Id { get; set; }
        public required string Email { get; set; }
        public string? GivenName { get; set; }
        public string? FamilyName { get; set; }
    }

    private class GitHubUserInfo
    {
        public required string Id { get; set; }
        public required string Login { get; set; }
        public string? Name { get; set; }
        public required string Email { get; set; }
    }

    public async Task<bool> LogoutAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user != null)
        {
            // Update security stamp to invalidate existing tokens
            await _userManager.UpdateSecurityStampAsync(user);
            return true;
        }
        return false;
    }
} 