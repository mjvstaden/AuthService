using AuthService.Application.Models;
using AuthService.Application.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Models.ExternalAuth;
using System.Security.Claims;

namespace AuthService.API.Controllers;

/// <summary>
/// Provides authentication-related endpoints, including registration, login, token management, and external authentication.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authService;

    /// <summary>
    /// Initializes a new instance of the <see cref="AuthController"/> class.
    /// </summary>
    /// <param name="authService">Service for handling authentication operations.</param>
    public AuthController(IAuthenticationService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Registers a new user.
    /// </summary>
    /// <param name="request">The registration request containing user details.</param>
    /// <returns>An <see cref="AuthenticationResponse"/> containing authentication tokens if successful.</returns>
    /// <response code="200">Registration successful.</response>
    /// <response code="400">Invalid input or registration failed.</response>
    [HttpPost("register")]
    [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        try
        {
            var response = await _authService.RegisterAsync(request);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Logs in an existing user.
    /// </summary>
    /// <param name="request">The login request containing user credentials.</param>
    /// <returns>An <see cref="AuthenticationResponse"/> containing authentication tokens if successful.</returns>
    /// <response code="200">Login successful.</response>
    /// <response code="400">Invalid credentials or login failed.</response>
    [HttpPost("login")]
    [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        try
        {
            var response = await _authService.LoginAsync(request);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Refreshes the authentication token.
    /// </summary>
    /// <param name="request">The request containing the refresh token.</param>
    /// <returns>An <see cref="AuthenticationResponse"/> containing new authentication tokens if successful.</returns>
    /// <response code="200">Token refreshed successfully.</response>
    /// <response code="400">Invalid refresh token or refresh failed.</response>
    [HttpPost("refresh-token")]
    [ProducesResponseType(typeof(AuthenticationResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequest request)
    {
        try
        {
            var response = await _authService.RefreshTokenAsync(request.RefreshToken);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Logs out the current user.
    /// </summary>
    /// <returns>A confirmation message indicating the user has been logged out.</returns>
    /// <response code="200">Logout successful.</response>
    [HttpPost("logout")]
    [Authorize]
    [ProducesResponseType(typeof(LogoutResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId != null)
        {
            var user = await _authService.LogoutAsync(userId);
        }
        return Ok(new LogoutResponse { Message = "Logged out successfully" });
    }

    /// <summary>
    /// Initiates an external login process.
    /// </summary>
    /// <param name="request">The request containing external authentication details.</param>
    /// <returns>A URL for the external authentication process.</returns>
    /// <response code="200">External login URL returned successfully.</response>
    /// <response code="400">Invalid request or external login failed.</response>
    [HttpPost("external-login")]
    public IActionResult ExternalLogin([FromBody] ExternalAuthRequest request)
    {
        try
        {
            var authorizationUrl = _authService.GetExternalAuthorizationUrl(request);
            return Ok(new { url = authorizationUrl });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Handles the callback from an external login provider.
    /// </summary>
    /// <param name="provider">The external authentication provider.</param>
    /// <param name="code">The authorization code from the provider.</param>
    /// <param name="state">The state parameter from the provider.</param>
    /// <param name="error">Any error returned by the provider.</param>
    /// <returns>An <see cref="AuthenticationResponse"/> containing authentication tokens if successful.</returns>
    /// <response code="200">External authentication successful.</response>
    /// <response code="400">External authentication failed.</response>
    [HttpGet("external-callback/{provider}")]
    public async Task<IActionResult> ExternalCallback(
        [FromRoute] string provider,
        [FromQuery] string? code = null,
        [FromQuery] string? state = null,
        [FromQuery] string? error = null)
    {
        try
        {
            var callback = new ExternalAuthCallback
            {
                Code = code,
                State = state,
                Error = error
            };

            var response = await _authService.HandleExternalAuthCallbackAsync(provider, callback);
            return Ok(response);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}