using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Models;
using AuthService.Application.Interfaces;
using AuthService.Application.Models.ExternalAuth;
using System.Security.Claims;

namespace AuthService.API.Controllers;

/// <summary>
/// Provides user management-related endpoints, including password reset, 
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class UserManagementController : ControllerBase
{
    private readonly IUserManagementService _userManagementService;
    private readonly ILogger<UserManagementController> _logger;

    public UserManagementController(IUserManagementService userManagementService, ILogger<UserManagementController> logger)
    {
        _userManagementService = userManagementService;
        _logger = logger;
    }

    /// <summary>
    /// Initiates the password reset process by sending a reset link to the user's email
    /// </summary>
    /// <param name="request">The password reset request containing the user's email</param>
    /// <returns>A response indicating whether the reset email was sent</returns>
    [HttpPost("request-password-reset")]
    [ProducesResponseType(typeof(PasswordResetResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RequestPasswordReset([FromBody] RequestPasswordResetRequest request)
    {
        var response = await _userManagementService.RequestPasswordResetAsync(request);
        return Ok(response);
    }

    /// <summary>
    /// Resets the user's password using the provided reset token
    /// </summary>
    /// <param name="request">The request containing the reset token and new password</param>
    /// <returns>A response indicating whether the password was successfully reset</returns>
    [HttpPost("reset-password")]
    [ProducesResponseType(typeof(PasswordResetResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var response = await _userManagementService.ResetPasswordAsync(request);
        if (!response.Success)
        {
            return BadRequest(response);
        }
        return Ok(response);
    }
}