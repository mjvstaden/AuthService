using AuthService.Application.Models;

namespace AuthService.Application.Interfaces;

public interface IUserManagementService
{
    /// <summary>
    /// Initiates the password reset process by generating a token and sending it via the NotificationsAPI
    /// </summary>
    Task<PasswordResetResponse> RequestPasswordResetAsync(RequestPasswordResetRequest request);

    /// <summary>
    /// Validates the reset token and updates the user's password
    /// </summary>
    Task<PasswordResetResponse> ResetPasswordAsync(ResetPasswordRequest request);
} 