using System.Net.Http.Json;
using AuthService.Application.Models;
using AuthService.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using AuthService.Application.Interfaces;

namespace AuthService.Application.Services;

public class UserManagementService : IUserManagementService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<UserManagementService> _logger;
    private readonly HttpClient _httpClient;

    public UserManagementService(
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        ILogger<UserManagementService> logger,
        HttpClient? httpClient = null)
    {
        _userManager = userManager;
        _configuration = configuration;
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient();
    }

    public async Task<PasswordResetResponse> RequestPasswordResetAsync(RequestPasswordResetRequest request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                _logger.LogWarning("Password reset requested for non-existent email: {Email}", request.Email);
                // Return success to prevent email enumeration attacks
                return new PasswordResetResponse 
                { 
                    Success = true,
                    Message = "If your email is registered, you will receive a password reset link."
                };
            }

            // Generate password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Send notification via NotificationsAPI
            var notificationEndpoint = _configuration["NotificationsAPI:Endpoint"] 
                ?? throw new InvalidOperationException("NotificationsAPI endpoint not configured");

            var notificationRequest = new
            {
                Email = user.Email,
                Subject = "Password Reset Request",
                TemplateId = "password-reset",
                TemplateData = new
                {
                    FirstName = user.FirstName,
                    ResetLink = $"{_configuration["FrontendUrl"]}/reset-password?email={Uri.EscapeDataString(user.Email)}&token={Uri.EscapeDataString(token)}"
                }
            };

            var response = await _httpClient.PostAsJsonAsync(notificationEndpoint, notificationRequest);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to send password reset notification. Status: {StatusCode}", response.StatusCode);
                throw new InvalidOperationException("Failed to send password reset notification");
            }

            return new PasswordResetResponse 
            { 
                Success = true,
                Message = "Password reset instructions have been sent to your email."
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing password reset request for {Email}", request.Email);
            return new PasswordResetResponse 
            { 
                Success = false,
                Message = "An error occurred while processing your request."
            };
        }
    }

    public async Task<PasswordResetResponse> ResetPasswordAsync(ResetPasswordRequest request)
    {
        try
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null)
            {
                return new PasswordResetResponse 
                { 
                    Success = false,
                    Message = "Invalid request."
                };
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Password reset failed for {Email}. Errors: {Errors}", request.Email, errors);
                
                return new PasswordResetResponse 
                { 
                    Success = false,
                    Message = "Failed to reset password. Please try again."
                };
            }

            _logger.LogInformation("Password reset successful for {Email}", request.Email);
            return new PasswordResetResponse 
            { 
                Success = true,
                Message = "Your password has been reset successfully."
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resetting password for {Email}", request.Email);
            return new PasswordResetResponse 
            { 
                Success = false,
                Message = "An error occurred while resetting your password."
            };
        }
    }
}