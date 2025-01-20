using System.Net;
using System.Net.Http.Json;
using AuthService.Application.Models;
using AuthService.Application.Models.ExternalAuth;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using Xunit.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using AuthService.API.Controllers;
using AuthService.Application.Services;
using AuthService.Domain.Entities;
using Microsoft.Extensions.Configuration;
using AuthService.Infrastructure.Data;
using Microsoft.Extensions.Options;
using IAuthService = AuthService.Application.Services.IAuthenticationService;
using AuthenticationSvc = AuthService.Application.Services.AuthenticationService;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AuthService.Tests;

public class AuthControllerTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly TestWebApplicationFactory _factory;
    private readonly HttpClient _client;
    private readonly ITestOutputHelper _output;

    public AuthControllerTests(
        TestWebApplicationFactory factory,
        ITestOutputHelper output)
    {
        _factory = factory;
        _client = factory.CreateClient();
        _output = output;
    }

    [Fact]
    public async Task Register_WithValidData_ShouldReturnSuccess()
    {
        // Arrange
        var request = new RegisterRequest
        {
            Email = "test@example.com",
            Password = "Test123!@#",
            FirstName = "Test",
            LastName = "User",
            PhoneNumber = "1234567890"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", request);
        var content = await response.Content.ReadFromJsonAsync<AuthenticationResponse>();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        content.Should().NotBeNull();
        content!.Token.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Register_WithExistingEmail_ShouldReturnBadRequest()
    {
        // Arrange
        var request = new RegisterRequest
        {
            Email = "existing@example.com",
            Password = "Test123!@#",
            FirstName = "Test",
            LastName = "User"
        };

        // Register first time
        await _client.PostAsJsonAsync("/api/auth/register", request);

        // Act - Register second time with same email
        var response = await _client.PostAsJsonAsync("/api/auth/register", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Login_WithValidCredentials_ShouldReturnSuccess()
    {
        // Arrange
        var email = "login.test@example.com";
        var password = "Test123!@#";

        // Register a user first
        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest
        {
            Email = email,
            Password = password,
            FirstName = "Test",
            LastName = "User"
        });

        var loginRequest = new LoginRequest
        {
            Email = email,
            Password = password
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        var content = await response.Content.ReadFromJsonAsync<AuthenticationResponse>();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        content.Should().NotBeNull();
        content!.Token.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task Login_WithInvalidCredentials_ShouldReturnBadRequest()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Email = "nonexistent@example.com",
            Password = "WrongPassword123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task RefreshToken_WithValidToken_ShouldReturnNewTokens()
    {
        // Arrange
        // First, register and login to get initial tokens
        var email = "refresh.test@example.com";
        var password = "Test123!@#";

        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest
        {
            Email = email,
            Password = password,
            FirstName = "Test",
            LastName = "User"
        });

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Email = email,
            Password = password
        });

        var loginContent = await loginResponse.Content.ReadFromJsonAsync<AuthenticationResponse>();
        var refreshRequest = new RefreshTokenRequest { RefreshToken = loginContent!.RefreshToken };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/refresh-token", refreshRequest);
        var content = await response.Content.ReadFromJsonAsync<AuthenticationResponse>();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        content.Should().NotBeNull();
        content!.Token.Should().NotBeNullOrEmpty();
        content.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RefreshToken_WithInvalidToken_ShouldReturnBadRequest()
    {
        // Arrange
        var refreshRequest = new RefreshTokenRequest { RefreshToken = "invalid-token" };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/refresh-token", refreshRequest);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ExternalLogin_WithValidProvider_ShouldReturnAuthorizationUrl()
    {
        // Arrange
        var request = new ExternalAuthRequest
        {
            Provider = "Google",
            ReturnUrl = "https://localhost:5001"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/external-login", request);
        var content = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            _output.WriteLine($"Error: {content?["message"] ?? "No error message"}");
        }
        content.Should().NotBeNull();
        content!["url"].Should().NotBeNullOrEmpty();
        content["url"].Should().Contain("accounts.google.com");
    }

    [Fact]
    public async Task ExternalLogin_WithInvalidProvider_ShouldReturnBadRequest()
    {
        // Arrange
        var request = new ExternalAuthRequest
        {
            Provider = "InvalidProvider",
            ReturnUrl = "https://localhost:5001"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/external-login", request);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Logout_WithValidToken_ShouldReturnSuccess()
    {
        // Arrange
        var userId = "test-user-id";
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        var authServiceMock = new Mock<IAuthService>();
        authServiceMock.Setup(x => x.LogoutAsync(userId))
            .ReturnsAsync(true);

        var controller = new AuthController(authServiceMock.Object);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            }
        };

        // Act
        var result = await controller.Logout();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<LogoutResponse>(okResult.Value);
        Assert.Equal("Logged out successfully", response.Message);
        authServiceMock.Verify(x => x.LogoutAsync(userId), Times.Once);
    }

    [Fact]
    public async Task Logout_WithNoToken_ShouldReturnSuccess()
    {
        // Arrange
        var authServiceMock = new Mock<IAuthService>();
        var controller = new AuthController(authServiceMock.Object);
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity())
            }
        };

        // Act
        var result = await controller.Logout();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<LogoutResponse>(okResult.Value);
        Assert.Equal("Logged out successfully", response.Message);
        authServiceMock.Verify(x => x.LogoutAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task LogoutAsync_WithValidUserId_ShouldUpdateSecurityStamp()
    {
        // Arrange
        var userId = "test-user-id";
        var user = new ApplicationUser 
        { 
            Id = userId,
            FirstName = "Test",
            LastName = "User",
            CreatedAt = DateTime.UtcNow,
            Email = "test@example.com",
            UserName = "test@example.com",
            IsActive = true
        };
        
        var userStore = Mock.Of<IUserStore<ApplicationUser>>();
        var optionsAccessor = Mock.Of<IOptions<IdentityOptions>>();
        var passwordHasher = Mock.Of<IPasswordHasher<ApplicationUser>>();
        var userValidators = new[] { Mock.Of<IUserValidator<ApplicationUser>>() };
        var passwordValidators = new[] { Mock.Of<IPasswordValidator<ApplicationUser>>() };
        var keyNormalizer = Mock.Of<ILookupNormalizer>();
        var errors = Mock.Of<IdentityErrorDescriber>();
        var services = Mock.Of<IServiceProvider>();
        var logger = Mock.Of<ILogger<UserManager<ApplicationUser>>>();

        var userManagerMock = new Mock<UserManager<ApplicationUser>>(
            userStore, optionsAccessor, passwordHasher, userValidators,
            passwordValidators, keyNormalizer, errors, services, logger);
        
        userManagerMock.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(user);
        userManagerMock.Setup(x => x.UpdateSecurityStampAsync(user))
            .ReturnsAsync(IdentityResult.Success);

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
        var dbContext = new AuthDbContext(options);

        var service = new AuthenticationSvc(
            userManagerMock.Object,
            Mock.Of<IConfiguration>(),
            dbContext);

        // Act
        var result = await service.LogoutAsync(userId);

        // Assert
        Assert.True(result);
        userManagerMock.Verify(x => x.FindByIdAsync(userId), Times.Once);
        userManagerMock.Verify(x => x.UpdateSecurityStampAsync(user), Times.Once);
    }

    [Fact]
    public async Task LogoutAsync_WithInvalidUserId_ShouldReturnFalse()
    {
        // Arrange
        var userId = "invalid-user-id";
        
        var userStore = Mock.Of<IUserStore<ApplicationUser>>();
        var optionsAccessor = Mock.Of<IOptions<IdentityOptions>>();
        var passwordHasher = Mock.Of<IPasswordHasher<ApplicationUser>>();
        var userValidators = new[] { Mock.Of<IUserValidator<ApplicationUser>>() };
        var passwordValidators = new[] { Mock.Of<IPasswordValidator<ApplicationUser>>() };
        var keyNormalizer = Mock.Of<ILookupNormalizer>();
        var errors = Mock.Of<IdentityErrorDescriber>();
        var services = Mock.Of<IServiceProvider>();
        var logger = Mock.Of<ILogger<UserManager<ApplicationUser>>>();

        var userManagerMock = new Mock<UserManager<ApplicationUser>>(
            userStore, optionsAccessor, passwordHasher, userValidators,
            passwordValidators, keyNormalizer, errors, services, logger);
        
        userManagerMock.Setup(x => x.FindByIdAsync(userId))
            .ReturnsAsync(() => null);

        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: "TestDb")
            .Options;
        var dbContext = new AuthDbContext(options);

        var service = new AuthenticationSvc(
            userManagerMock.Object,
            Mock.Of<IConfiguration>(),
            dbContext);

        // Act
        var result = await service.LogoutAsync(userId);

        // Assert
        Assert.False(result);
        userManagerMock.Verify(x => x.FindByIdAsync(userId), Times.Once);
        userManagerMock.Verify(x => x.UpdateSecurityStampAsync(It.IsAny<ApplicationUser>()), Times.Never);
    }
} 