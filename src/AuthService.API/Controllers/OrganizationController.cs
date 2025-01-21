using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Services;
using AuthService.Domain.Entities;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace AuthService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class OrganizationController : ControllerBase
{
    private readonly IOrganizationService _organizationService;
    private readonly ILogger<OrganizationController> _logger;

    public OrganizationController(IOrganizationService organizationService, ILogger<OrganizationController> logger)
    {
        _organizationService = organizationService;
        _logger = logger;
    }

    [HttpPost]
    public async Task<ActionResult<Organization>> CreateOrganization([FromBody] CreateOrganizationRequest request)
    {
        try
        {
            _logger.LogInformation("Creating organization with name: {Name}", request.Name);
            var organization = await _organizationService.CreateOrganizationAsync(request.Name, request.Description);
            
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            _logger.LogInformation("User ID from claims: {UserId}", userId);
            
            if (userId != null)
            {
                _logger.LogInformation("Adding user {UserId} to organization {OrganizationId}", userId, organization.Id);
                await _organizationService.AddUserToOrganizationAsync(organization.Id, userId);
            }
            else
            {
                _logger.LogWarning("No user ID found in claims");
            }

            _logger.LogInformation("Organization created successfully: {OrganizationId}", organization.Id);
            return Ok(organization);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating organization");
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Organization>> GetOrganization(string id)
    {
        var organization = await _organizationService.GetOrganizationByIdAsync(id);
        if (organization == null)
        {
            return NotFound();
        }

        return Ok(organization);
    }

    [HttpGet("user")]
    public async Task<ActionResult<IEnumerable<Organization>>> GetUserOrganizations()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (userId == null)
        {
            return BadRequest(new { message = "User ID not found" });
        }

        var organizations = await _organizationService.GetUserOrganizationsAsync(userId);
        return Ok(organizations);
    }

    [HttpPost("{organizationId}/users/{userId}")]
    public async Task<IActionResult> AddUserToOrganization(string organizationId, string userId)
    {
        try
        {
            await _organizationService.AddUserToOrganizationAsync(organizationId, userId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpDelete("{organizationId}/users/{userId}")]
    public async Task<IActionResult> RemoveUserFromOrganization(string organizationId, string userId)
    {
        try
        {
            await _organizationService.RemoveUserFromOrganizationAsync(organizationId, userId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("{organizationId}/roles")]
    public async Task<ActionResult<OrganizationRole>> CreateRole(string organizationId, [FromBody] CreateRoleRequest request)
    {
        try
        {
            var role = await _organizationService.CreateRoleAsync(organizationId, request.Name, request.Description);
            return Ok(role);
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("{organizationId}/roles")]
    public async Task<ActionResult<IEnumerable<OrganizationRole>>> GetOrganizationRoles(string organizationId)
    {
        var roles = await _organizationService.GetOrganizationRolesAsync(organizationId);
        return Ok(roles);
    }

    [HttpPost("{organizationId}/users/{userId}/roles/{roleId}")]
    public async Task<IActionResult> AssignRoleToUser(string organizationId, string userId, string roleId)
    {
        try
        {
            await _organizationService.AssignRoleToUserAsync(organizationId, userId, roleId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpDelete("{organizationId}/users/{userId}/roles/{roleId}")]
    public async Task<IActionResult> RemoveRoleFromUser(string organizationId, string userId, string roleId)
    {
        try
        {
            await _organizationService.RemoveRoleFromUserAsync(organizationId, userId, roleId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("roles/{roleId}/permissions")]
    public async Task<ActionResult<IEnumerable<Permission>>> GetRolePermissions(string roleId)
    {
        var permissions = await _organizationService.GetRolePermissionsAsync(roleId);
        return Ok(permissions);
    }

    [HttpPost("roles/{roleId}/permissions/{permissionId}")]
    public async Task<IActionResult> AssignPermissionToRole(string roleId, string permissionId)
    {
        try
        {
            await _organizationService.AssignPermissionToRoleAsync(roleId, permissionId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpDelete("roles/{roleId}/permissions/{permissionId}")]
    public async Task<IActionResult> RemovePermissionFromRole(string roleId, string permissionId)
    {
        try
        {
            await _organizationService.RemovePermissionFromRoleAsync(roleId, permissionId);
            return Ok();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("{organizationId}/users/{userId}/has-permission/{permissionName}")]
    public async Task<ActionResult<bool>> CheckUserPermission(string organizationId, string userId, string permissionName)
    {
        var hasPermission = await _organizationService.UserHasPermissionAsync(organizationId, userId, permissionName);
        return Ok(hasPermission);
    }
}

public class CreateOrganizationRequest
{
    public required string Name { get; set; }
    public string? Description { get; set; }
}

public class CreateRoleRequest
{
    public required string Name { get; set; }
    public string? Description { get; set; }
} 