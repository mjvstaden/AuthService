using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthService.Application.Services;
using AuthService.Domain.Entities;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace AuthService.API.Controllers;

/// <summary>
/// Controller for managing organizations, users, and roles.
/// </summary>
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

    /// <summary>
    /// Creates a new organization.
    /// </summary>
    /// <param name="request">Details of the organization to be created.</param>
    /// <returns>The created organization.</returns>
    [HttpPost]
    public async Task<ActionResult<Organization>> CreateOrganization([FromBody] CreateOrganizationRequest request)
    {
        try
        {
            _logger.LogInformation("Creating organization with name: {Name}", request.Name);
            var organization = await _organizationService.CreateOrganizationAsync(request.Name, request.Description);

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId != null)
            {
                await _organizationService.AddUserToOrganizationAsync(organization.Id, userId);
            }

            return Ok(organization);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating organization");
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Gets details of an organization by its ID.
    /// </summary>
    /// <param name="id">The ID of the organization.</param>
    /// <returns>The organization details.</returns>
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

    /// <summary>
    /// Gets the organizations associated with the current user.
    /// </summary>
    /// <returns>A list of organizations.</returns>
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

    /// <summary>
    /// Adds a user to an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="userId">The ID of the user.</param>
    /// <returns>Status of the operation.</returns>
    [HttpPost("{organizationId}/user/{userId}")]
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

    /// <summary>
    /// Removes a user from an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="userId">The ID of the user.</param>
    /// <returns>Status of the operation.</returns>
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

    /// <summary>
    /// Creates a role within an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="request">Details of the role to be created.</param>
    /// <returns>The created role.</returns>
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

    /// <summary>
    /// Gets all roles within an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <returns>A list of roles.</returns>
    [HttpGet("{organizationId}/roles")]
    public async Task<ActionResult<IEnumerable<OrganizationRole>>> GetOrganizationRoles(string organizationId)
    {
        var roles = await _organizationService.GetOrganizationRolesAsync(organizationId);
        return Ok(roles);
    }

    /// <summary>
    /// Assigns a role to a user within an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="roleId">The ID of the role.</param>
    /// <returns>Status of the operation.</returns>
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

    /// <summary>
    /// Removes a role from a user within an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="roleId">The ID of the role to be removed.</param>
    /// <returns>Status of the operation.</returns>
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

    /// <summary>
    /// Creates a new permission.
    /// </summary>
    /// <param name="request">The permission object to be created.</param>
    /// <returns>The created permission.</returns>
    [HttpPost("permissions")]
    public async Task<ActionResult<Permission>> CreatePermission([FromBody] CreatePermissionRequest request)
    {
        try
        {
            var createdPermission = await _organizationService.CreatePermissionAsync(request.Name, request.Description);
            return CreatedAtAction(nameof(GetPermissionById), new { permissionId = createdPermission.Id }, createdPermission);
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Deletes a permission.
    /// </summary>
    /// <param name="permissionId">The ID of the permission to be deleted.</param>
    /// <returns>Status of the operation.</returns>
    [HttpDelete("permissions/{permissionId}")]
    public async Task<IActionResult> DeletePermission(string permissionId)
    {
        try
        {
            await _organizationService.DeletePermissionAsync(permissionId);
            return NoContent();
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    /// <summary>
    /// Gets a permission by its ID.
    /// </summary>
    /// <param name="permissionId">The ID of the permission.</param>
    /// <returns>The permission object.</returns>
    [HttpGet("permissions/{permissionId}")]
    public async Task<ActionResult<Permission>> GetPermissionById(string permissionId)
    {
        var permission = await _organizationService.GetPermissionByIdAsync(permissionId);
        if (permission == null)
        {
            return NotFound();
        }
        return Ok(permission);
    }

    /// <summary>
    /// Gets the permissions associated with a specific role.
    /// </summary>
    /// <param name="roleId">The ID of the role.</param>
    /// <returns>A list of permissions for the role.</returns>
    [HttpGet("roles/{roleId}/permissions")]
    public async Task<ActionResult<IEnumerable<Permission>>> GetRolePermissions(string roleId)
    {
        var permissions = await _organizationService.GetRolePermissionsAsync(roleId);
        return Ok(permissions);
    }

    /// <summary>
    /// Assigns a permission to a specific role.
    /// </summary>
    /// <param name="roleId">The ID of the role.</param>
    /// <param name="permissionId">The ID of the permission to be assigned.</param>
    /// <returns>Status of the operation.</returns>
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

    /// <summary>
    /// Removes a permission from a specific role.
    /// </summary>
    /// <param name="roleId">The ID of the role.</param>
    /// <param name="permissionId">The ID of the permission to be removed.</param>
    /// <returns>Status of the operation.</returns>
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

    /// <summary>
    /// Checks if a user has a specific permission within an organization.
    /// </summary>
    /// <param name="organizationId">The ID of the organization.</param>
    /// <param name="userId">The ID of the user.</param>
    /// <param name="permissionName">The name of the permission to check.</param>
    /// <returns>True if the user has the permission; otherwise, false.</returns>
    [HttpGet("{organizationId}/users/{userId}/has-permission/{permissionName}")]
    public async Task<ActionResult<bool>> CheckUserPermission(string organizationId, string userId, string permissionName)
    {
        var hasPermission = await _organizationService.UserHasPermissionAsync(organizationId, userId, permissionName);
        return Ok(hasPermission);
    }
}

/// <summary>
/// Request object for creating an organization.
/// </summary>
public class CreateOrganizationRequest
{
    /// <summary>
    /// The name of the organization.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// An optional description of the organization.
    /// </summary>
    public string? Description { get; set; }
}

/// <summary>
/// Request object for creating a role within an organization.
/// </summary>
public class CreateRoleRequest
{
    /// <summary>
    /// The name of the role.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// An optional description of the role.
    /// </summary>
    public string? Description { get; set; }
}

/// <summary>
/// Request object for creating a permission.
/// </summary>
public class CreatePermissionRequest
{
    /// <summary>
    /// The name of the permission.
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// An optional description of the permission.
    /// </summary>
    public string? Description { get; set; }
}