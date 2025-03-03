using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : ControllerBase
    {
        [HttpGet]
        [Authorize]
        public IActionResult Get()
        {
            var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
            var username = User.FindFirst(JwtRegisteredClaimNames.Name)?.Value;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new
            {
                message = "This is a secured endpoint for any authenticated user",
                userId,
                username,
                role
            });
        }

        [HttpGet("admin")]
        [Authorize(Policy = "AdminOnly")]
        public IActionResult GetAdmin()
        {
            return Ok(new { message = "This is a secured endpoint for admins only" });
        }

        [HttpGet("user")]
        [Authorize(Policy = "UserOnly")]
        public IActionResult GetUser()
        {
            return Ok(new { message = "This is a secured endpoint for regular users only" });
        }
    }
}
