using JwtAuth.Models;
using JwtAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ITokenService _tokenService;

        public AuthController(IUserService userService, ITokenService tokenService)
        {
            _userService = userService;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (!await _userService.IsUsernameUniqueAsync(request.UserName))
            {
                return BadRequest(new { message = "Username already exists" });
            }

            if (!await _userService.IsEmailUniqueAsync(request.Email))
            {
                return BadRequest(new { message = "Email already exists" });
            }

            var user = await _userService.CreateAsync(request);

            var tokenResponse = await _tokenService.GenerateTokensAsync(user);

            return Ok(new
            {
                message = "Registration successful",
                userId = user.Id,
                username = user.UserName,
                email = user.Email,
                role = user.Role,
                tokens = tokenResponse
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _userService.GetUserNameAsync(request.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
            {
                return Unauthorized(new { message = "Invalid username or password" });
            }

            var tokenResponse = await _tokenService.GenerateTokensAsync(user);

            return Ok(tokenResponse);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            try
            {
                var tokenResponse = await _tokenService.RefreshTokenAsync(request.RefreshToken);
                return Ok(tokenResponse);
            }
            catch (SecurityTokenException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
        }

        [HttpPost("revoke-token")]
        [Authorize]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
        {
            try
            {
                await _tokenService.RevokeTokenAsync(request.RefreshToken);
                return Ok(new { message = "Token revoked" });
            }
            catch (SecurityTokenException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}
