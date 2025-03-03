using JwtAuth.Data;
using JwtAuth.Entities;
using JwtAuth.Configuration;
using JwtAuth.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Services
{
    public class TokenService : ITokenService
    {
        private readonly ApplicationDbContext _context;
        private readonly IUserService _userService;
        private readonly JwtSettings _jwtSettings;

        public TokenService(ApplicationDbContext context, IUserService userService, IOptions<JwtSettings> jwtSettings)
        {
            _context = context;
            _userService = userService;
            _jwtSettings = jwtSettings.Value;
        }

        private RSA GetPrivateKey()
        {
            string privateKeyContent = File.ReadAllText("private.pem");
            RSA privateKey = RSA.Create();
            privateKey.ImportFromPem(privateKeyContent.ToCharArray());
            return privateKey;
        }

        public async Task<TokenResponse> GenerateTokensAsync(User user)
        {
            var privateKey = GetPrivateKey();

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            };

            var credentials = new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryInMinutes),
                signingCredentials: credentials);

            var accessToken = new JwtSecurityTokenHandler().WriteToken(token);

            var refreshToken = GenerateRefreshToken();
            refreshToken.UserId = user.Id;
            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            await _userService.UpdateLastLoginAsync(user.Id);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                ExpiresIn = _jwtSettings.ExpiryInMinutes * 60
            };
        }

        public async Task<TokenResponse> RefreshTokenAsync(string token)
        {
            var refreshToken = await _context.RefreshTokens
                .Include(r => r.User)
                .SingleOrDefaultAsync(r => r.Token == token);

            if (refreshToken == null || !refreshToken.IsActive)
            {
                throw new SecurityTokenException("Invalid token");
            }

            var newRefreshToken = GenerateRefreshToken();
            newRefreshToken.UserId = refreshToken.UserId;

            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            refreshToken.ReasonRevoked = "Refresh token rotation";

            _context.RefreshTokens.Add(newRefreshToken);
            _context.RefreshTokens.Update(refreshToken);
            await _context.SaveChangesAsync();

            var user = refreshToken.User;

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
            };

            var privateKey = GetPrivateKey();
            var credentials = new SigningCredentials(new RsaSecurityKey(privateKey), SecurityAlgorithms.RsaSha256);

            var jwtToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.ExpiryInMinutes),
                signingCredentials: credentials);

            var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            return new TokenResponse
            {
                AccessToken = accessToken,
                RefreshToken = newRefreshToken.Token,
                ExpiresIn = _jwtSettings.ExpiryInMinutes * 60
            };
        }

        public async Task RevokeTokenAsync(string token)
        {
            var refreshToken = await _context.RefreshTokens.SingleOrDefaultAsync(r => r.Token == token);

            if (refreshToken == null)
            {
                throw new SecurityTokenException("Token not found");
            }

            if (!refreshToken.IsActive)
            {
                throw new SecurityTokenException("Token already revoked or expired");
            }

            refreshToken.RevokedAt = DateTime.UtcNow;
            refreshToken.ReasonRevoked = "Revoked by user";

            await _context.SaveChangesAsync();
        }

        private RefreshToken GenerateRefreshToken()
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(_jwtSettings.RefreshExpiryInDays),
                CreatedAt = DateTime.UtcNow
            };
        }
    }
}
