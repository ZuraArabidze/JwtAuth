using JwtAuth.Entities;
using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface ITokenService
    {
        Task<TokenResponse> GenerateTokensAsync(User user);
        Task<TokenResponse> RefreshTokenAsync(string token);
        Task RevokeTokenAsync(string token);
    }
}
