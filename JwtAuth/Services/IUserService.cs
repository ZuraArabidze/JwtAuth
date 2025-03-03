using JwtAuth.Entities;
using JwtAuth.Models;

namespace JwtAuth.Services
{
    public interface IUserService
    {
        Task<User> GetByIdAsync(int id);
        Task<User> GetUserNameAsync(string userName);
        Task<User> GetEmailAsync(string email);
        Task<bool> IsEmailUniqueAsync(string email);
        Task<bool> IsUsernameUniqueAsync(string username);
        Task<User> CreateAsync(RegisterRequest model);
        Task UpdateLastLoginAsync(int userId);
    }
}
