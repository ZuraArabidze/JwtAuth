using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models
{
    public class UpdateUserRequest
    {
        [StringLength(50)]
        public string? Username { get; set; }

        [EmailAddress]
        [StringLength(100)]
        public string? Email { get; set; }

        [StringLength(100, MinimumLength = 6)]
        public string? Password { get; set; }

        public string? CurrentPassword { get; set; }

        public string? Role { get; set; }
    }
}
