using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models
{
    public class RefreshTokenRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
