using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Models
{
    public class RevokeTokenRequest
    {
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
}
