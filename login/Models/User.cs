using System.ComponentModel.DataAnnotations;

namespace login.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }
        [MaxLength(50)]
        public required string? Username { get; set; }
        [Required]
        [MaxLength(100)]
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        [MaxLength(256)]
        public string? PasswordHash { get; set; }
        [Required]
        [MaxLength(20)]
        public string Role { get; set; } = "User";
        public bool IsEmailConfirmed { get; set; } = false;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastLoginAt { get; set; }
        public bool IsActive { get; set; } = true;
        public virtual ICollection<Refreshtoken>? RefreshTokens { get; set; }

    }
}
