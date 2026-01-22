using System.ComponentModel.DataAnnotations;

namespace login.Models
{
    public class EditProfileModel
    {
        [Required(ErrorMessage ="Username majburiy")]
        [MaxLength(50, ErrorMessage = "Username 50 ta belgidan oshmasligi kerak")]
        [Display(Name = "Username")]
        public string? Username { get; set; }
        [Required(ErrorMessage = "Email majburiy")]
        [EmailAddress(ErrorMessage = "Noto'g'ri email format")]
        [MaxLength(100, ErrorMessage = "Email 100 ta belgidan oshmasligi kerak")]
        [Display(Name = "Email")]
        public string? Email { get; set; }
    }
}
