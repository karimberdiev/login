using System.ComponentModel.DataAnnotations;

namespace login.Models
{
    public class RegisterModel
    {
        [Required(ErrorMessage = "Username majburiy")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username 3 dan 50 gacha belgidan iborat bo'lishi kerak")]
        [RegularExpression("^[a-zA-Z0-9_]+$", ErrorMessage = "Username faqat harflar, raqamlar va pastki chiziqlarni o'z ichiga olishi mumkin")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Email majburiy")]
        [EmailAddress(ErrorMessage = "Noto'g'ri email format")]
        [MaxLength(100, ErrorMessage = "Email 100 belgidan oshmasligi kerak")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Parol majburiy")]
        [DataType(DataType.Password)]
        [StringLength(20, MinimumLength = 6, ErrorMessage = "Parol kamida 6 belgidan iborat bo'lishi kerak")]
        public string Password { get; set; }
        [Required(ErrorMessage = "Parolni tasdiqlash majburiy")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Parollar mos kelmadi")]
        public string ConfirmPassword { get; set; }
    }
}
