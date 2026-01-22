using System.ComponentModel.DataAnnotations;

namespace login.Models
{
    public class ChangePasswordModel
    {
        [Required(ErrorMessage = "Joriy parol majburiy")]
        [DataType(DataType.Password)]
        [Display(Name = "Joriy parol")]
        public string CurrentPassword { get; set; }
        [Required(ErrorMessage = "Yangi parol majburiy")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "Yangi parol kamida {2} va maksimal {1} belgidan iborat bo'lishi kerak.") ]
        [DataType(DataType.Password)]
        [Display(Name = "Yangi parol")]
        public string NewPassword { get; set; }
        [Required(ErrorMessage = "Yangi parolni tasdiqlash majburiy")]
        [DataType(DataType.Password)]
        [Display(Name = "Yangi parolni tasdiqlash")]
        [Compare("NewPassword", ErrorMessage = "Yangi parol va tasdiqlash mos emas.")]
        public string ConfirmNewPassword { get; set; }
    }
}
