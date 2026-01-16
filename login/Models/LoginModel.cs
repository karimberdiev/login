using System.ComponentModel.DataAnnotations;

namespace login.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Username majburiy")]
        public string Username { get; set; }
        [Required(ErrorMessage = "Password majburiy")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
