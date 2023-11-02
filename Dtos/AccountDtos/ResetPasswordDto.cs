using System.ComponentModel.DataAnnotations;

namespace UserJourney.WebAPI.Dtos.AccountDtos
{
    public class ResetPasswordDto
    {
        [Required(ErrorMessage = "Password is required.")]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[#$^+=!*()@%&]).{8,}$", ErrorMessage = "Please enter strong password.")]
        public string Password { get; set; } = null!;
        [Required(ErrorMessage = "Email is required.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "Code is required.")]
        public string Code { get; set; }
    }
}
