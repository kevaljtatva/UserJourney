using System.ComponentModel.DataAnnotations;

namespace UserJourney.WebAPI.Dtos.AccountDtos
{
    public class ResetPasswordFromLoginDto
    {
        [Required]
        public string OldPassword { get; set; } = string.Empty;
        [Required]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[#$^+=!*()@%&]).{8,}$", ErrorMessage = "Please enter strong password.")]
        public string NewPassword { get; set; } = string.Empty;
        [Required]
        [Compare("NewPassword")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
