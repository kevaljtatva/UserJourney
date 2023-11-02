using System.ComponentModel.DataAnnotations;

namespace UserJourney.WebAPI.Dtos.AccountDtos
{
    public class RegisterDto
    {
        [Required(ErrorMessage ="User Name can not be null.")]
        public string UserName { get; set; } = string.Empty;
        [Required(ErrorMessage ="Email address is required.")]
        [DataType(DataType.EmailAddress)]
        [RegularExpression(@"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}", ErrorMessage = "Please enter correct email")]
        public string Email { get; set; } = string.Empty;
        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[#$^+=!*()@%&]).{8,}$", ErrorMessage ="Please enter strong password.")]
        public string Password { get; set; } = string.Empty;

    }
}
