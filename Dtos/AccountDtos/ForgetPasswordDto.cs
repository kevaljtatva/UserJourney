using System.ComponentModel.DataAnnotations;

namespace UserJourney.WebAPI.Dtos.AccountDtos
{
    public class ForgetPasswordDto
    {
        [Required]
        [DataType(DataType.EmailAddress)]
        public string EmailAddress { get; set; } = string.Empty;
    }
}
