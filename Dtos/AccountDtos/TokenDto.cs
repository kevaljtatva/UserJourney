namespace UserJourney.WebAPI.Dtos.AccountDtos
{
    public class TokenDto
    {
        public string Token { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public string SuccessMessage { get; set; } = string.Empty;
    }
}
