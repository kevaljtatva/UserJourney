namespace UserJourney.WebAPI.Models
{
    public partial class ResetPassword
    {
        public long ResetPasswordId { get; set; }
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
        public int ExpiryTime { get; set; }
        public bool? IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime AddedAt { get; set; }
    }
}
