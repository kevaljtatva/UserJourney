namespace UserJourney.WebAPI.Const
{
    public static class SystemMessages
    {
        public const string EmailExists = "The email address you have entered is already registered. Please try with a different email address.";
        public const string RegisterSuccess = "You have successfully completed the registration.";
        public const string EmailPassNotMatch = "Invalid credentials!";
        public const string LoginSuccess = "You have logged in successfully.";
        public const string InvalidEmail = "Invalid email address!";
        public const string Subject = "Forgot Password";
        public const string Body = "Please find the password reset link.";
        public const string EmailSentSuccess = "Password reset link has been sent to your email address.";
        public const string LinkExpired = "Password reset link has expired.";
        public const string PassUpdateSuccess = "Password updated successfully.";
        public const string PassUpdateFailed = "Failed to reset the password.";
        public const string OldPassNotMatch = "Incorrect old password!.";
        public const string OldAndNewPassSame = "Please enter a different password than the previous one.";
        public const string EmailNotExists = "The email address does not exists in our system.";
    }
}
