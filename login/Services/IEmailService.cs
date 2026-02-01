namespace login.Services
{
    public interface IEmailService
    {
        Task<bool> SendVerificationEmailAsync(string toEmail, string username, string verificationLink);
        Task<bool> SendPasswordResetEmailAsync(string toEmail, string username, string resetLink);
        Task<bool> SendWelcomeEmailAsync(string toEmail, string username);
        Task<bool> SendEmailAsync(string toEmail, string subject, string body, bool isHtml = false);
    }
}
