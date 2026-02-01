using System.Net;
using System.Net.Mail;

namespace login.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<bool> SendVerificationEmailAsync(string toEmail, string username, string verificationLink)
        {
            var subject = "Email Manzilingizni Tasdiqlang";

            var body = $@"
<html>
<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <h2>Salom {username},</h2>
    <p>Login System tizimiga xush kelibsiz!</p>
    <p>Email manzilingizni tasdiqlash uchun quyidagi linkni bosing:</p>
    <p><a href='{verificationLink}' style='color: #007bff;'>{verificationLink}</a></p>
    <p><strong>Bu link 24 soat ichida amal qiladi.</strong></p>
    <p>Agar siz bu hisobni yaratmagan bo'lsangiz, bu emailni e'tiborsiz qoldiring.</p>
    <hr style='border: 1px solid #eee;'>
    <p style='color: #666; font-size: 12px;'>Hurmat bilan, Login System Jamoasi</p>
</body>
</html>";

            return await SendEmailAsync(toEmail, subject, body, isHtml: true);
        }

        public async Task<bool> SendPasswordResetEmailAsync(string toEmail, string username, string resetLink)
        {
            var subject = "Parolni Tiklash";

            var body = $@"
<html>
<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <h2>Salom {username},</h2>
    <p>Parolni tiklash so'rovi qabul qilindi.</p>
    <p>Yangi parol o'rnatish uchun quyidagi linkni bosing:</p>
    <p><a href='{resetLink}' style='color: #007bff;'>{resetLink}</a></p>
    <p><strong>Bu link 1 soat ichida amal qiladi.</strong></p>
    <p>Agar siz bu so'rovni yubormagan bo'lsangiz, bu emailni e'tiborsiz qoldiring.</p>
    <hr style='border: 1px solid #eee;'>
    <p style='color: #666; font-size: 12px;'>Hurmat bilan, Login System Jamoasi</p>
</body>
</html>";

            return await SendEmailAsync(toEmail, subject, body, isHtml: true);
        }

        public async Task<bool> SendWelcomeEmailAsync(string toEmail, string username)
        {
            var subject = "Xush Kelibsiz!";

            var body = $@"
<html>
<body style='font-family: Arial, sans-serif; line-height: 1.6; color: #333;'>
    <h2>Tabriklaymiz {username}!</h2>
    <p>Emailingiz muvaffaqiyatli tasdiqlandi!</p>
    <p>Endi siz Login System tizimidan to'liq foydalanishingiz mumkin.</p>
    <h3>Keyingi qadamlar:</h3>
    <ul>
        <li>Profilingizni to'ldiring</li>
        <li>Xavfsiz parol o'rnating</li>
        <li>Tizim imkoniyatlari bilan tanishing</li>
    </ul>
    <p>Savollaringiz bo'lsa, biz doim yordam berishga tayyormiz.</p>
    <hr style='border: 1px solid #eee;'>
    <p style='color: #666; font-size: 12px;'>Hurmat bilan, Login System Jamoasi</p>
</body>
</html>";

            return await SendEmailAsync(toEmail, subject, body, isHtml: true);
        }

        public async Task<bool> SendEmailAsync(string toEmail, string subject, string body, bool isHtml = false)
        {
            try
            {
                var smtpHost = _configuration["Email:SmtpHost"];
                var smtpPort = int.Parse(_configuration["Email:SmtpPort"] ?? "587");
                var smtpUsername = _configuration["Email:SmtpUsername"];
                var smtpPassword = _configuration["Email:SmtpPassword"];
                var fromEmail = _configuration["Email:FromEmail"] ?? smtpUsername;
                var fromName = _configuration["Email:FromName"] ?? "Login System";

                if (string.IsNullOrEmpty(smtpHost) ||
                    string.IsNullOrEmpty(smtpUsername) ||
                    string.IsNullOrEmpty(smtpPassword))
                {
                    _logger.LogError("Email konfiguratsiyasi to'liq emas");
                    return false;
                }

                using var smtpClient = new SmtpClient(smtpHost, smtpPort)
                {
                    EnableSsl = true,
                    Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                    Timeout = 30000,
                    DeliveryMethod = SmtpDeliveryMethod.Network
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(fromEmail, fromName),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = isHtml,
                    Priority = MailPriority.Normal
                };

                mailMessage.To.Add(toEmail);

                await smtpClient.SendMailAsync(mailMessage);

                _logger.LogInformation($"Email yuborildi: To={toEmail}, Subject={subject}");
                return true;
            }
            catch (SmtpException ex)
            {
                _logger.LogError(ex, $"SMTP xatosi: StatusCode={ex.StatusCode}, Message={ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Email yuborishda xatolik: {ex.Message}");
                return false;
            }
        }
    }
}
