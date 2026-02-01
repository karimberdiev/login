using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using login.Data;
using login.Models;
using login.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BCrypt.Net;

namespace login.Controllers
{
    public class AuthController : Controller
    {
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;

        public AuthController(AuthDbContext context, IConfiguration configuration, IEmailService emailService)
        {
            _context = context;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Dashboard", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (await _context.Users.AnyAsync(u => u.Username == model.Username))
            {
                ModelState.AddModelError("Username", "Bu username allaqachon band");
                return View(model);
            }

            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "Bu email allaqachon ro'yxatdan o'tgan");
                return View(model);
            }

            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.Password),
                Role = "User",
                IsEmailConfirmed = false,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var token = GenerateVerificationToken();
            var verificationToken = new EmailVerificationToken
            {
                UserId = user.Id,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(24)
            };

            _context.EmailVerificationTokens.Add(verificationToken);
            await _context.SaveChangesAsync();

            var verificationLink = Url.Action(
                "VerifyEmail",
                "Auth",
                new { token = token },
                Request.Scheme
            );

            try
            {
                await _emailService.SendVerificationEmailAsync(user.Email, user.Username, verificationLink!);
                TempData["SuccessMessage"] = "Ro'yxatdan o'tish muvaffaqiyatli! Email manzilingizga tasdiqlash linki yuborildi.";
            }
            catch (Exception ex)
            {
                TempData["WarningMessage"] = $"Ro'yxatdan o'tdingiz, lekin email yuborishda xatolik: {ex.Message}";
            }

            return RedirectToAction("Login");
        }

        [HttpGet]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                TempData["ErrorMessage"] = "Noto'g'ri token";
                return RedirectToAction("Login");
            }

            var verificationToken = await _context.EmailVerificationTokens
                .Include(vt => vt.User)
                .FirstOrDefaultAsync(vt => vt.Token == token);

            if (verificationToken == null)
            {
                TempData["ErrorMessage"] = "Token topilmadi";
                return RedirectToAction("Login");
            }

            if (verificationToken.IsExpired)
            {
                TempData["ErrorMessage"] = "Token muddati tugagan. Yangi token so'rang.";
                return RedirectToAction("ResendVerification", new { email = verificationToken.User?.Email });
            }

            if (verificationToken.IsVerified)
            {
                TempData["InfoMessage"] = "Email allaqachon tasdiqlangan";
                return RedirectToAction("Login");
            }

            verificationToken.VerifiedAt = DateTime.UtcNow;
            verificationToken.User!.IsEmailConfirmed = true;
            await _context.SaveChangesAsync();

            try
            {
                await _emailService.SendWelcomeEmailAsync(verificationToken.User.Email, verificationToken.User.Username);
            }
            catch
            {
            }

            TempData["SuccessMessage"] = "Email muvaffaqiyatli tasdiqlandi! Endi login qilishingiz mumkin.";
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult ResendVerification(string? email)
        {
            ViewBag.Email = email;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResendVerificationPost([FromForm] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                TempData["ErrorMessage"] = "Email majburiy";
                return View("ResendVerification");
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                TempData["ErrorMessage"] = "Bu email bilan user topilmadi";
                return View("ResendVerification");
            }

            if (user.IsEmailConfirmed)
            {
                TempData["InfoMessage"] = "Email allaqachon tasdiqlangan";
                return RedirectToAction("Login");
            }

            var oldTokens = await _context.EmailVerificationTokens
                .Where(vt => vt.UserId == user.Id && vt.VerifiedAt == null)
                .ToListAsync();

            _context.EmailVerificationTokens.RemoveRange(oldTokens);

            var token = GenerateVerificationToken();
            var verificationToken = new EmailVerificationToken
            {
                UserId = user.Id,
                Token = token,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddHours(24)
            };

            _context.EmailVerificationTokens.Add(verificationToken);
            await _context.SaveChangesAsync();

            var verificationLink = Url.Action(
                "VerifyEmail",
                "Auth",
                new { token = token },
                Request.Scheme
            );

            try
            {
                await _emailService.SendVerificationEmailAsync(user.Email, user.Username, verificationLink!);
                TempData["SuccessMessage"] = "Tasdiqlash linki qayta yuborildi. Emailingizni tekshiring.";
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"Email yuborishda xatolik: {ex.Message}";
            }

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Dashboard", "Home");
            }
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == model.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                ModelState.AddModelError("", "Login yoki parol noto'g'ri");
                return View(model);
            }

            if (!user.IsActive)
            {
                ModelState.AddModelError("", "Sizning hisobingiz bloklangan");
                return View(model);
            }

            if (!user.IsEmailConfirmed)
            {
                TempData["WarningMessage"] = "Email manzilingiz tasdiqlanmagan. Emailingizni tekshiring yoki yangi link so'rang.";
                return RedirectToAction("ResendVerification", new { email = user.Email });
            }

            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            var accessToken = GenerateAccessToken(user.Username, user.Role);
            var refreshToken = GenerateRefreshToken();
            await SaveRefreshToken(user.Username, refreshToken);

            SetTokenCookie("AccessToken", accessToken, 15);
            SetTokenCookie("RefreshToken", refreshToken, 10080);

            return RedirectToAction("Dashboard", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["RefreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new { message = "Refresh token topilmadi" });
            }

            var storedToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == refreshToken && t.IsActive);

            if (storedToken == null)
            {
                return Unauthorized(new { message = "Refresh token yaroqsiz" });
            }

            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Username == storedToken.UserId);

            if (user == null || !user.IsActive)
            {
                return Unauthorized(new { message = "User topilmadi yoki faol emas" });
            }

            var newAccessToken = GenerateAccessToken(user.Username, user.Role);
            var newRefreshToken = GenerateRefreshToken();

            storedToken.RevokedAt = DateTime.UtcNow;
            storedToken.ReplacedByToken = newRefreshToken;

            await SaveRefreshToken(user.Username, newRefreshToken);
            await _context.SaveChangesAsync();

            SetTokenCookie("AccessToken", newAccessToken, 15);
            SetTokenCookie("RefreshToken", newRefreshToken, 10080);

            return Ok(new { message = "Token yangilandi" });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["RefreshToken"];

            if (!string.IsNullOrEmpty(refreshToken))
            {
                var token = await _context.RefreshTokens
                    .FirstOrDefaultAsync(t => t.Token == refreshToken);

                if (token != null)
                {
                    token.RevokedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                }
            }

            Response.Cookies.Delete("AccessToken");
            Response.Cookies.Delete("RefreshToken");

            return RedirectToAction("Login");
        }

        private string GenerateAccessToken(string username, string role)
        {
            var securityKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, username),
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private string GenerateVerificationToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber).Replace("+", "-").Replace("/", "_");
        }

        private async Task SaveRefreshToken(string userId, string token)
        {
            var refreshToken = new Refreshtoken
            {
                Token = token,
                UserId = userId,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                RevokedAt = null
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();
        }

        private void SetTokenCookie(string name, string value, int expireMinutes)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(expireMinutes)
            };

            Response.Cookies.Append(name, value, cookieOptions);
        }
    }
}
