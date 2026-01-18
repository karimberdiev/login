using login.Data;
using login.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace login.Controllers
{
    public class AuthController : Controller
    {
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;
        public AuthController(AuthDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }
        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
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
            if(await _context.Users.AnyAsync(u => u.Username == model.Username))
            {
                ModelState.AddModelError("Username", "Bu foydalanuvchi nomi allaqachon mavjud");
                return View(model);
            }
            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "Bu email allaqachon mavjud");
                return View(model);
            }
            User user = new User
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

            TempData["SuccessMessage"] = "Ro'yxatdan o'tish muvaffaqiyatli amalga oshirildi. Iltimos, tizimga kiring.";
            return RedirectToAction("Login", "Auth");
        }
        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Dashboard", "Home");
            }
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if(!ModelState.IsValid) {
                return View(model);
            }
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                ModelState.AddModelError(string.Empty, "Noto'g'ri foydalanuvchi nomi yoki parol");
                return View(model);
            }
            if(!user.IsActive)
            {
                ModelState.AddModelError(string.Empty, "Foydalanuvchi hisobingiz faol emas. Iltimos, administrator bilan bog'laning.");
                return View(model);
            }
            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            var accessToken = GenerateAccessToken(user.Username, user.Role);
            var refreshToken = GenerateRefreshToken();
            await SaveRefreshToken(user.Username, refreshToken);
            SetTokenCookies("AccessToken", accessToken, 1);
            SetTokenCookies("RefreshToken", refreshToken, 7 * 24 * 60);
            return RedirectToAction("Dashboard", "Home");

        }
        [HttpPost]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["RefreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
            {
                return Unauthorized(new {message = "Refresh token topilmadi"});
            }
            var storedToken = _context.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);
            if (storedToken == null || !storedToken.IsActive)
            {
                return Unauthorized(new { message = "Noto'g'ri yoki muddati o'tgan refresh token" });
            }
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == storedToken.UserId);
            if (user == null || !user.IsActive)
            {
                return Unauthorized(new { message = "Foydalanuvchi topilmadi yoki faol emas" });
            }
            var newAccessToken = GenerateAccessToken(storedToken.UserId, user.Role);
            var newRefreshToken = GenerateRefreshToken();
            storedToken.RevokedAt = DateTime.UtcNow;
            storedToken.ReplacedByToken = newRefreshToken;
            await SaveRefreshToken(storedToken.UserId, newRefreshToken);
            await _context.SaveChangesAsync();
            SetTokenCookies("AccessToken", newAccessToken, 1);
            SetTokenCookies("RefreshToken", newRefreshToken, 7 * 24 * 60);
            return Ok(new { message = "Tokenlar muvaffaqiyatli yangilandi" });
        }
        public async Task<IActionResult> Logout()
        {
            var refreshToken = Request.Cookies["RefreshToken"];
            if (!string.IsNullOrEmpty(refreshToken))
            {
                var storedToken = _context.RefreshTokens.FirstOrDefault(rt => rt.Token == refreshToken);
                if (storedToken != null && storedToken.IsActive)
                {
                    storedToken.RevokedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                }
            }
            Response.Cookies.Delete("AccessToken");
            Response.Cookies.Delete("RefreshToken");
            return RedirectToAction("Login", "Auth");
        }
        private string GenerateAccessToken(string username, string role)
        {
            var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
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
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
        private async Task SaveRefreshToken(string userId, string refreshToken)
        {
            var refreshTokenEntity = new Refreshtoken
            {
                Token = refreshToken,
                UserId = userId,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(7),
                RevokedAt = default,
            };
            _context.RefreshTokens.Add(refreshTokenEntity);
            await _context.SaveChangesAsync();
        }
        private void SetTokenCookies(string name, string value, int expireMinutes)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTimeOffset.UtcNow.AddMinutes(expireMinutes),
                Secure = true,
                SameSite = SameSiteMode.Strict
            };
            Response.Cookies.Append(name, value, cookieOptions);
        }
    }
}
