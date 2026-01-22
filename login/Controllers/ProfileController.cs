using login.Data;
using login.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace login.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly AuthDbContext _context;
        public ProfileController(AuthDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Index()
        {
            var username = User.Identity?.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            return View(user);
        }
        [HttpGet]
        public async Task<IActionResult> Edit()
        {
            var username = User.Identity?.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            var model = new Models.EditProfileModel
            {
                Username = user.Username,
                Email = user.Email
            };
            return View(model);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(EditProfileModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var username = User.Identity?.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            if (model.Email != user.Email)
            {
                var emailExists = await _context.Users.AnyAsync(u => u.Email == model.Email && u.Id != user.Id);
                if (emailExists)
                {
                    ModelState.AddModelError("Email", "Bu email allaqachon mavjud.");
                    return View(model);
                }
                user.Email = model.Email;
            }
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Profil muvaffaqiyatli yangilandi.";
            return RedirectToAction("Index");
        }
        [HttpGet]
        public IActionResult ChangePassword()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var username = User.Identity?.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            if (!BCrypt.Net.BCrypt.Verify(model.CurrentPassword, user.PasswordHash))
            {
                ModelState.AddModelError("CurrentPassword", "Joriy parol noto'g'ri.");
                return View(model);
            }
            if (model.CurrentPassword == model.NewPassword)
            {
                ModelState.AddModelError("NewPassword", "Yangi parol joriy paroldan farq qilishi kerak.");
                return View(model);
            }
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.NewPassword);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Parol muvaffaqiyatli o'zgartirildi.";
            return RedirectToAction("Index");
        }
        [HttpGet]
        public IActionResult DeleteAccount()
        {
            return View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteAccountConfirmed(string password)
        {
            var username = User.Identity?.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                ModelState.AddModelError("Password", "Parol noto'g'ri.");
                return View("DeleteAccount");
            }
            if (user.Role == "Admin")
            {
                var adminCount = await _context.Users.CountAsync(u => u.Role == "Admin");
                if (adminCount <= 1) {
                    ModelState.AddModelError(string.Empty, "Siz oxirgi admin hisobingizni o'chira olmaysiz. Iltimos, avval boshqa foydalanuvchini admin qiling.");
                    return View("DeleteAccount");
                }
            }

            if (user.RefreshTokens != null && user.RefreshTokens.Any())
            {
                _context.RefreshTokens.RemoveRange(user.RefreshTokens);
            }
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            Response.Cookies.Delete("AccesToken");
            Response.Cookies.Delete("RefreshToken");
            TempData["SuccessMessage"] = "Hisobingiz muvaffaqiyatli o'chirildi.";
            return RedirectToAction("Login", "Auth");
        }
    }

}
