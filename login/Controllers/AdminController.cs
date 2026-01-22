using login.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace login.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly AuthDbContext _context;
        public AdminController(AuthDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Dashboard()
        {
            var totalUsers = await _context.Users.CountAsync();
            var activeUsers = await _context.Users.CountAsync(u => u.IsActive);
            var AdminCount = await _context.Users.CountAsync(u => u.Role == "Admin");
            var UserCount = await _context.Users.CountAsync(u => u.Role == "User");
            var todayRegistrations = await _context.Users.CountAsync(u => u.CreatedAt.Date == DateTime.UtcNow.Date);
            ViewBag.TotalUsers = totalUsers;
            ViewBag.ActiveUsers = activeUsers;
            ViewBag.AdminCount = AdminCount;
            ViewBag.UserCount = UserCount;
            ViewBag.TodayRegistrations = todayRegistrations;
            return View();
        }
        public async Task<IActionResult> Users()
        {
            var users = await _context.Users.OrderByDescending(u => u.CreatedAt).ToListAsync();
            return View(users);
        }
        public async Task<IActionResult> UserDetails(int id)
        {
            var user = await _context.Users.Include(u => u.RefreshTokens).FirstOrDefaultAsync(u => u.Id == id);
            if (user == null)
            {
                return NotFound();
            }
            return View(user);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleUserStatus(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            if (user.Username == User.Identity.Name)
            {
                TempData["Error"] = "Siz o'zingizni block qila olmaysiz";
                return RedirectToAction("Users");
            }
            user.IsActive = !user.IsActive;
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = user.IsActive ? $"{user.Username} faollashtirildi." : $"{user.Username} bloklandi.";
            return RedirectToAction("Users");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangeRole(int id, string newRole)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            if (user.Username == User.Identity.Name)
            {
                TempData["Error"] = "Siz o'zingizni rolingizni o'zgartirolmaysiz";
                return RedirectToAction("Users");
            }
            if (newRole != "Admin" && newRole != "User")
            {
                TempData["Error"] = "Noto'g'ri rol tanlandi.";
                return RedirectToAction("Users");
            }
            user.Role = newRole;
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = $"{user.Username} roli {newRole} ga o'zgartirildi.";
            return RedirectToAction("Users");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return NotFound();
            }
            if (user.Username == User.Identity.Name)
            {
                TempData["Error"] = "Siz o'zingizni o'chira olmaysiz";
                return RedirectToAction("Users");
            }
            if (user.RefreshTokens != null && user.RefreshTokens.Count > 0)
            {
                _context.RefreshTokens.RemoveRange(user.RefreshTokens);
            }
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = $"{user.Username} foydalanuvchisi o'chirildi.";
            return RedirectToAction("Users");
        }
        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
