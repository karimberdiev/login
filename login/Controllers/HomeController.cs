using login.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace login.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly AuthDbContext _context;
        public HomeController(AuthDbContext context)
        {
            _context = context;
        }
        public async Task<IActionResult> Dashboard()
        {
            var username = User.Identity.Name;
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user == null)
            {
                return RedirectToAction("Login", "Auth");
            }
            ViewBag.Username = username;
            ViewBag.Email = user.Email; 
            ViewBag.Role = user.Role;
            ViewBag.CreatedAt = user.CreatedAt;
            ViewBag.LastLoginAt = user.LastLoginAt;

            if(user.Role == "Admin")
            {
                ViewBag.WelcomeMessage = "Xush kelibsiz, Administrator!";
                ViewBag.CanAccessAdminPanel = true;
            }
            else
            {
                ViewBag.WelcomeMessage = "Xush kelibsiz, Foydalanuvchi!";
                ViewBag.CanAccessAdminPanel = false;
            }

            return View();
        }
        public IActionResult Index()
        {
            return RedirectToAction("Dashboard");
        }
        [AllowAnonymous]
        public IActionResult Privacy()
        {
            return View();
        }
        [Authorize(Roles = "User")]
        public IActionResult UserOnly()
        {
            return View();
        }
    }
}
