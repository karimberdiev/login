using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace login.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public IActionResult Dashboard()
        {
            var username = User.Identity.Name;
            ViewBag.Username = username;
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
    }
}
