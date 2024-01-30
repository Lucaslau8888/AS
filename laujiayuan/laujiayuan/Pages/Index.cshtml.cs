using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace laujiayuan.Pages
{

    public class IndexModel : PageModel
    {
        private readonly IHttpContextAccessor _context;
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(IHttpContextAccessor context, ILogger<IndexModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("Dajiahao");
        }
        //public IActionResult OnGet()
        //{
        //    _logger.LogInformation($"time: testing");

        //    // Check if the user is authenticated
        //    if (TempData.TryGetValue("SessionTerminated", out var sessionTerminated) && (bool)sessionTerminated)
        //    {
        //        return RedirectToPage("Login");
        //    }
        //    if (!_context.HttpContext.User.Identity.IsAuthenticated)
        //    {
        //        return RedirectToPage("Login");
        //    }
        //    else
        //    {
        //        var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
        //        _logger.LogInformation($"time: {sessionTimeoutSeconds}");

        //        var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
        //        var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

        //        if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
        //        {
        //            // Session has timed out, clear session and redirect to login page
        //            _context.HttpContext.Session.Clear();
        //            foreach (var key in _context.HttpContext.Session.Keys)
        //            {
        //                _context.HttpContext.Session.Remove(key);
        //            }
        //            RedirectToPage("Login");
        //        }
        //        else
        //        {
        //            _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);

        //            // Continue processing for an active session
        //            // _context.HttpContext.Session.SetInt32("StudentId", 50);
        //        }
        //    }

        //    var userEmail = _context.HttpContext.Session.GetString("User_Email");
        //    return Page();
        //}
    }
}
