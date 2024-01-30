using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.Pages;
using WebApplication3.ViewModels;
using laujiayuan.viewModels;
using static System.Net.WebRequestMethods;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;

namespace laujiayuan.Pages
{
    public class user_detail4Model : PageModel
    {


        private readonly IHttpContextAccessor _context;
        private readonly ILogger<user_detail4Model> _logger;
        private readonly AuthDbContext _dbcontext;

        private SignInManager<IdentityUser> signInManager { get; }

        public user_detail4Model(
           IHttpContextAccessor dbContext,
           ILogger<user_detail4Model> logger,
           SignInManager<IdentityUser> signInManager,
           AuthDbContext _dbcontext
)
        {
            this._context = dbContext;
            this._logger = logger;
            this.signInManager = signInManager;
            this._dbcontext = _dbcontext;
        }


        public async Task<IActionResult> OnGet() 
        {

            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                _logger.LogInformation("Cannot found any session ID in your session ");
                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToPage("Login");

            }
            var AUDIT_RECORD = new AuditLog
            {
                UserId =_context.HttpContext.Session.GetString("User_Email"),
                Timing = DateTime.UtcNow,
                Task = "User Detail"
            };

            _dbcontext.AuditLog.Add(AUDIT_RECORD);
            await _dbcontext.SaveChangesAsync();
     

            var sessionTimer = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"Your Session Timer: {sessionTimer}");

            var now = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? now;

            if (sessionTimer.HasValue && (now - lastActivityTime) > sessionTimer)
            {

                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                _logger.LogInformation($"Your Session is already time out");
                removeSession();
                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)now);

             
            }


            return Page();  
        }

        public async Task<IActionResult> OnPostAsync()
        {
            return Page();
        }

        public async Task<IActionResult> removeSession()
        {
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage("/Login");
        }
    }
}

