using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using laujiayuan.viewModels;
using Microsoft.EntityFrameworkCore;
using WebApplication3.Model;
using System;
using System.Threading.Tasks;

namespace laujiayuan.Pages
{
    public class LogoutModel : PageModel
    {
        private SignInManager<IdentityUser> signInManager { get; }
        private readonly AuthDbContext _dbcontext;
        private readonly IHttpContextAccessor _context;
        private readonly ILogger<ChangePWDModel> _logger;

        public LogoutModel(IHttpContextAccessor context,
            SignInManager<IdentityUser> signInManager,
            AuthDbContext _dbcontext,
            ILogger<ChangePWDModel> logger)
        {
            _context = context;
            this.signInManager = signInManager;
            this._dbcontext = _dbcontext;
            this._logger = logger;
        }

        public async Task<IActionResult> OnGet()
        {

            if (_context?.HttpContext != null)
            {
                string User_Email_From_Session = _context.HttpContext.Session.GetString("User_Email");

                if (!string.IsNullOrEmpty(User_Email_From_Session))
                {
                    await removeSession(User_Email_From_Session);

                    _context.HttpContext.Session.Clear();

                    foreach (var key in _context.HttpContext.Session.Keys)
                    {
                        _context.HttpContext.Session.Remove(key);
                    }
                    return RedirectToPage("/Login");
                }
            }
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("Session cannot found in logout");
            return RedirectToPage("/login");
        }

        public async Task<IActionResult> removeSession(string User_Email_From_Session)
        {
            try
            {
                _logger.LogInformation("Logout and record succesfully:");
                var auditLog = new AuditLog
                {
                    UserId = User_Email_From_Session,
                    Timing = DateTime.UtcNow,
                    Task = "Logout"
                };

                _dbcontext.AuditLog.Add(auditLog);
                await _dbcontext.SaveChangesAsync();

                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return RedirectToPage("/Login");
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred during the 'removeSession' operation: {ex}");
                throw;
            }
        }
    }
}
