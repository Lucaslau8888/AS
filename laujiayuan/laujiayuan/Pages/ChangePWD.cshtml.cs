using laujiayuan.viewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Newtonsoft.Json;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using Microsoft.EntityFrameworkCore;

namespace laujiayuan.Pages
{
    public class ChangePWDModel : PageModel
    {
        public DbSet<AuditLog> AuditLogs { get; set; }

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly IHttpContextAccessor _context;

        private readonly ILogger<ChangePWDModel> _logger;

        private readonly AuthDbContext _dbcontext; // Add this field


        //[BindProperty]
        //public Register RModel { get; set; }

        [BindProperty]
        public ChangePWD CModel { get; set; }


        [BindProperty]
        public string RecaptchaResponse { get; set; }

        //private string Email_Session = "";


        public ChangePWDModel(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        IDataProtectionProvider dataProtectionProvider,
         IHttpContextAccessor dbContext,
         ILogger<ChangePWDModel> logger,
         AuthDbContext _dbcontext)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.dataProtectionProvider = dataProtectionProvider;
            this._context = dbContext;
            this._logger = logger;
            this._dbcontext = _dbcontext;
        }



        public async Task<IActionResult> OnGet()
        {
            if (_context.HttpContext.Session.GetString("SessionId") == null)
            {
                await signInManager.SignOutAsync();
                await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                _logger.LogInformation("Cannot found any session ID in your session ");
                return RedirectToPage("Login");

            }

            var sessionTimeoutSeconds = _context.HttpContext.Session.GetInt32("UserSessionTimeout");
            _logger.LogInformation($"time: {sessionTimeoutSeconds}");

            var currentTime = DateTimeOffset.Now.ToUnixTimeSeconds();
            var lastActivityTime = _context.HttpContext.Session.GetInt32("LastActivityTime") ?? currentTime;

            if (sessionTimeoutSeconds.HasValue && (currentTime - lastActivityTime) > sessionTimeoutSeconds)
            {

                _context.HttpContext.Session.Clear();

                foreach (var key in _context.HttpContext.Session.Keys)
                {
                    _context.HttpContext.Session.Remove(key);
                }
                _logger.LogInformation($"Your Session is already time out");
                Remove_Session();

                return RedirectToPage("Login");
            }
            else
            {
                _context.HttpContext.Session.SetInt32("LastActivityTime", (int)currentTime);

                // _context.HttpContext.Session.SetInt32("StudentId", 50);
            }

            return Page();
        }


        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OnPostAsync()
        {

            // Inside your OnPostAsync method
            var recaptcha_SecretKey = "6Lf_xV4pAAAAAI3fQb53P9ZG6g-s8yGZZICKv_iU";
            var recaptcha_Api_Url = "https://www.google.com/recaptcha/api/siteverify";

            var recaptcha__Client = new HttpClient();
            var recaptchaResult = await recaptcha__Client.PostAsync(recaptcha_Api_Url, new FormUrlEncodedContent(new List<KeyValuePair<string, string>>
                {
                new KeyValuePair<string, string>("secret", recaptcha_SecretKey),
                new KeyValuePair<string, string>("response", RecaptchaResponse),
                new KeyValuePair<string, string>("remoteip", HttpContext.Connection.RemoteIpAddress.ToString())
            }));


            if (!recaptchaResult.IsSuccessStatusCode)
            {
                ModelState.AddModelError("", "Failed to validate the reCAPTCHA.");
                return Page();
            }

            var recaptcha_Content = await recaptchaResult.Content.ReadAsStringAsync();
            var recaptcha_Response = JsonConvert.DeserializeObject<RecaptchaResponse>(recaptcha_Content);

            if (!recaptcha_Response.Success)
            {
                ModelState.AddModelError("", "the reCAPTCHA validation failed.");
                return Page();
            }



            if (CModel.Password != null && CModel.ConfirmPassword != null)
            {
                if (CModel.Password != null)
                {
                    if (!PasswordRequirements(CModel.Password))
                    {
                        ModelState.AddModelError(nameof(CModel.Password), "Password must be at least 12 characters long and include a " +
                            "combination of lower-case, upper-case, numbers, and special characters.");
                        return Page();
                    }
                }


                try
                {
                    var password_encryptor = dataProtectionProvider.CreateProtector("Password");
                    var ProtectPassword = password_encryptor.Protect(CModel.Password);

                    var Email_Session = unprotect_Email(_context.HttpContext.Session.GetString("User_Email"));
                    var usr_Login = await userManager.FindByEmailAsync(Email_Session);
                    _logger.LogInformation($"User {Email_Session} is found");

                    // update password function
                    var changePasswordResult = await userManager.ChangePasswordAsync(usr_Login, CModel.Current_Password, CModel.Password);

                    if (changePasswordResult.Succeeded)
                    {
                        if (string.IsNullOrEmpty(Email_Session))
                        {
                            _logger.LogInformation($"User email is null or empty. Password update unsuccessful.");
                            return RedirectToPage("/Error");
                        }

                        // update the register database as well
                        var Users_From_Database = _dbcontext.Registers.ToList(); 
                        var user = Users_From_Database.FirstOrDefault(u => unprotect_Email(u.Email) == Email_Session);


                        if (user == null)
                        {
                            _logger.LogInformation($"{Email_Session} password update unsecessfully");
                            return NotFound();  

                        }


                        _logger.LogInformation($"{Email_Session} password update seccesfully");
                       await record();

                        user.Password = ProtectPassword;
                        user.ConfirmPassword = ProtectPassword;

                        await _dbcontext.SaveChangesAsync();


                        return RedirectToPage("/user_detail4");
                    }
                    else if (!changePasswordResult.Succeeded)
                    {
                        ModelState.AddModelError(nameof(CModel.Current_Password), "Your Current Password is Wrong");
                        return Page();
                    }
                    else
                    {
                        if (!changePasswordResult.Succeeded)
                        {
                            foreach (var error in changePasswordResult.Errors)
                            {
                                ModelState.AddModelError(string.Empty, error.Description);
                            }

                            return Page();
                        }

                    }
                }
                catch (Exception ex)
                {
                    _logger.LogInformation($"error in 208 lines");
                    return NotFound();

                }

            }
            return Page();
        }

        private string unprotect_Email(string encryptedEmail)
        {
            var protector = dataProtectionProvider.CreateProtector("EmailProtection");
            return protector.Unprotect(encryptedEmail);
        }

        private bool PasswordRequirements(string password)
        {

            return password.Length >= 12
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(ch => !char.IsLetterOrDigit(ch));
        }

        public async Task<IActionResult> Remove_Session()
        {
            await signInManager.SignOutAsync();
            await _context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToPage("/Login");
        }


        private async Task record()
        {
            // Log user activity to the database
            var auditLog = new AuditLog
            {
                UserId = HttpContext.Session.GetString("User_Email"),
                Timing = DateTime.UtcNow,
                Task = "ChangePassword"
            };

            _dbcontext.AuditLog.Add(auditLog);
            await _dbcontext.SaveChangesAsync();
        }
    }
}
