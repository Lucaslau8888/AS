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
    using Newtonsoft.Json;

    using laujiayuan.viewModels;
    using static System.Net.WebRequestMethods;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication;
    using System.Text.RegularExpressions;
using System.Collections.Generic;  


    namespace laujiayuan.Pages
    {
        public class LoginModel : PageModel
        {

        private UserManager<IdentityUser> userManager { get; }
        private SignInManager<IdentityUser> signInManager { get; }
        public DbSet<AuditLog> AuditLogs { get; set; }


        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly AuthDbContext _context; 

            private readonly ILogger<LoginModel> _logger;

            //[BindProperty]
            //public Register RModel { get; set; }

            [BindProperty]
            public Login LModel { get; set; }


            [BindProperty]
            public string RecaptchaResponse { get; set; }



            public LoginModel
            (
              UserManager<IdentityUser> userManager,
              SignInManager<IdentityUser> signInManager,
              IDataProtectionProvider dataProtectionProvider,
               AuthDbContext dbContext,
               ILogger<LoginModel> logger
                )
            {
                this.userManager = userManager;
                this.signInManager = signInManager;
                this.dataProtectionProvider = dataProtectionProvider;
                this._context = dbContext;
                this._logger = logger;
            }

            public void OnGet()
            {
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


                var RegexForEmail = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
                if (LModel.Email != null)
                {
                    if (!RegexForEmail.IsMatch(LModel.Email) || LModel.Email == null)
                    {
                        ModelState.AddModelError(nameof(LModel.Email), "Please enter the valid email");
                        return Page();
                    }
                }

                else if (LModel.Email == null && LModel.Password == null)
                {
                    ModelState.AddModelError("", "Please enter your Email and password");
                    return Page();
                }
            var usrLogin = await userManager.FindByEmailAsync(LModel.Email);

            if (usrLogin != null)
            {
                // get all users from the database
                var list_of_Users = _context.Registers.ToList(); 
                var user = list_of_Users.FirstOrDefault(u => umprotectEmail(u.Email) == usrLogin.Email);

                var protector = dataProtectionProvider.CreateProtector("EmailProtection");


              
                if (await userManager.IsLockedOutAsync(usrLogin))
                {
                    var auditLog = new AuditLog
                    {
                        UserId = protector.Protect(usrLogin.Email),
                        Timing = DateTime.UtcNow,
                        Task = "Account is locked but still trying"
                    };

                    _context.AuditLog.Add(auditLog);
                    await _context.SaveChangesAsync();

                    ModelState.AddModelError("", "Your Account is locked out. Please try again later.");
                    return Page();
                }


                if (LModel.Password != null)
                {
                    var hasher = new PasswordHasher<IdentityUser>();
                    var passworderificationResult = hasher.VerifyHashedPassword(usrLogin, usrLogin.PasswordHash, LModel.Password);
                    if (passworderificationResult == PasswordVerificationResult.Success)
                        {
                        var email_protect = protector.Protect(usrLogin.Email);

                        var session_timeout = 120; //1min
                        HttpContext.Session.SetInt32("UserSessionTimeout", session_timeout);
                        var existingSessionId = HttpContext.Session.GetString("SessionId");
                        var newSessionId = Guid.NewGuid().ToString();
                        await signInManager.PasswordSignInAsync(usrLogin.Email, LModel.Password, false, false);


                        if (!string.IsNullOrEmpty(existingSessionId))
                            {
                                HttpContext.Session.Clear();
                                await signInManager.SignOutAsync();
                                TempData["SessionTerminated"] = true;
                                _logger.LogInformation($"Terminating old session -  SessionId: {existingSessionId}");
                            

                            HttpContext.Session.SetString("SessionId", newSessionId);
                                HttpContext.Session.SetString("User_Email", email_protect);
                                _logger.LogInformation($"Create a new session with SessionId: {newSessionId}");
                            }
                            else
                            {

                                HttpContext.Session.SetString("SessionId", newSessionId);
                                TempData["SessionTerminated"] = false;
                                HttpContext.Session.SetString("User_Email", email_protect);
                            HttpContext.Session.SetString("First_Name", user.First_Name);
                            HttpContext.Session.SetString("Last_Name", user.Last_Name);
                            HttpContext.Session.SetString("NRIC", user.NRIC);
                            HttpContext.Session.SetString("WAI", user.WhoAmI);
                            HttpContext.Session.SetString("DOB", user.DOB.ToString());


                            _logger.LogInformation($"Login successful with SessionId: {email_protect}");
                            }
                        await record();
                        return RedirectToPage("/user_detail4");

                        }
                        else
                        {
                            await userManager.AccessFailedAsync(usrLogin);

                            if (await userManager.IsLockedOutAsync(usrLogin))
                            {
                                var auditLog1 = new AuditLog
                                {
                                    UserId = protector.Protect(usrLogin.Email),
                                    Timing = DateTime.UtcNow,
                                    Task = "Account is lock"
                                };


                                _context.AuditLog.Add(auditLog1);
                                await _context.SaveChangesAsync();
                                ModelState.AddModelError("", "Account is locked out. Please try again later.");
                                return Page();

                            }

                        ModelState.AddModelError("", "Email or password is invalid");
                        var auditLog = new AuditLog
                        {
                            UserId = protector.Protect(usrLogin.Email),
                            Timing = DateTime.UtcNow,
                            Task = "Enter wrong password"
                        };


                        _context.AuditLog.Add(auditLog);
                        await _context.SaveChangesAsync();

                        _logger.LogInformation($"Wrong password");
                            return Page();
                    }
                }
                else
                {
                    ModelState.AddModelError("", "Please Enter Password");
                    return Page();
                }
            }
            else
            {
                ModelState.AddModelError("", "Email or password is invalid");
                _logger.LogInformation($"User is not found in the Database");
                return Page();
            }
        }


            private string umprotectEmail(string encryptedEmail)
            {
                var protector = dataProtectionProvider.CreateProtector("EmailProtection");
                return protector.Unprotect(encryptedEmail);
            }




        private async Task record()
        {
            // Log user activity to the database
            var auditLog = new AuditLog
            {
                UserId = HttpContext.Session.GetString("User_Email"),
                Timing = DateTime.UtcNow,
                Task = "login"
            };

            _context.AuditLog.Add(auditLog);
            await _context.SaveChangesAsync();
        }

    }
    }
