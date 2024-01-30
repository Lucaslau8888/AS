using laujiayuan.viewModels;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.IO; 
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WebApplication3.Model;
using WebApplication3.ViewModels;
using static System.Net.WebRequestMethods;

namespace WebApplication3.Pages
{
	public class RegisterModel : PageModel
	{

		private UserManager<IdentityUser> userManager { get; }
		private SignInManager<IdentityUser> signInManager { get; }
        //private  DbSet<Register> Registers { get; set; }

        private readonly IDataProtectionProvider dataProtectionProvider;

        private readonly AuthDbContext _context; // Add this field

        private readonly ILogger<RegisterModel> _logger;



        [BindProperty]
		public Register RModel { get; set; }

        [BindProperty]
        public IFormFile Resume { get; set; }

        public RegisterModel(
           UserManager<IdentityUser> userManager,
           SignInManager<IdentityUser> signInManager,
           IDataProtectionProvider dataProtectionProvider,
            AuthDbContext dbContext,
            ILogger<RegisterModel> logger
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
            var file_path_overall = "";

            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,}$");
            if (RModel.Email == null || !emailRegex.IsMatch(RModel.Email))
            {
                ModelState.AddModelError(nameof(RModel.Email), "Please enter a valid email address.");
                return Page();
            }



            if (RModel.First_Name != null && RModel.Last_Name != null && RModel.NRIC != null)
            {

                var Name_protector = dataProtectionProvider.CreateProtector("Name");

                var protectFirst_Name = Name_protector.Protect(RModel.First_Name.ToLower());
                var protectlast_Name = Name_protector.Protect(RModel.Last_Name.ToLower());

                var Email_protector = dataProtectionProvider.CreateProtector("EmailProtection");
                var email_Regex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
                // Check if the email format is valid
                if (RModel.Email == null || !email_Regex.IsMatch(RModel.Email))
                {
                    ModelState.AddModelError(nameof(RModel.Email), "Please enter a valid email address.");
                    return Page();
                }

                var protectEmail = Email_protector.Protect(RModel.Email.ToLower());
                var nricRegex = new Regex(@"^[TtSs]\d{7}[A-Za-z]$");
                if (RModel.NRIC == null || !nricRegex.IsMatch(RModel.NRIC))
                {
                    ModelState.AddModelError(nameof(RModel.NRIC), "Please enter a valid NRIC address.");
                    return Page();
                }

                var IC_protector = dataProtectionProvider.CreateProtector("NRIC");
                var ProtectNRIC = IC_protector.Protect(RModel.NRIC);


                var all_email = await _context.Registers.ToListAsync();
                var existingUser = await userManager.Users.FirstOrDefaultAsync(u => u.Email == RModel.Email);
                var existingUser_register_db = all_email.FirstOrDefault(u => UnprotectEmail(u.Email).ToLower() == RModel.Email.ToLower());



            if ( existingUser !=null)
            {
                ModelState.AddModelError(nameof(RModel.Email), "Email already been used");
                return Page();
            }
          

            if (RModel.Password != null){
                if (!Passwordvalidation(RModel.Password))
                {
                    ModelState.AddModelError(nameof(RModel.Password), "Password must be at least 12 characters long and include a combination of lower-case, upper-case, numbers, and special characters.");
                    return Page();
                }
            }
            if (Resume != null)
            {
                    long FILE_SIZE = 2 * 1024 * 1024; 

                    if (Resume.Length > FILE_SIZE)
                    {
                        ModelState.AddModelError(nameof(Resume), "File size exceeds the allowed limit.");
                        return Page();
                    }
                 string[] allowedExtensions = { ".pdf", ".doc", ".docx" };
                var fileExtension = Path.GetExtension(Resume.FileName).ToLowerInvariant();
                if (!allowedExtensions.Contains(fileExtension))
                {
                    ModelState.AddModelError(nameof(Resume), "Invalid file extension.only Allowed extensions are .pdf, .doc, .docx");
                    return Page();
                }
                else
                {
                        file_path_overall = generateUniqueID(fileExtension);
                        using (var File_Stresm = new FileStream(file_path_overall, FileMode.Create))
                        {
                        await Resume.CopyToAsync(File_Stresm);
                        }
                }

            }

              if(RModel.Password == null || RModel.Password == "")
                {
                    ModelState.AddModelError(nameof(RModel.Password), "Password is required.");
                    return Page();
                }

               var password_protector = dataProtectionProvider.CreateProtector("Password");
               var ProtectPassword = password_protector.Protect(RModel.Password);


                if (ModelState.IsValid)
                {
                    var user = new IdentityUser()
                    {
                        UserName = RModel.Email,
                        Email = RModel.Email
                    };


                    if (!string.IsNullOrEmpty(RModel.WhoAmI))
                    {
                        RModel.WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RModel.WhoAmI);
                    }

                    var register = new Register()
                    {
                        Email = protectEmail,
                        First_Name = protectFirst_Name,
                        Last_Name = protectlast_Name,
                        DOB = RModel.DOB,
                        ConfirmPassword = ProtectPassword,
                        Password = ProtectPassword,
                        NRIC = ProtectNRIC,
                        Gender = RModel.Gender,
                        WhoAmI = System.Text.Encodings.Web.HtmlEncoder.Default.Encode(RModel.WhoAmI),
                        ResumeFilePath = file_path_overall, 
                    };

                    _context.Registers.Add(register);
                    var result1 = await _context.SaveChangesAsync();

                    var result2 = await userManager.CreateAsync(user, RModel.Password);

                    if (result1 > 0 && result2.Succeeded) 
                    {
                        await signInManager.SignInAsync(user, false);
                        return RedirectToPage("Index");
                    }
                    else
                    {
                        ModelState.AddModelError("", "Error in Register 205 line codes.");
                        return Page();
                    }
                }
            }
            return Page();
        }


        private string generateUniqueID(string file_Extension)
        {
            var random = new Random();
            var Random_ID = random.Next(1, 10001);
            var filePath = Path.Combine(".\\resume", Random_ID + file_Extension);

            if (System.IO.File.Exists(filePath))
            {
                return generateUniqueID(file_Extension);
            }
            else
            {
                return filePath;
            }
        }


        private string UnprotectEmail(string encryptedEmail)
        {
            var protector = dataProtectionProvider.CreateProtector("EmailProtection");
            return protector.Unprotect(encryptedEmail);
        }


        private bool Passwordvalidation(string password)
        {
            
            return password.Length >= 12
                && password.Any(char.IsUpper)
                && password.Any(char.IsLower)
                && password.Any(char.IsDigit)
                && password.Any(ch => !char.IsLetterOrDigit(ch));
        }


    }
}
