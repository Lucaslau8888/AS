using Microsoft.AspNetCore.Mvc;

namespace sessionCore.controllers
{
    public class Home: Controller
    {
        private readonly IHttpContextAccessor contxt;
        public Home(IHttpContextAccessor httpContextAccessor)
        {
            contxt = httpContextAccessor;
        }

        public IActionResult Index() 
        {
            contxt.HttpContext.Session.SetString("User_Email", "user@example.com");
            contxt.HttpContext.Session.SetInt32("StudentId", 50);
	        return View();
        }

}
}
