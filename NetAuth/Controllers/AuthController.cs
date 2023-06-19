using Microsoft.AspNetCore.Mvc;
using NetAuth.Dtos;
using NetAuth.Models;

namespace NetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User User = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto requres)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(requres.PasswordHash);

            User.UserName = requres.UserName;
            User.PasswordHash = passwordHash;

            return Ok(User);
        }
    }
}
