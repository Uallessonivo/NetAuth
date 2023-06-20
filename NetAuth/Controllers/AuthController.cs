using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NetAuth.Dtos;
using NetAuth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace NetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User User = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto requrest)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(requrest.Password);

            User.UserName = requrest.UserName;
            User.PasswordHash = passwordHash;

            return Ok(User);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto requrest)
        {
            if (User.UserName != requrest.UserName)
            {
                return BadRequest("User not found.");

            }

            if (!BCrypt.Net.BCrypt.Verify(requrest.Password, User.PasswordHash))
            {
                return BadRequest("Wrong email or password");
            }

            string token = CreateToken(User);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.Role, "User"),
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
