using Microsoft.AspNetCore.Authorization;
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
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("me"), Authorize]
        public ActionResult<string> GetMyName()
        {
            var userName = User.Identity?.Name;
            var roleClaims = User.FindAll(ClaimTypes.Role);

            var roles = roleClaims?.Select(c => c.Value).ToList();

            return Ok(new { userName, roles });
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto requrest)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(requrest.Password);

            user.UserName = requrest.UserName;
            user.PasswordHash = passwordHash;

            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto requrest)
        {
            if (user.UserName != requrest.UserName)
            {
                return BadRequest("User not found.");

            }

            if (!BCrypt.Net.BCrypt.Verify(requrest.Password, user.PasswordHash))
            {
                return BadRequest("Wrong email or password");
            }

            string token = CreateToken(user);

            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "User"),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            string jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}
