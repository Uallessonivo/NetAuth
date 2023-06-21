using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetAuth.Dtos;
using NetAuth.Models;
using NetAuth.Services;
using System.Security.Claims;

namespace NetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
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
            return Ok(_authService.Register(requrest));
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto requrest)
        {
            return Ok(_authService.Login(requrest));
        }
    }
}
