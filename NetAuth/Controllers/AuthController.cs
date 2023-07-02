using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetAuth.Dtos;
using NetAuth.Models;
using NetAuth.Services;
using System.Security.Claims;
using System.Security.Cryptography;

namespace NetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
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
        public ActionResult<User> Register(UserDto request)
        {
            return Ok(_authService.Register(request));
        }

        [HttpPost("login")]
        public ActionResult<string> Login([FromBody] UserDto request)
        {
            var token = _authService.Login(request);

            var refreshToken = _authService.GenerateRefreshToken();
            _authService.SetRefreshToken(refreshToken);

            return Ok(token);
        }
        
        [HttpPost("refresh-token")]
        public ActionResult<string> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"]!;
            
            var token = _authService.RefreshToken(refreshToken);
            var newRefreshToken = _authService.GenerateRefreshToken();
            _authService.SetRefreshToken(newRefreshToken);

            return Ok(token);
        }
    }
}