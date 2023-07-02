using Microsoft.IdentityModel.Tokens;
using NetAuth.Dtos;
using NetAuth.Exceptions;
using NetAuth.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NetAuth.Services
{
    public class AuthService : IAuthService
    {
        private static User _user = new User();
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _contextAccessor;

        public AuthService(IConfiguration configuration, IHttpContextAccessor contextAccessor)
        {
            _configuration = configuration;
            _contextAccessor = contextAccessor;
        }

        public string Login(UserDto userDto)
        {
            if (_user.UserName != userDto.UserName)
            {
                throw new UserNotFoundException("User not found.");
            }

            if (!BCrypt.Net.BCrypt.Verify(userDto.Password, _user.PasswordHash))
            {
                throw new InvalidCredentialsException("Invalid Credentials.");
            }

            string token = CreateToken(_user);

            return token;
        }

        public User Register(UserDto userDto)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(userDto.Password);

            _user.UserName = userDto.UserName;
            _user.PasswordHash = passwordHash;

            return _user;
        }

        public string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, AuthService._user.UserName),
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

        public RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddHours(2)
            };

            return refreshToken;
        }

        public void SetRefreshToken(RefreshToken refreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires,
            };

            _user.RefreshToken = refreshToken.Token;
            _user.TokenCreated = refreshToken.Created;
            _user.TokenExpires = refreshToken.Expires;

            _contextAccessor.HttpContext?.Response.Cookies.Append("refreshToken", refreshToken.Token, cookieOptions);
        }

        public string RefreshToken(string newRefreshToken)
        {
            if (!_user.RefreshToken.Equals(newRefreshToken))
            {
                throw new UnauthorizedException("Invalid Refresh Token");
            }
            else if (_user.TokenExpires < DateTime.Now)
            {
                throw new UnauthorizedException("Token Expired");
            }

            string token = CreateToken(_user);
            
            return token;
        }
    }
}