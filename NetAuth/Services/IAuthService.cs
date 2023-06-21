using NetAuth.Dtos;
using NetAuth.Models;

namespace NetAuth.Services
{
    public interface IAuthService
    {
        User Register(UserDto userDto);
        string Login(UserDto userDto);
        string CreateToken(User user);
    }
}
