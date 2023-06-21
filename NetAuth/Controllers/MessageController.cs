using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetAuth.Dtos;
using NetAuth.Models;

namespace NetAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MessageController : ControllerBase
    {
        private static readonly Message Message = new();

        [HttpPost("/send"), Authorize(Roles = "Admin")]
        public ActionResult<Message> SendMessage(MessageDto request)
        {
            Message.Content = request.ContentBody;
            return Ok(Message);
        }
    }
}
