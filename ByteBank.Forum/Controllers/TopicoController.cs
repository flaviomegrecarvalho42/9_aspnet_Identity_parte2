using ByteBank.Forum.ViewModels;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    public class TopicoController : Controller
    {
        [Authorize]
        public ActionResult Criar()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        public ActionResult Criar(TopicoCriarViewModel topicoCriarViewModel)
        {
            return View();
        }
    }
}