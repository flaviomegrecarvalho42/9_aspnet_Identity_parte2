﻿using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
    }
}