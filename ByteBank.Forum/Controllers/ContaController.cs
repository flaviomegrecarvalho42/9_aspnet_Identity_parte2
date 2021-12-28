using ByteBank.Forum.Models;
using ByteBank.Forum.ViewModels;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ByteBank.Forum.Controllers
{
    public class ContaController : Controller
    {
        private UserManager<UsuarioAplicacao> _userManager;
        private SignInManager<UsuarioAplicacao, string> _signInManager;

        public UserManager<UsuarioAplicacao> UserManager
        {
            get
            {
                if (_userManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _userManager = contextOwin.GetUserManager<UserManager<UsuarioAplicacao>>();
                }

                return _userManager;
            }

            set { _userManager = value; }
        }

        public SignInManager<UsuarioAplicacao, string> SignInManager
        {
            get
            {
                if (_signInManager == null)
                {
                    var contextOwin = HttpContext.GetOwinContext();
                    _signInManager = contextOwin.GetUserManager<SignInManager<UsuarioAplicacao, string>>();
                }

                return _signInManager;
            }

            set { _signInManager = value; }
        }

        public IAuthenticationManager AuthenticationManager
        {
            get
            {
                var contextoOwin = Request.GetOwinContext();
                return contextoOwin.Authentication;
            }
        }

        public ActionResult Registrar()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Registrar(ContaRegistrarViewModel contaRegistrarViewModel)
        {
            if (ModelState.IsValid)
            {
                var novoUsuario = new UsuarioAplicacao
                {
                    Email = contaRegistrarViewModel.Email,
                    UserName = contaRegistrarViewModel.UserName,
                    NomeCompleto = contaRegistrarViewModel.NomeCompleto
                };

                var usuarioCadastrado = await UserManager.FindByEmailAsync(contaRegistrarViewModel.Email);

                if (usuarioCadastrado != null)
                {
                    return View("AguardandoConfirmacao");
                }

                var resultado = await UserManager.CreateAsync(novoUsuario, contaRegistrarViewModel.Senha);

                if (!resultado.Succeeded)
                {
                    AdicionaErros(resultado);

                    return View(contaRegistrarViewModel);
                }

                // Enviar o email de confirmação
                await EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(novoUsuario, false);
                return View("AguardandoConfirmacao");
            }

            return View(contaRegistrarViewModel);
        }

        public async Task<ActionResult> ConfirmacaoEmail(string usuarioId, string token)
        {
            if (string.IsNullOrWhiteSpace(usuarioId) || string.IsNullOrWhiteSpace(token))
            {
                return View("Error");
            }

            var resultado = await UserManager.ConfirmEmailAsync(usuarioId, token);

            if (!resultado.Succeeded)
            {
                return View("Error");
            }

            return View("EmailConfirmado");
        }

        public ActionResult Login()
        {
            ContaLoginViewModel contaLoginViewModel = new ContaLoginViewModel();
            contaLoginViewModel.ContinuarLogado = true;
            ViewData.Model = contaLoginViewModel;

            return View();
        }

        [HttpPost]
        public async Task<ActionResult> Login(ContaLoginViewModel contaLoginViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(contaLoginViewModel.Email);

                if (usuario == null)
                {
                    return SenhaOuUsuarioInvalidos();
                }

                var signInResultado = await SignInManager
                                            .PasswordSignInAsync(usuario.UserName,
                                                                 contaLoginViewModel.Password,
                                                                 isPersistent: contaLoginViewModel.ContinuarLogado,
                                                                 shouldLockout: true);

                switch (signInResultado)
                {
                    case SignInStatus.Success:
                        if (!usuario.EmailConfirmed)
                        {
                            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                            return View("AguardandoConfirmacao");
                        }

                        return RedirectToAction("Index", "Home");
                    case SignInStatus.LockedOut:
                        bool senhaCorreta = await UserManager.CheckPasswordAsync(usuario, contaLoginViewModel.Password);

                        if (senhaCorreta)
                        {
                            ModelState.AddModelError("", "A conta está bloqueada!");
                        }
                        else
                        {
                            return SenhaOuUsuarioInvalidos();
                        }

                        break;
                    default:
                        return SenhaOuUsuarioInvalidos();
                }
            }

            return View(contaLoginViewModel);
        }

        public ActionResult LembrarSenha()
        {
            return View();
        }

        [HttpPost]
        public async Task<ActionResult> LembrarSenha(ContaEsqueciSenhaViewModel contaEsqueciSenhViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await UserManager.FindByEmailAsync(contaEsqueciSenhViewModel.Email);

                if (usuario != null)
                {
                    await EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(usuario, true);
                }

                return View("EmailAlteracaoSenhaEnviado");
            }

            return View();
        }

        public ActionResult ConfirmacaoAlteracaoSenha(string usuarioId, string token)
        {
            var contaConfirmaAlteracaoSenhaViewModel = new ContaConfirmaAlteracaoSenhaViewModel
            {
                UsuarioId = usuarioId,
                Token = token
            };

            return View(contaConfirmaAlteracaoSenhaViewModel);
        }

        [HttpPost]
        public async Task<ActionResult> ConfirmacaoAlteracaoSenha(ContaConfirmaAlteracaoSenhaViewModel contaConfirmaAlteracaoSenhaViewModel)
        {
            if (ModelState.IsValid)
            {
                // Verifica o Token recebido
                // Verifica o ID do usuário
                // Mudar a senha
                var resultadoAlteracao = await UserManager.ResetPasswordAsync(contaConfirmaAlteracaoSenhaViewModel.UsuarioId,
                                                                              contaConfirmaAlteracaoSenhaViewModel.Token,
                                                                              contaConfirmaAlteracaoSenhaViewModel.NewPassword);

                if (!resultadoAlteracao.Succeeded)
                {
                    AdicionaErros(resultadoAlteracao);
                }

                return View("AlteracaoSenhaConfirmada");
            }

            return View();
        }

        [HttpPost]
        public ActionResult Logoff()
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            return RedirectToAction("Index", "Home");
        }

        private void AdicionaErros(IdentityResult identityResult)
        {
            foreach (var erro in identityResult.Errors)
            {
                ModelState.AddModelError("", erro);
            }
        }

        private ActionResult SenhaOuUsuarioInvalidos()
        {
            ModelState.AddModelError("", "Credenciais inválidas!");
            return View("Login");
        }

        private async Task EnviarEmailDeConfirmacaoOuAlteracaoSenhaAsync(UsuarioAplicacao usuarioAplicacaoModel, bool ehAlteracaoSenha)
        {
            string textoLinkCallBack = "ConfirmacaoEmail";
            string assuntoEmail = "Fórum ByteBank - Confirmação de Email";

            if (ehAlteracaoSenha)
            {
                textoLinkCallBack = "ConfirmacaoAlteracaoSenha";
                assuntoEmail = "Fórum ByteBank - Alteração de Senha";
            }

            // Gerar o token de reset da senha
            var tokenEmail = ehAlteracaoSenha ? await UserManager.GeneratePasswordResetTokenAsync(usuarioAplicacaoModel.Id) :
                                                await UserManager.GenerateEmailConfirmationTokenAsync(usuarioAplicacaoModel.Id);
            ;

            // Gerar a url para o usuário
            var linkDeCallback = Url.Action(
                textoLinkCallBack,
                "Conta",
                new { usuarioId = usuarioAplicacaoModel.Id, token = tokenEmail },
                Request.Url.Scheme);

            // Enviar email
            await UserManager.SendEmailAsync(
                usuarioAplicacaoModel.Id,
                assuntoEmail,
                ehAlteracaoSenha ? $"Bem-vido ao fórum ByteBank, cliqque aqui {linkDeCallback} para alterar a sua senha!" :
                                   $"Bem-vido ao fórum ByteBank, cliqque aqui {linkDeCallback} para confirmar seu email!");
        }
    }
}