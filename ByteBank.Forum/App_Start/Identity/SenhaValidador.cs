using Microsoft.AspNet.Identity;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace ByteBank.Forum.App_Start.Identity
{
    public class SenhaValidador : IIdentityValidator<string>
    {
        public int TamanhoRequerido { get; set; }
        public bool ObrigatorioCaracteresEspeciais { get; set; }
        public bool ObrigatorioLowerCase { get; set; }
        public bool ObrigatorioUpperCase { get; set; }
        public bool ObrigatorioDigitos { get; set; }

        public async Task<IdentityResult> ValidateAsync(string item)
        {
            var erros = new List<string>();

            if (!VerificaTamanhoRequerido(item))
            {
                erros.Add($"A senha deve conter no mínimo {TamanhoRequerido} caracteres.");
            }

            if (ObrigatorioCaracteresEspeciais && !VerificaCaracteresEspeciais(item))
            {
                erros.Add("A senha deve conter caracteres especiais.");
            }

            if (ObrigatorioLowerCase && !VerificaLowerCase(item))
            {
                erros.Add($"A senha deve conter no mínimo uma letra minúscula.");
            }

            if (ObrigatorioUpperCase && !VerificaUpperCase(item))
            {
                erros.Add($"A senha deve conter no mínimo uma letra maiúscula.");
            }

            if (ObrigatorioDigitos && !VerificaDigitos(item))
            {
                erros.Add($"A senha deve conter no mínimo um dígito.");
            }

            if (erros.Any())
            {
                return IdentityResult.Failed(erros.ToArray());
            }

            return IdentityResult.Success;
        }

        public bool VerificaTamanhoRequerido(string senha) =>
            senha?.Length >= TamanhoRequerido;

        public bool VerificaCaracteresEspeciais(string senha) =>
            Regex.IsMatch(senha, @"[~`!@#$%^&*()+=|\\{}':;.,<>/?[\]""_-]");

        public bool VerificaLowerCase(string senha) =>
            senha.Any(char.IsLower);

        public bool VerificaUpperCase(string senha) =>
            senha.Any(char.IsUpper);

        public bool VerificaDigitos(string senha) =>
            senha.Any(char.IsDigit);
    }
}