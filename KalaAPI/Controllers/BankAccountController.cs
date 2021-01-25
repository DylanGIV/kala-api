using KalaAPI.Authentication;
using KalaAPI.Models;
using KalaAPI.Models.Request;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KalaAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class BankAccountController : ControllerBase
    {
        private readonly ILogger<BankAccountController> _logger;
        private readonly ApplicationDbContext _context;

        public BankAccountController(ILogger<BankAccountController> logger, ApplicationDbContext context)
        {
            _logger = logger;
            _context = context;
        }

        [HttpPost]
        public async Task<ActionResult<BankAccount>> PostBankAccount([FromBody]AddBankAccountRequest addBankAccountRequest)
        {
            BankAccount bankAccount = new BankAccount();
            bankAccount.PlaidAccessToken = addBankAccountRequest.PlaidAccessToken;
            var userId = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
            bankAccount.UserId = userId;


            _context.BankAccounts.Add(bankAccount);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetBankAccount), new { id = bankAccount.Id }, bankAccount);
        }

        [HttpGet("{id}")]
        public ActionResult<BankAccount> GetBankAccount(int id)
        {
            return _context.BankAccounts.FirstOrDefault((account) => account.Id == id);
        }

        [HttpGet]
        public ActionResult<IEnumerable<BankAccount>> GetBankAccounts()
        {
            var userId = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value;
            var accounts = _context.BankAccounts.Where(ba => ba.User.Id == userId);

            return Ok(accounts);
        }
    }
}
