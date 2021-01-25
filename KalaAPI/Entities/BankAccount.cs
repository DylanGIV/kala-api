using KalaAPI.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KalaAPI.Models
{
    public class BankAccount
    {
        public long Id { get; set; }

        public string PlaidAccessToken { get; set; }
        
        public string UserId { get; set; }

        public virtual ApplicationUser User { get; set; }
    }
}
