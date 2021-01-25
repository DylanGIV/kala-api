using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace KalaAPI.Authentication
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string FirstName { get; set; }
    }
}
