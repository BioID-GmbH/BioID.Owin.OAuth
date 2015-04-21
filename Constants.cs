
namespace BioID.Owin.OAuth
{
    public static class BioIDClaimTypes
    {
        public const string BCID = "urn:bioid:bcid";
        public const string Profile = "urn:bioid:profile";
    }
    public static class BioIDAuthentication
    {
        public const string DefaultType = "BioID";
        public const string DefaultPath = "/signin-bioid";
    }
}
