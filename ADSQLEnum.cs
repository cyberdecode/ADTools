using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.Security.Principal;
using System.Data;
using System.Runtime.InteropServices;
using System.Data.SqlClient;

namespace CSharp_ADSQLEnum
{
    class Program
    {
        public static List<string> BuildPropertyList(SearchResult sr)
        {
            // define new List<string>
            List<string> propertyList = new List<string>();

            // append each property name to List
            foreach (string prop in sr.Properties.PropertyNames) { propertyList.Add(prop); }

            // sort the keys 
            propertyList.Sort();

            return propertyList;
        }
        
        public static List<string> TargetConnStrs = new List<string>();

        public static DirectoryEntry GetDefaultNamingContext(string domainName)
        {
            DirectoryEntry de = new DirectoryEntry();

            try
            {
                de = new DirectoryEntry(string.Format("LDAP://{0}/RootDSE", domainName));
            }

            catch (Exception ex)
            {
                Console.WriteLine(string.Format("\n[!!] ERROR: GetDefaultNamingContext: {0}", ex.Message));
                System.Environment.Exit(0);
            }

            return de;
        }

        public static void GetMssqlSPNs(string ldapBindStr)
        {
            using (DirectoryEntry de = new DirectoryEntry(
                        string.Format("{0}", ldapBindStr),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
            {
                // define the filter 
                string LDAPFilter = "";
                LDAPFilter = "(servicePrincipalName=mssqlsvc/*)";

                DirectorySearcher ds = new DirectorySearcher(de, LDAPFilter);

                // page sizing
                ds.PageSize = 1000;
                ds.ServerPageTimeLimit = TimeSpan.FromSeconds(2);

                ds.PropertiesToLoad.Add("servicePrincipalName");

                using (SearchResultCollection src = ds.FindAll())
                {
                    if (src.Count > 0)
                    {
                        Console.WriteLine();

                        foreach (SearchResult sr in src)
                        {
                            List<string> propertyList = BuildPropertyList(sr);

                            foreach (string prop in propertyList)
                            {
                               for (int i = 0; i < sr.Properties[prop].Count; i++)
                               {
                                    string hostName = "";

                                    // define hostName
                                    hostName = sr.Properties[prop][i].ToString().Split('/')[1].Split(':')[0];
                                    
                                    if ( !(hostName == "") )
                                    {
                                        // build unique list of SQL instances
                                        string connStr = string.Format("Server = {0}; Database = master; Integrated Security = SSPI; Connection Timeout=1;", hostName);
                                        TargetConnStrs.Add(connStr);
                                    }
                                }                                
                            }
                        }

                        TargetConnStrs = TargetConnStrs.Distinct().ToList();
                    }

                    else { Console.WriteLine(string.Format("\n[!!] No MSSQL SPNs found for {0}\n", ldapBindStr)); }
                }
            }
        }

        public static void RunMSSQLQuery(string query, string description, string connStr)
        {
            SqlConnection con = new SqlConnection(connStr);
            con.Open();
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();

            Console.WriteLine(string.Format("{0} : {1}", description, reader[0]));
            con.Close();
        }

        public static void TestMSSQLAuthentication()
        {
            foreach ( string connStr in TargetConnStrs )
            {
                Console.WriteLine(string.Format("[--> TESTING: {0}",connStr));

                SqlConnection con = new SqlConnection(connStr);

                try
                {
                    con.Open();
                    Console.WriteLine(string.Format("[*] Successful authentication for {0}.", connStr.Split(';')[0].Split('=')[1]));
                    con.Close();

                    // get SYSTEM_USER
                    RunMSSQLQuery("SELECT SYSTEM_USER;", "\tSQL Login: ", connStr);

                    // get USERNAME
                    RunMSSQLQuery("SELECT USER_NAME();", "\tUsername: ", connStr);

                    // get SRVROLE MEMBER
                    RunMSSQLQuery("SELECT IS_SRVROLEMEMBER('public');", "\tPublic Role: ", connStr);
                    RunMSSQLQuery("SELECT IS_SRVROLEMEMBER('sysadmin');", "\tSysadmin Role: ", connStr);

                    // get database name
                    RunMSSQLQuery("SELECT DB_NAME();", "\tDatabase: ", connStr);

                    // get servername
                    RunMSSQLQuery("SELECT @@servername;", "\tServer Name: ", connStr);

                    // get servicename
                    RunMSSQLQuery("SELECT @@servicename;", "\tService Name: ", connStr);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(string.Format("[!!] ERROR - Authentication failure on {0}: {1}", connStr, ex));
                }

                Console.WriteLine();
            }
        }

        static void Main(string[] args)
        {
            // check the parameter
            if ((args.Length == 0) || (args.Length > 1))
            {
                Console.WriteLine(string.Format("\n[*] Usage: ADSQLEnum.exe [namingContext]"));
                System.Environment.Exit(0);
            }

            // print user information
            Console.WriteLine();
            Console.WriteLine("[*] User: {0}", Environment.UserName);
            Console.WriteLine("[*] Domain Name: {0}", Environment.UserDomainName);
            Console.WriteLine("[*] User Interactive: {0}", Environment.UserInteractive);

            // get domain information
            DirectoryEntry domainDE = new DirectoryEntry();
            domainDE = GetDefaultNamingContext(args[0].ToString());

            Console.WriteLine();
            Console.WriteLine(String.Format("[*] defaultNamingContext: {0}", domainDE.Properties["defaultNamingContext"][0]));
            Console.WriteLine(String.Format("[*] serverName: {0}", domainDE.Properties["serverName"][0]));

            // build domain controller string
            string dcHostName = "";
            dcHostName += domainDE.Properties["serverName"][0].ToString().Split(',')[0].Split('=')[1];
            
            string dcDomainName = "";
            dcDomainName += domainDE.Properties["defaultNamingContext"][0].ToString().Replace("DC=", "").Replace(',', '.');

            string dcFullName = string.Format("{0}.{1}", dcHostName, dcDomainName);
            Console.WriteLine(String.Format("[*] Domain Controller: {0}",dcFullName));

            // ldap bind string
            string ldapBindStr = "";
            ldapBindStr += string.Format("LDAP://{0}/{1}", dcFullName, domainDE.Properties["defaultNamingContext"][0].ToString());

            Console.WriteLine("[*] LDAP Bind String: {0}", ldapBindStr);

            // query for mssql service
            GetMssqlSPNs(ldapBindStr);

            // attempt MSSQL authentication
            if ( TargetConnStrs.Count > 0 )
            {
                TestMSSQLAuthentication();
            }
            
            else
            {
                Console.WriteLine("[!!] ERROR - No MSSQL SPNs to target.");
                System.Environment.Exit(0);
            }
        }  
    }
}
