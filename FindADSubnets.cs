using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Security.Principal;

namespace FindADSubnets
{
    class Program
    {

        public static List<string> BuildPropertyList( SearchResult sr )
        {
            // define new List<string>
            List<string> propertyList = new List<string>();

            // append each property name to List
            foreach ( string prop in sr.Properties.PropertyNames ) { propertyList.Add(prop); }

            // sort the keys 
            propertyList.Sort();

            return propertyList;
        }

        public static void PrintString ( string key, string value)
        {
            Console.WriteLine ( string.Format ("{0}", value.Trim()) );
        }

        public static void GetSubnetInfo ( string namingContext )
        {
            using ( DirectoryEntry de = new DirectoryEntry (
                        string.Format ( "LDAP://CN=Sites,CN=Configuration,{0}", namingContext ),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
            {
                string LDAPFilter = string.Format ( "(objectClass=subnet)" );

                DirectorySearcher ds = new DirectorySearcher ( de, LDAPFilter );
                ds.PropertiesToLoad.Add("distinguishedname");
                ds.PropertiesToLoad.Add("siteobject");

                using ( SearchResultCollection src = ds.FindAll() )
                {
                    if ( src.Count > 0 )
                    {
                        
                        Console.WriteLine();

                        foreach ( SearchResult sr in src )
                        {
                            List<string> propertyList = BuildPropertyList(sr);
                            
                            foreach (string prop in propertyList)
                            {
                                if ( (prop == "distinguishedname") || (prop == "siteobject") )
                                {
                                    if ( sr.Properties[prop].Count > 1)
                                    {
                                        for ( int i = 0; i < sr.Properties[prop].Count - 1; i++ )
                                        {
                                            
                                            switch ( sr.Properties[prop][i].GetType().ToString() )
                                            {
                                                
                                                case "System.String":
                                                    PrintString(prop, (string)sr.Properties[prop][i]);
                                                    break;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        switch ( sr.Properties[prop][0].GetType().ToString() )
                                        {
                                            case "System.String":
                                                PrintString(prop, (string)sr.Properties[prop][0]);
                                                break;
                                        }
                                    }
                                }
                            }

                            Console.WriteLine();
                        }

                        Console.WriteLine();
                    }

                    else {  Console.WriteLine ( string.Format ( "\n[!!] No Subnet found.\n"  ) ); }
                }
            }
        }    
        
        public static void Main ( string[] args )
        {
            // check the parameter
            if ( (args.Length == 0) || (args.Length > 1) )
            {
                Console.WriteLine ( string.Format ( "\n[*] Usage: FindADSubnet.exe [namingContext]" ));
                System.Environment.Exit(0);
            }

            GetSubnetInfo ( args[0].ToString() );
        }
    }
}