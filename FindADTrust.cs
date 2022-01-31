using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Security.Principal;

namespace FindADTrust
{
    public class Program
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

        public static void PrintDateTimestamp( string key, Int64 value )
        {
            if ( value != 0 )
            {
                try { Console.WriteLine ( string.Format ("{0} : {1}", key, DateTime.FromFileTime(value))); }
                catch { Console.WriteLine ( string.Format ("{0} : {1}", key, value )); }   
            }
            else
            {
                Console.WriteLine ( string.Format ("{0} : {1}", key, value ));
            }
            
        }

        public static void PrintString ( string key, string value)
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value.Trim()) );
        }

        public static void PrintInt32 ( string key, Int32 value)
        {
            if ( key == "trustdirection" )
            {
                switch (value)
                {
                    case 0:
                        Console.WriteLine ( string.Format ("{0} : Disabled", key) );
                        break;
                    
                    case 1:
                        Console.WriteLine ( string.Format ("{0} : Inbound (One-Way)", key) );
                        break;            
                    
                    case 2:
                        Console.WriteLine ( string.Format ("{0} : Outbound (One-Way)", key) );
                        break;
                    
                    case 3:
                        Console.WriteLine ( string.Format ("{0} : Bi-Directional (Two-Way)", key) );
                        break;
                    
                    default:
                        Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
                        break;
                }
            }

            else if ( key == "trusttype" )
            {
                switch (value)
                {
                    case 1:
                        Console.WriteLine ( string.Format ("{0} : DOWNLEVEL", key) );
                        break;
                    
                    case 2:
                        Console.WriteLine ( string.Format ("{0} : UPLEVEL", key) );
                        break;

                    case 3:
                        Console.WriteLine ( string.Format ("{0} : MIT", key) );
                        break;
                    
                    case 4:
                        Console.WriteLine ( string.Format ("{0} : DCE", key) );
                        break;
                    
                    default:
                        Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
                        break;
                }
            }

            else
            {
                Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
            }
        }

        public static void PrintDateTime ( string key, DateTime value)
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static void PrintByte ( string key, byte[] value)
        {
            // handle SID
            if ( (key == "objectsid") || (key == "securityidentifier") )
            {
                SecurityIdentifier sid = new SecurityIdentifier(value,0);
                Console.WriteLine ( string.Format ("{0} : {1}", key, sid ));    

            }

            // handle GUID
            else if ( key == "objectguid" )
            {
                Guid g = new Guid(value);
                Console.WriteLine ( string.Format ("{0} : {1}", key, g.ToString() ));    
            }
            
            // handle all other binary data
            else
            {

                var sb = new StringBuilder();

                foreach ( var b in value) { sb.Append(b); }

                Console.WriteLine ( string.Format ("{0} : {1}", key, sb.ToString() ));
            }
        }

        public static void PrintBool ( string key, bool value)
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static void GetTrustInfo ( string namingContext )
        {
            using ( DirectoryEntry de = new DirectoryEntry (
                        string.Format ( string.Format("LDAP://{0}", namingContext) ),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
            {
                string LDAPFilter = string.Format ( "(objectClass=trustedDomain)" );

                DirectorySearcher ds = new DirectorySearcher ( de, LDAPFilter );

                using ( SearchResultCollection src = ds.FindAll() )
                {
                    Console.WriteLine();

                    foreach ( SearchResult sr in src )
                    {
                        List<string> propertyList = BuildPropertyList(sr);
                        
                        foreach (string prop in propertyList)
                        {
                            if ( sr.Properties[prop].Count > 1)
                            {
                                for ( int i = 0; i < sr.Properties[prop].Count - 1; i++ )
                                {
                                    switch ( sr.Properties[prop][i].GetType().ToString() )
                                    {
                                        case "System.Int64":
                                            PrintDateTimestamp(prop, (Int64)sr.Properties[prop][i]);
                                            break;
                                        
                                        case "System.Int32":
                                            PrintInt32(prop, (Int32)sr.Properties[prop][i]);
                                            break;
                                        
                                        case "System.String":
                                            PrintString(prop, (string)sr.Properties[prop][i]);
                                            break;
                                        
                                        case "System.DateTime":
                                            PrintDateTime(prop, (System.DateTime)sr.Properties[prop][i]);
                                            break;

                                        case "System.Byte[]":
                                            PrintByte(prop, (System.Byte[])sr.Properties[prop][i]);
                                            break;
                                        
                                        case "System.Boolean":
                                            PrintBool(prop, (bool)sr.Properties[prop][i]);
                                            break;
                                    }
                                }
                            }
                            else
                            {
                                switch ( sr.Properties[prop][0].GetType().ToString() )
                                {
                                    case "System.Int64":
                                        PrintDateTimestamp(prop, (Int64)sr.Properties[prop][0]);
                                        break;

                                    case "System.Int32":
                                        PrintInt32(prop, (Int32)sr.Properties[prop][0]);
                                        break;
                                    
                                    case "System.String":
                                        PrintString(prop, (string)sr.Properties[prop][0]);
                                        break;
                                    
                                    case "System.DateTime":
                                        PrintDateTime(prop, (System.DateTime)sr.Properties[prop][0]);
                                        break;

                                    case "System.Byte[]":
                                        PrintByte(prop, (System.Byte[])sr.Properties[prop][0]);
                                        break;

                                    case "System.Boolean":
                                        PrintBool(prop, (bool)sr.Properties[prop][0]);
                                        break;
                                }
                            }
                        }

                        Console.WriteLine();
                    }
                }
            }
        }    
        
        public static void Main (string[] args)
        {
            if (( args.Length == 0 ) || ( args.Length > 1 ))
            {
                Console.WriteLine ( string.Format ( "\n[*] Usage: FindADTrust [namingContext]" ));
                System.Environment.Exit(0);
            }

            // get user information / data 
            GetTrustInfo ( args[0].ToString() );
        }
    }
}