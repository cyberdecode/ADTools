using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Security.Principal;

namespace ADGPO
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
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static void PrintDateTime ( string key, DateTime value)
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static void PrintByte ( string key, byte[] value)
        {
            // handle SID
            if ( key.Contains("sid") )
            {
                SecurityIdentifier sid = new SecurityIdentifier(value,0);
                Console.WriteLine ( string.Format ("{0} : {1}", key, sid ));    

            }

            // handle GUID
            else if ( key.Contains("guid") )
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

        public static void PrintBool ( string key, bool value )
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static void GetGPOInfo ( string namingContext, string displayName )
        {
            using ( DirectoryEntry de = new DirectoryEntry (
                        string.Format ( "LDAP://{0}", namingContext ),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
            {

                string LDAPFilter = "";

                switch (displayName)
                {
                    case "all":
                        LDAPFilter = string.Format ( "(objectClass=grouppolicycontainer)" ) ;
                        break;
                    
                    default:
                        LDAPFilter = string.Format ( "(&(objectClass=grouppolicycontainer)(displayName={0}))", displayName );
                        break;
                }

                DirectorySearcher ds = new DirectorySearcher ( de, LDAPFilter );

                ds.PageSize = 1000;
                ds.ServerPageTimeLimit = TimeSpan.FromSeconds(2);

                // handle all attributes returned
                if ( displayName == "all" )
                {
                    ds.PropertiesToLoad.Add("displayName");
                    ds.PropertiesToLoad.Add("distinguishedName");
                    ds.PropertiesToLoad.Add("gpcFileSysPath");
                    ds.PropertiesToLoad.Add("cn");
                    ds.PropertiesToLoad.Add("objectguid");
                }

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

                    else {  Console.WriteLine ( string.Format ( "\n[!!] No GPO found for {0}\n", displayName ) ); }
                }
            }
        }    
        
        public static void Main ( string[] args )
        {
            // check the parameter
            if (( args.Length == 0 ) || ( args.Length == 1 ) || ( args.Length > 2 ))
            {
                Console.WriteLine ( string.Format ( "\n[*] Usage: ADGPO.exe [namingContext] [gpoDisplayName | all]" ));
                System.Environment.Exit(0);
            }


            // get user information / data 
            GetGPOInfo ( args[0].ToString(), args[1].ToString() );
        }
    }
}