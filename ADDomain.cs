using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Security.Principal;

namespace ADDomain
{
    class Program
    {

        public static List<string> BuildPropertyList( DirectoryEntry de )
        {
            // define new List<string>
            List<string> propertyList = new List<string>();

            // append each property name to List
            foreach ( string prop in de.Properties.PropertyNames ) { propertyList.Add(prop); }

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
            if ( key == "objectsid" )
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

        public static void PrintBool ( string key, bool value )
        {
            Console.WriteLine ( string.Format ("{0} : {1}", key, value) );
        }

        public static bool GetDefaultNamingContext ( string domainName )
        {
            try
            {
                using (DirectoryEntry de = new DirectoryEntry(string.Format("LDAP://{0}/RootDSE",domainName)))
                {
                    
                    List<string> propertyList = BuildPropertyList(de);
                    
                    foreach (string prop in propertyList)
                    {
                        if ( de.Properties[prop].Count > 1)
                        {
                            for ( int i = 0; i < de.Properties[prop].Count - 1; i++ )
                            {
                                
                                switch ( de.Properties[prop][i].GetType().ToString() )
                                {
                                    case "System.Int64":
                                        PrintDateTimestamp(prop, (Int64)de.Properties[prop][i]);
                                        break;
                                    
                                    case "System.Int32":
                                        PrintInt32(prop, (Int32)de.Properties[prop][i]);
                                        break;
                                    
                                    case "System.String":
                                        PrintString(prop, (string)de.Properties[prop][i]);
                                        break;
                                    
                                    case "System.DateTime":
                                        PrintDateTime(prop, (System.DateTime)de.Properties[prop][i]);
                                        break;

                                    case "System.Byte[]":
                                        PrintByte(prop, (System.Byte[])de.Properties[prop][i]);
                                        break;

                                    case "System.Boolean":
                                        PrintBool(prop, (bool)de.Properties[prop][i]);
                                        break;
                                }
                            }
                        }
                        else
                        {
                            switch ( de.Properties[prop][0].GetType().ToString() )
                            {
                                case "System.Int64":
                                    PrintDateTimestamp(prop, (Int64)de.Properties[prop][0]);
                                    break;

                                case "System.Int32":
                                    PrintInt32(prop, (Int32)de.Properties[prop][0]);
                                    break;
                                
                                case "System.String":
                                    PrintString(prop, (string)de.Properties[prop][0]);
                                    break;
                                
                                case "System.DateTime":
                                    PrintDateTime(prop, (System.DateTime)de.Properties[prop][0]);
                                    break;

                                case "System.Byte[]":
                                    PrintByte(prop, (System.Byte[])de.Properties[prop][0]);
                                    break;
                                
                                case "System.Boolean":
                                        PrintBool(prop, (bool)de.Properties[prop][0]);
                                        break;
                            }
                        }
                    }
                    
                }

                return true;
            }
            
            catch ( Exception ex ) 
            {   
                Console.WriteLine ( string.Format ( "\nGetDefaultNamingContext: {0}", ex.Message ));
                return false; 
            }
        }

        
        public static void Main ( string[] args )
        {
            // exit if getting defaultNamingContext fails
            // check the parameter
            if (( args.Length == 0 ) || ( args.Length > 1 ))
            {
                Console.WriteLine ( string.Format ( "\n[*] Usage: ADDomain.exe [domainName]" ));
                System.Environment.Exit(0);
            }

            if ( !GetDefaultNamingContext( args[0].ToString() ) )
            {
                System.Environment.Exit(-1);
            }

        }
    }
}