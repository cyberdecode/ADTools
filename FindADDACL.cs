using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;

class Program
{
    public static byte[] descriptorBytes;
    public static string owner;
    public static string group;
 
    public static void getSecurityDescriptor(string distinguishedName)
    {
        // set the ADS Path
        string adsPath = string.Format("LDAP://{0}",distinguishedName);

        // establish the bind
        DirectoryEntry de = new DirectoryEntry(adsPath, null, null, AuthenticationTypes.Secure);

        // perform the search
        using (de)
        {
            // define the directory searcher - pass de, ldapFilter, and string[] array
            DirectorySearcher ds = new DirectorySearcher(de, null, new string[] { "ntSecurityDescriptor" } );

            // define the security masks
            ds.SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Group | SecurityMasks.Owner;

            // execute the search
            SearchResult sr = ds.FindOne();

            // if no object found, exit script
            if ( sr == null)
            {
                Console.WriteLine(string.Format("[!!] ERROR - No AD Object found for {0}", distinguishedName));
                System.Environment.Exit(0);
            }
            else
            {
                descriptorBytes = (byte[])sr.Properties["ntSecurityDescriptor"][0];
            }
        }
    }

    public static void parseSecurityDescriptor()
    {

        ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

        ads.SetSecurityDescriptorBinaryForm(descriptorBytes,AccessControlSections.All);

        // print SecurityDescriptor attributes
        printSD(ads);

        AuthorizationRuleCollection rules = null;
        
        rules = ads.GetAccessRules(true, true, typeof (NTAccount));

        // print ACEs
        foreach (ActiveDirectoryAccessRule rule in rules) { printACE(rule); }

    }

    public static void printSD(ActiveDirectorySecurity sd)
    {
        owner = sd.GetOwner(typeof(NTAccount)).ToString();
        group = sd.GetGroup(typeof(NTAccount)).ToString();

        Console.WriteLine(string.Format("Owner: {0}",owner));
        Console.WriteLine(string.Format("Group: {0}",group));
    }

    public static void printACE(ActiveDirectoryAccessRule rule)
    {

        // define dictionary of default AD GUIDs
        Dictionary<string,string> propertyGUIDs = new Dictionary<string,string>();
        propertyGUIDs["Domain Password & Lockout Policies"] = "C7407360-20BF-11D0-A768-00AA006E0529".ToLower();
        propertyGUIDs["General Infomration"] = "59BA2F42-79A2-11D0-9020-00C04FC2D3CF".ToLower();
        propertyGUIDs["Account Restrictions"] = "4C164200-20C0-11D0-A768-00AA006E0529".ToLower();
        propertyGUIDs["Logon Information"] = "5F202010-79A5-11D0-9020-00C04FC2D4CF".ToLower();
        propertyGUIDs["Group Membership"] = "BC0AC240-79A9-11D0-9020-00C04FC2D4CF".ToLower();
        propertyGUIDs["Phone and Mail Options"] = "E45795B2-9455-11D1-AEBD-0000F80367C1".ToLower();
        propertyGUIDs["Personal Information"] = "77B5B886-944A-11D1-AEBD-0000F80367C1".ToLower();
        propertyGUIDs["Web Information"] = "E45795B3-9455-11D1-AEBD-0000F80367C1".ToLower();
        propertyGUIDs["Public Information"] = "E48D0154-BCF8-11D1-8702-00C04FB96050".ToLower();
        propertyGUIDs["Remote Access Information"] = "037088F8-0AE1-11D2-B422-00A0C968F939".ToLower();
        propertyGUIDs["Other Domain Parameters"] = "B8119FD0-04F6-4762-AB7A-4986C76B3F9A".ToLower();
        propertyGUIDs["DNS Host Name Attributes"] = "72E39547-7B18-11D1-ADEF-00C04FD8D5CD".ToLower();
        propertyGUIDs["MS-TS-GatewayAccess"] = "FFA6F046-CA4B-4FEB-B40D-04DFEE722543".ToLower();
        propertyGUIDs["Private Information"] = "91E647DE-D96F-4B70-9557-D63FF4F3CCD8".ToLower();
        propertyGUIDs["Terminal Server License Server"] = "5805BC62-BDC9-4428-A5E2-856A0F4C185E".ToLower();
    
        string objectType = "";
        string inheritedObjectType = "";

        // handle ObjecType GUID values
        if (rule.ObjectType == Guid.Empty) { objectType = ""; }
        else { 
            
            objectType = rule.ObjectType.ToString(); 

            // attempt to resolve GUID
            foreach(KeyValuePair<string,string> guid in propertyGUIDs)
            {
                if (guid.Value.Equals(objectType)) { objectType += string.Format(" ({0})", guid.Key); }
            }
        
        }

        // handle InheritenceObjectType GUID values
        if (rule.InheritedObjectType == Guid.Empty) { inheritedObjectType = ""; }
        else { 
            
            inheritedObjectType = rule.InheritedObjectType.ToString(); 
        
            // attempt to resolve GUID
            foreach(KeyValuePair<string,string> guid in propertyGUIDs)
            {
                if (guid.Value.Equals(inheritedObjectType)) { inheritedObjectType += string.Format(" ({0})", guid.Key); }
            }
        }

        // format string for CSV output
        Console.WriteLine(string.Format("{0},{1},{2},{3},{4},{5},{6}", rule.IdentityReference.ToString(),
                                                                       rule.AccessControlType.ToString(),
                                                                       rule.ActiveDirectoryRights.ToString().Replace(",",";"),
                                                                       rule.InheritanceType.ToString(),
                                                                       objectType,
                                                                       rule.ObjectFlags.ToString(),
                                                                       inheritedObjectType));
        
    }

    public static void Main(string[] args)
    {
        // check arguments
        if ((args.Length == 0) || (args.Length > 1))
        {
            Console.WriteLine();
            Console.WriteLine(string.Format("[*] Usage: FindADDACL.exe [distinguishedName]"));
            System.Environment.Exit(0);
        }

        // start CSV output format
        Console.WriteLine(string.Format("Identity,AccessControl,ADRights,InheritenceType,ObjectType,ObjectFlags,InheritedObjectType"));

        // program execution       
        getSecurityDescriptor(args[0].ToString());

        Console.WriteLine();
        parseSecurityDescriptor();

    }
}