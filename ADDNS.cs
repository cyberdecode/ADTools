using System;
using System.DirectoryServices;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Text;
using System.Security.Principal;

namespace ADDns
{
    public class dnsRecord
    {
        public string distinguishedName { get; set; }
        public byte[] adDnsRecord { get; set; }

        public dnsRecord() {}
    }

    class Program
    {
        public static string distinguishedName = "";
        
        // get distinguishedName of passed domain
        public static void GetDistinguishedName( string domain )
        {
             using ( DirectoryEntry de = new DirectoryEntry (
                        string.Format ( "LDAP://{0}", domain ),
                        null,
                        null,
                        AuthenticationTypes.Secure
                    ))
                    {
                        try
                        { 
                            Console.WriteLine(string.Format("[*] distinguishedName: {0}",de.Properties["distinguishedName"][0].ToString()));
                            distinguishedName = de.Properties["distinguishedName"][0].ToString(); 
                        }
                        catch ( Exception ex ) 
                        { 
                            Console.WriteLine(string.Format("\n[!!] ERROR - GetDistinguishedName(): {0}\n", ex.ToString()));
                            System.Environment.Exit(0);
                        }
                    }
        }
        
        // Get ADS Path values from DNS zones
        public static void GetAdsPaths()
        {
            try
            {

                using ( DirectoryEntry de = new DirectoryEntry (
                            string.Format ( "LDAP://DC=DomainDnsZones,{0}", distinguishedName ),
                            null,
                            null,
                            AuthenticationTypes.Secure
                        ))
                        {   
                            string LDAPFilter = "(objectClass=dnsZone)";

                            DirectorySearcher ds = new DirectorySearcher ( de, LDAPFilter );

                            using ( SearchResultCollection src = ds.FindAll() )
                            {
                                if ( src.Count > 0 )
                                {
                                    Console.WriteLine(string.Format("[*] Total dnsZones: {0}", src.Count));

                                    foreach ( SearchResult sr in src )
                                    {
                                        try
                                        {
                                            for ( int i = 0; i < sr.Properties["adspath"].Count; i++ )
                                            {
                                                Console.WriteLine("[**] ZONE: {0}",sr.Properties["adspath"][i].ToString());
                                                GetDnsRecords(sr.Properties["adspath"][i].ToString());
                                            }
                                        }
                                        catch {}
                                    }
                                }
                            }
                        }
            }
            catch ( Exception ex )
            {
                Console.WriteLine(string.Format("\n[!!] ERROR - GetAdsPath(): {0}\n", ex.ToString()));
                System.Environment.Exit(0);
            }
        }

        // pull all dnsRecords for given adspath
        public static void GetDnsRecords(string adspath)
        {
            try
            { 
                using ( DirectoryEntry de = new DirectoryEntry (
                            //path,
                            adspath,
                            null,
                            null,
                            AuthenticationTypes.Secure
                    ))
                    {
                        foreach ( DirectoryEntry lde in de.Children)
                        {
                            dnsRecord holder = new dnsRecord();
                            holder.distinguishedName = lde.Properties["distinguishedName"][0].ToString();
                            holder.adDnsRecord = (byte[]) lde.Properties["dnsRecord"][0];
                            
                            ParseDnsRecords(holder);
                        }
                    }
            }
            catch ( Exception ex )
            {
                Console.WriteLine(string.Format("\n[!!] ERROR - GetDnsRecords(): {0}\n", ex.ToString()));
                System.Environment.Exit(0);
            }
        }

        // decode hostname
        public static string DecodeName( byte[] adDnsRecord, int offset )
        {
            int totalLen = adDnsRecord[offset];
            int segments = adDnsRecord[offset + 1];
            int index = offset + 2;

            string name = "";

            for ( int i = segments; i > 0; i-- )
            {
                int segmentLength = adDnsRecord[index++];

                for ( int j = segmentLength; j > 0; j-- )
                {
                    name = name + (char)adDnsRecord[index++];
                }

                name = name + ".";
            }

            return name;
        }

        //public static void ParseDnsRecords()
        public static void ParseDnsRecords(dnsRecord dnsr)
        {

            // pull the domain name from the distinguishedname
            string[] nameArray = dnsr.distinguishedName.Split(',');
            string name = nameArray[0].Substring(3);

            // Type of Record
            int rdatatype = (int)((dnsr.adDnsRecord[3] * 256) + dnsr.adDnsRecord[2]);

            // Serial in the SOA where this item was last updated
            int updatedAtSerial = (int) dnsr.adDnsRecord[11];
            updatedAtSerial = (int)((updatedAtSerial * 256) + dnsr.adDnsRecord[10]);
            updatedAtSerial = (int)((updatedAtSerial * 256) + dnsr.adDnsRecord[9]);
            updatedAtSerial = (int)((updatedAtSerial * 256) + dnsr.adDnsRecord[8]);

            // Time To Live
            int ttl = (int) dnsr.adDnsRecord[12];
            ttl = (int)((ttl * 256) + dnsr.adDnsRecord[13]);
            ttl = (int)((ttl * 256) + dnsr.adDnsRecord[14]);
            ttl = (int)((ttl * 256) + dnsr.adDnsRecord[15]);

            // Timestamp of when record expires, 0 means static
            int age = (int) dnsr.adDnsRecord[23];
            age = (int)((age * 256) + dnsr.adDnsRecord[22]);
            age = (int)((age * 256) + dnsr.adDnsRecord[21]);
            age = (int)((age * 256) + dnsr.adDnsRecord[20]);

            string recordTimeSpan = "";
            if ( age != 0 )
            {
                TimeSpan t = DateTime.UtcNow - new DateTime(1970,1,1);
                recordTimeSpan = (System.DateTimeOffset.FromUnixTimeMilliseconds((long)t.TotalMilliseconds).DateTime).ToString();
                
            }
            else
            {
                recordTimeSpan = "[static]";
            }

            // switch case to process record type
            switch ( rdatatype )
            {
                // A Record
                case 1:
                    string ip = string.Format("{0}.{1}.{2}.{3}", dnsr.adDnsRecord[24],
                                                                    dnsr.adDnsRecord[25],
                                                                    dnsr.adDnsRecord[26],
                                                                    dnsr.adDnsRecord[27]);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "A",
                                                                ip.ToString()
                                                                ));
                    break;
            
                // NS Record
                case 2:
                    string nsName = DecodeName(dnsr.adDnsRecord,24);
                    
                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "NS",
                                                                nsName.ToString()
                                                                ));

                    break;
                
                // CNAME or Alias
                case 5:
                    string aliasName = DecodeName(dnsr.adDnsRecord,24);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "CNAME",
                                                                aliasName.ToString()
                                                                ));
                    break;

                // SOA Record
                case 6:
            
                    int nsLen = (int) dnsr.adDnsRecord[44];
                    string soaName = DecodeName(dnsr.adDnsRecord,44);
                    int index = 46 + nsLen;

                    // responsible party
                    string respParty = DecodeName(dnsr.adDnsRecord,index);

                    // serial
                    int serial = dnsr.adDnsRecord[24];
                    serial = (int)((serial * 256) + dnsr.adDnsRecord[25]);
                    serial = (int)((serial * 256) + dnsr.adDnsRecord[26]);
                    serial = (int)((serial * 256) + dnsr.adDnsRecord[27]);

                    // refresh
                    int refresh = dnsr.adDnsRecord[28];
                    refresh = (int)((refresh * 256) + dnsr.adDnsRecord[29]);
                    refresh = (int)((refresh * 256) + dnsr.adDnsRecord[30]);
                    refresh = (int)((refresh * 256) + dnsr.adDnsRecord[31]);

                    // retry
                    int retry = dnsr.adDnsRecord[32];
                    retry = (int)((retry * 256) + dnsr.adDnsRecord[33]);
                    retry = (int)((retry * 256) + dnsr.adDnsRecord[34]);
                    retry = (int)((retry * 256) + dnsr.adDnsRecord[35]);

                    // expires
                    int expires = dnsr.adDnsRecord[36];
                    expires = (int)((expires * 256) + dnsr.adDnsRecord[37]);
                    expires = (int)((expires * 256) + dnsr.adDnsRecord[38]);
                    expires = (int)((expires * 256) + dnsr.adDnsRecord[39]);

                    // minttl
                    int minttl = dnsr.adDnsRecord[40];
                    minttl = (int)((minttl * 256) + dnsr.adDnsRecord[41]);
                    minttl = (int)((minttl * 256) + dnsr.adDnsRecord[42]);
                    minttl = (int)((minttl * 256) + dnsr.adDnsRecord[43]);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "SOA"
                                                                ));
                    Console.WriteLine(string.Format("{0}Primary Server: {1}","".PadLeft(32),soaName));
                    Console.WriteLine(string.Format("{0}Responsible Party: {1}","".PadLeft(32),respParty));
                    Console.WriteLine(string.Format("{0}Serial: {1}","".PadLeft(32),serial));
                    Console.WriteLine(string.Format("{0}TTL: {1}","".PadLeft(32),ttl));
                    Console.WriteLine(string.Format("{0}Refresh: {1}","".PadLeft(32),refresh));
                    Console.WriteLine(string.Format("{0}Retry: {1}","".PadLeft(32),retry));
                    Console.WriteLine(string.Format("{0}Expires: {1}","".PadLeft(32),expires));
                    Console.WriteLine(string.Format("{0}Minimum TTL (default): {1}","".PadLeft(32),minttl));

                    break;

                // PTR record
                case 12:

                    string ptrName = DecodeName(dnsr.adDnsRecord,24);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "PTR",
                                                                ptrName.ToString()
                                                                ));
                    break;

                // HINFO record
                case 13:

                    string cpuType = "";
                    string osType = "";
                    
                    // cpu type
                    int hinfo_segmentLength = dnsr.adDnsRecord[24];
                    int hinfo_index = 25;

                    for ( int i = hinfo_segmentLength; i > 0; i-- )
                    {
                        cpuType = cpuType + (char) dnsr.adDnsRecord[hinfo_index++];
                    }

                    // os type
                    hinfo_index = 24 + dnsr.adDnsRecord[24] + 1;
                    hinfo_segmentLength = hinfo_index++;

                    for ( int j = hinfo_segmentLength; j > 0; j-- )
                    {
                        osType = osType + (char) dnsr.adDnsRecord[hinfo_index++];
                    }

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4},{5}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "HINFO",
                                                                cpuType.ToString(),
                                                                osType.ToString()
                                                                ));
                    break;
                
                // MX Record
                case 15:

                    // priority
                    int priority = dnsr.adDnsRecord[24];
                    priority = (int)((priority * 256) + dnsr.adDnsRecord[25]);

                    // MX host
                    string mxName = DecodeName(dnsr.adDnsRecord,26);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}  {5}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "MX",
                                                                priority,
                                                                mxName.ToString()
                                                                ));
                    break;

                // TXT record
                case 16:

                    string txt = "";
                    int segmentLength = dnsr.adDnsRecord[24];
                    int index2 = 25;

                    for ( int i = segmentLength; i > 0; i-- ) 
                    { 
                        txt = txt + (char)dnsr.adDnsRecord[index2++];
                    }

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "TXT",
                                                                txt.ToString()
                                                                ));
                    break;
                
                // AAAA record
                case 28:

                    string str = "";

                    for ( int i = 24; i < 40; i = i + 2 )
                    {
                        int segment = dnsr.adDnsRecord[i];
                        str = str + segment.ToString("x4");
                        if ( i != 38 ) { str = str + ":"; }
                    }

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "AAAA",
                                                                str.ToString()
                                                                ));
                    break;
                
                // SVR record
                case 33:

                    // port
                    int port = dnsr.adDnsRecord[28];
                    port = (int)((port * 256) + dnsr.adDnsRecord[29]);
                    
                    // weight
                    int weight = dnsr.adDnsRecord[26];
                    weight = (int)((weight * 256) + dnsr.adDnsRecord[27]);

                    // priority
                    int priority2 = dnsr.adDnsRecord[24];
                    priority2 = (int)((priority2 * 256) + dnsr.adDnsRecord[25]);

                    // nsname
                    string nsName2 = DecodeName(dnsr.adDnsRecord,30);

                    Console.WriteLine(string.Format("{0,-30}\t{1,-24}\t{2}\t{3}\t{4} {5}",
                                                                name.ToString(),
                                                                recordTimeSpan.ToString(),
                                                                ttl.ToString(),
                                                                "SRV",
                                                                string.Format("[{0}][{1}][{2}]",
                                                                        priority2.ToString(),
                                                                        weight.ToString(),
                                                                        port.ToString()
                                                                    ),
                                                                nsName2.ToString()
                                                                ));
                    break;
                
                // dump bytes
                // only used if dont know record type
                default:

                    Console.WriteLine(string.Format("{0}",name));
                    Console.WriteLine(string.Format("RDataType {0}",rdatatype));
                    Console.WriteLine(string.Format("{0}",dnsr.distinguishedName));

                    string hex = "";
                    string chr = "";
                    string str_int = "";

                    Console.WriteLine(string.Format("[*] Array contains {0} elements.",dnsr.adDnsRecord.Length));

                    int dump_index = 0;
                    int count = 0;

                    for ( int j = dnsr.adDnsRecord.Length; j > 0; j-- )
                    {
                        int value = dnsr.adDnsRecord[dump_index++];

                        hex = hex + string.Format("{0} ",value.ToString("x2"));

                        if ( (Char.IsLetterOrDigit((char) value)) ||
                             (Char.IsPunctuation((char) value)) || 
                             (((char) value).ToString() == " "))
                        {
                            chr = chr + (char) value;
                        }
                        else { chr = chr + "."; }

                        str_int = str_int + string.Format("{0,4:N0}",value);

                        count++;

                        if ( count > 9 )
                        {
                            Console.WriteLine("{0} {1} {2}",hex,chr,str_int);

                            hex = "";
                            chr = "";
                            str_int = "";
                            count = 0;
                        }
                    }

                    if ( count > 0 )
                    {
                        if ( count < 9 )
                        {
                            hex = hex + string.Format("{0," + (3 * (9 - count)) + "}", " ");
                            chr = chr + string.Format("{0," + (1 * (9 - count)) + "}", " ");
                            str_int = str_int + string.Format("{0," + (4 * (9 - count)) + "}", " ");
                        }

                        Console.WriteLine("{0} {1} {2}",hex,chr,str_int);
                    }

                    break;
            }
        }

        public static void Main ( string[] args )
        {
            // check the parameter
            if (( args.Length == 0 ) || ( args.Length > 1 ))
            {
                Console.WriteLine ( string.Format ( "\n[*] Usage: ADDNS.exe [domain]" ));
                System.Environment.Exit(0);
            }

            // formatting
            Console.WriteLine();

            // get the domain distinguishedName
            GetDistinguishedName(args[0].ToString());
            
            // get the adsPaths for the namingContext            
            GetAdsPaths();

            Console.WriteLine();
        }
    }
}