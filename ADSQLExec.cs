using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SqlClient;

namespace CSharp_ADSQLExec
{
    class Program
    {
        public static string buildConnStr()
        {
            // connection parameters
            string username = "";
            string password = "";
            string servername = "";
            string serverport = "";
            string database = "";

            string banner = "[*] C# MSSQL Client\n";
            banner += "***********************\n";
           
            Console.WriteLine();
            Console.WriteLine(banner);

            Console.Write("[?] Server Name: ");
            servername = Console.ReadLine();

            Console.Write("[?] Server Port [1433]: ");
            serverport = Console.ReadLine();
            if ( serverport == "") { serverport = "1433"; }

            Console.Write("[?] Database [master]: ");
            database = Console.ReadLine();
            if ( database == "") { database = "master";  }

            Console.Write("[?] Username [optional]: ");
            username = Console.ReadLine();

            Console.Write("[?] Password [optional]: ");
            password = Console.ReadLine();

            // check if windows auth
            if ((username == "") || (password == ""))
            {
                return string.Format("Server = {0},{1}; Database = {2}; Integrated Security = SSPI; Connection Timeout=1;", servername,serverport,database);
            }
            else
            {
                return string.Format("Server = {0},{1}; Database = {2}; User Id = {3}; Password = {4}; Connection Timeout=1;", servername, serverport, database, username, password);
            }
        }

        public static void checkAuthentication(string connStr)
        {
            SqlConnection con = new SqlConnection(connStr);

            try
            {
                con.Open();
                Console.WriteLine(string.Format("\n[*] Successful authentication for {0}.", connStr.Split(';')[0].Split('=')[1].Trim()));
                con.Close();
            }
            catch ( Exception ex )
            {
                Console.WriteLine("\n[!!] ERROR - checkAuthentication(): {0}", ex.Message);
                System.Environment.Exit(0);
            }

        }

        public static void RunMSSQLQuery(string query, string connStr)
        {
            SqlConnection con = new SqlConnection(connStr);
            con.Open();
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();

            if (reader.HasRows)
            {
                for ( int i = 0; i < reader.FieldCount; i ++)
                {
                    Console.WriteLine("{0} : {1}", reader.GetName(i), reader[i]);
                }
            }
            
            con.Close();
        }

        public static void Main(string[] args)
        {
            // define connection string
            string connStr = buildConnStr();

            // check credentials
            checkAuthentication(connStr);

            Console.WriteLine("[-->] Enter '99' to exit SQL prompt and script.");

            // client loop
            while (true)
            {
                string cmd = "";
                
                Console.Write("\nSQL > ");
                cmd = Console.ReadLine();

                switch (cmd)
                {
                    case "99":
                        Console.WriteLine();
                        System.Environment.Exit(0);
                        break;

                    default:
                        RunMSSQLQuery(cmd, connStr);
                        break;
                }
            }

        }
    }
}
