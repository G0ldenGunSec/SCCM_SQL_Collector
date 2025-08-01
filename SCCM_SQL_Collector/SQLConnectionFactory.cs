
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Net.NetworkInformation;

namespace SCCM_SQL_Collector
{
    internal abstract class SQLConnectionFactory
    {

        /// <summary>
        /// The CreateSqlConnectionObject method creates a SQL connection object.
        /// This method can be particularly useful if you want to create multiple SQL connection objects.
        /// A single SQL connection object will only allow one instance of a 'SqlDataReader'.
        /// If you are writing a module where you need to execute multiple SQL queries against a database
        /// at the exact same time, then this module will facilitate that. Such as the Adsi module.
        /// </summary>
        /// <returns>A SQL connection object based on the current authentication type, or null if the authentication type is invalid.</returns>
        internal static SqlConnection CreateSqlConnectionObject(Dictionary<string,string> parsedArgs)
        {
            SqlConnection connection;

            //get base values we'll definitely need to connect to the database
            string host = parsedArgs.ContainsKey("h") ? parsedArgs["h"] : parsedArgs["host"];
            string port = "1433";            
            if (parsedArgs.ContainsKey("port"))
            {
                port = parsedArgs["port"];
            }
            //need to be explicit on db arg due to overlap with "d" for domain
            string database = parsedArgs["database"];
            string authType = (parsedArgs.ContainsKey("a") ? parsedArgs["a"] : parsedArgs["auth"]).ToLower();

            //optional vals based on auth type
            string domain = parsedArgs.ContainsKey("d") ? parsedArgs["d"] : parsedArgs.ContainsKey("domain") ? parsedArgs["domain"]: null;
            string user = parsedArgs.ContainsKey("u") ? parsedArgs["u"] : parsedArgs.ContainsKey("user") ? parsedArgs["user"] : null;
            string password = parsedArgs.ContainsKey("p") ? parsedArgs["p"] : parsedArgs.ContainsKey("password") ? parsedArgs["password"] : null;



            string serverInfo = $"{host},{port}";
            switch (authType)
            {
                case "wintoken":
                    connection = SqlAuthentication.WindowsToken(serverInfo, database);
                    break;
                case "windomain":
                    if(domain == null || user == null || password == null)
                    {
                        return null;
                    }
                    connection = SqlAuthentication.WindowsDomain(serverInfo, database, domain, user, password);
                    break;
                case "local":
                    if (user == null || password == null)
                    {
                        return null;
                    }
                    connection = SqlAuthentication.LocalAuthentication(serverInfo, database, user, password);
                    break;
                case "entraid":
                    if (domain == null || user == null || password == null)
                    {
                        return null;
                    }
                    connection = SqlAuthentication.EntraIdAuthentication(serverInfo, database, domain, user, password);
                    break;
                case "azurelocal":
                    if (user == null || password == null)
                    {
                        return null;
                    }
                    connection = SqlAuthentication.AzureLocalAuthentication(serverInfo, database, user, password);
                    break;
                default:
                    Print.Error("Set a valid authentication type.", true);
                    return null;
            }

            return connection;
        }        
    }
}