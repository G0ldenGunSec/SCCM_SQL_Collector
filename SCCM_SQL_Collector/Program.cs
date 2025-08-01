using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;

namespace SCCM_SQL_Collector
{
    internal class Program
    {
        private static bool vaultedCredentials = false;
        private static bool sessions = false;
        static void Main(string[] args)
        {
            Dictionary<string,string> parsedArgs = ParseArgs(args);
            if(!ValidateRequiredArgs(parsedArgs))
            {
                Print.Error("Missing required args, ensure you provide the target host, database, and authentication type", true);
                return;
            }
            if(parsedArgs.ContainsKey("vaultedcredentials") || parsedArgs.ContainsKey("vc"))
            {
                vaultedCredentials = true;
            }

            if(parsedArgs.ContainsKey("sessions") || parsedArgs.ContainsKey("s"))
            {
                sessions = true;
            }   

            SqlConnection connection = SQLConnectionFactory.CreateSqlConnectionObject(parsedArgs);

            if(connection == null)
            {
                Print.Error("Unable to create a SQL connection object. Ensure you provided all required args for your selected authentication type", true);
                return;
            }
            CollectBloodhoundData(connection);
        }

        private static Dictionary<string,string> ParseArgs(string[] args)
        {
            Dictionary<string, string> ParsedArgs = new Dictionary<string, string>();
            foreach(string arg in args)
            {
                if (arg[0] != '/')
                {
                    continue;
                }
                string key = arg.Substring(1);
                string value = "";
                //logic to check for flags (no value appended)
                if (arg.IndexOf(':') > -1)
                {
                    key = arg.Substring(1, arg.IndexOf(':') - 1);
                    value = arg.Substring(arg.IndexOf(':') + 1);
                }

                key = key.ToLower();
                ParsedArgs.Add(key, value);
            }
            return ParsedArgs;
        }
        private static bool ValidateRequiredArgs(Dictionary<string,string> parsedArgs)
        {
            bool passed = true;
            if (!parsedArgs.ContainsKey("h") && !parsedArgs.ContainsKey("host"))
            {
                passed = false;
            }
            else if(!parsedArgs.ContainsKey("database"))
            {
                passed = false;
            }
            else if (!parsedArgs.ContainsKey("a") && !parsedArgs.ContainsKey("auth"))
            {
                passed = false;
            }

            return passed;
        }

        private static void CollectBloodhoundData(SqlConnection con)
        {
            var data = new SCCMGraphData();
            var systemMap = new Dictionary<int, (string MachineSID, string LastUsername)>();

            Print.Status("Collecting SCCM clients from the System_DISC table", true);
            using (var cmd = new SqlCommand("SELECT itemKey, sid0, user_name0,user_domain0 FROM System_DISC WHERE sid0 IS NOT NULL AND user_name0 IS NOT NULL", con))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    int itemKey = reader.GetInt32(0);
                    string machineSid = reader.GetString(1);
                    string username = reader.GetString(2);
                    string domain = reader.IsDBNull(3) ? null : reader.GetString(3);
                    systemMap[itemKey] = (machineSid, username);
                    data.Clients[machineSid] = $"Host_{itemKey}";

                    if(!sessions)
                    {
                        //If not explicitly grabbing user SIDs via logon session lookup, we can also map via username + domain lookup against previously collected BH data
                        if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(username))
                        {
                            string identity = $"{domain}\\{username}";
                            data.Logons.Add((identity, machineSid));
                        }
                    }
                }
            }

            if(sessions)
            {
                Print.Status("Collecting logon sessions from the USER_PROFILE_DATA table", true);
                using (var cmd = new SqlCommand("SELECT SID00, MachineID, LocalPath00 FROM USER_PROFILE_DATA WHERE Special00 = 0 and SID00 IS NOT NULL AND LocalPath00 IS NOT NULL", con))
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        string userSid = reader.GetString(0);
                        int machineId = reader.GetInt32(1);
                        string localPath = reader.GetString(2);

                        if (!systemMap.TryGetValue(machineId, out var entry))
                            continue;

                        string extractedUser = localPath.Split('\\').Last();
                        if (entry.LastUsername != null && entry.LastUsername.EndsWith(extractedUser, StringComparison.OrdinalIgnoreCase))
                        {
                            data.Logons.Add((userSid, entry.MachineSID));
                        }
                    }
                }
            }

            if(vaultedCredentials)
            {
                Print.Status("Collecting vaulted credentials from the vSMS_SC_UserAccount view", true);
                {
                    using (var cmd = new SqlCommand("SELECT UserName FROM vSMS_SC_UserAccount", con))
                    {
                        using (var reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                string domainUsername = reader.GetString(0);
                                if (domainUsername.IndexOf('\\') == -1)
                                {
                                    continue;
                                }
                                data.VaultedCredentials.Add(domainUsername);
                            }
                        }
                    }
                }
            }

            Print.Status("Collecting SCCM admins from the RBAC_Admins table",true);
            var adminIdToSid = new Dictionary<int, string>();
            using (var cmd = new SqlCommand("SELECT AdminID, AdminSID FROM RBAC_Admins", con))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    int adminId = reader.GetInt32(0);
                    byte[] sidBytes = (byte[])reader[1];
                    string sidStr = new System.Security.Principal.SecurityIdentifier(sidBytes, 0).ToString();
                    adminIdToSid[adminId] = sidStr;
                }
            }

            Print.Status("Collecting SCCM admin roles with code exec capabilities from the v_SecuredScopePermissions view", true);
            using (var cmd = new SqlCommand("SELECT AdminID, RoleName FROM v_SecuredScopePermissions WHERE RoleName IN ('Full Administrator', 'Application Administrator')", con))
            using (var reader = cmd.ExecuteReader())
            {
                while (reader.Read())
                {
                    int adminId = reader.GetInt32(0);
                    string roleName = reader.GetString(1);
                    if (adminIdToSid.TryGetValue(adminId, out var sid))
                    {
                        data.AdminRoles.Add((sid, roleName));
                    }
                }
            }

            Print.Status("Collecting SCCM server info from the vSMSData view", true);
            using (var cmd = new SqlCommand("SELECT SiteSid, SMSProviderServer FROM vSMSData", con))
            using (var reader = cmd.ExecuteReader())
            {
                if (reader.Read())
                {
                    data.SiteSid = reader.IsDBNull(0) ? null : reader.GetString(0);
                    data.SmsProviderHostname = reader.IsDBNull(1) ? null : reader.GetString(1);
                }
            }

            //output collected data to JSON
            Print.Status("Finished collecting data, generating JSON output", true);

            var graph = new
            {
                nodes = new[]
    {
            new
            {
                id = "SCCM_APP_" + data.SmsProviderHostname,
                kinds = new[] { "SCCM_SMS_Application" },
                properties = new
                {
                    name = "SCCM_APP_" + data.SmsProviderHostname
                }
            }
        },
                edges = new List<object>()
            };

            string sccmAppNodeId = "SCCM_APP_" + data.SmsProviderHostname;

            //SCCM admins -> SCCM app
            foreach (var adminRole in data.AdminRoles)
            {
                graph.edges.Add(new
                {
                    kind = $"sccm_{adminRole.Role.Replace(' ','_')}",
                    start = new { value = adminRole.AdminSid },
                    end = new { value = sccmAppNodeId },
                    properties = new { }
                });
            }

            //Site server -> SCCM app
            graph.edges.Add(new
            {
                kind = "sccm_ServerTrust",
                start = new { value = data.SiteSid },
                end = new { value = sccmAppNodeId },
                properties = new { }
            });

            //SCCM app -> SCCM clients
            foreach (var client in data.Clients)
            {
                graph.edges.Add(new
                {
                    kind = "sccm_Exec",
                    start = new { value = sccmAppNodeId },
                    end = new { value = client.Key },
                    properties = new { }
                });
            }

            //clients -> users
            foreach (var logon in data.Logons)
            {
                graph.edges.Add(CreateEdgeWithValidationSupport("sccm_logonSession", logon.HostSid, logon.UserSid));
            }

            //site server -> vaulted credentials
            foreach (var account in data.VaultedCredentials)
            {
                graph.edges.Add(CreateEdgeWithValidationSupport("sccm_VaultedCredential", data.SiteSid, account));
            }

            var finalObject = new { graph };

            string jsonOutput = JsonConvert.SerializeObject(finalObject, Formatting.Indented);
            File.WriteAllText("sccm_graph.json", jsonOutput);
            Print.Success("Wrote SCCM graph data to sccm_graph.json", true);
        }

        private static Dictionary<string, object> CreateEdgeWithValidationSupport(string kind, string startId, string endId)
        {
            var edge = new Dictionary<string, object>
            {
                ["kind"] = kind,
                ["start"] = new { value = startId },
                ["end"] = new { value = endId },
                ["properties"] = new { }
            };

            var toValidate = new Dictionary<string, List<object>>();

            if (startId.Contains("\\"))
            {
                var parts = startId.Split('\\');
                if (parts.Length == 2)
                {
                    toValidate["start"] = new List<object>
            {
                new {
                    bhAttrib = "samaccountname",
                    attribValue = parts[1],
                    partialMatch = false
                },
                new {
                    bhAttrib = "domain",
                    attribValue = parts[0],
                    partialMatch = true
                }
            };
                }
            }

            if (endId.Contains("\\"))
            {
                var parts = endId.Split('\\');
                if (parts.Length == 2)
                {
                    toValidate["end"] = new List<object>
            {
                new {
                    bhAttrib = "samaccountname",
                    attribValue = parts[1],
                    partialMatch = false
                },
                new {
                    bhAttrib = "domain",
                    attribValue = parts[0],
                    partialMatch = true
                }
            };
                }
            }

            if (toValidate.Count > 0)
            {
                edge["toValidate"] = toValidate;
            }

            return edge;
        }

    }

    public class SCCMGraphData
    {
        public string SiteSid { get; set; }
        public string SmsProviderHostname { get; set; }
        public Dictionary<string, string> Clients = new Dictionary<string, string>(); // MachineSID -> Hostname
        public List<(string UserSid, string HostSid)> Logons = new List<(string UserSid, string HostSid)>();
        public List<(string AdminSid, string Role)> AdminRoles = new List<(string AdminSid, string Role)>();
        public List<string> VaultedCredentials = new List<string>();
    }
}
