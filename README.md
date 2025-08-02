# SCCM_SQL_Collector

PoC script to collect SCCM attack paths from a SCCM site DB. Credits to [@sanjivkawa](https://x.com/sanjivkawa) for SQLRecon, which is where most of the scaffolding code to allow for connecting to SQL came from (thanks Sanj!)

## Usage

Pretty much same as sqlrecon, but you dont need to select a module. Will output a json you can load into BH directly or feed into OpenImporter

**Flags:**

- `/h:` or `/host:` :: target sql host
- `/database:` :: target db name
- `/a:` or `/auth:` :: auth mechanism (wintoken,local,winauth,entraid,azurelocal)

**if authing with creds:**

- `/u:` or `/user:` :: username
- `/p:` or `/password:` :: password
- `/d:` or `/domain:` :: domain

**optional flags**

- `/port` :: set a non-default port for your db connection
- `/sessions` :: attempt to identify user SIDs to map user sessions from user folder data stored within USER_PROFILE_DATA. If this arg is not passed in, session data will be generated from last logged on user and will have a ToValidate property appended that can be used with OpenImporter to map usernames to SIDs within the Bloodhound database.
- `/vaultedcredentials` :: gather vaulted credentials to map potential attack paths. No guarantees creds arent stale. Identified vaulted credential takeover edges will have a ToValidate property set that can be used with OpenImporter to map usernames to SIDs within the Bloodhound database.


