# SCCM_SQL_Collector

PoC script to collect SCCM attack paths from a SCCM site DB. Credits to [@sanjivkawa](https://x.com/sanjivkawa) for most of the scaffolding code to allow for connection to SQL (thanks Sanj!)

## Usage

Pretty much same as sqlrecon, but you dont need to select a module. Will output a json you can load into BH directly or feed into OpenImporter

**Flags:**

- `/h:` or `/host:` :: target sql host
- `/database:` :: target db name
- `/a:` or `/auth:` :: auth mechanism (wintoken,local,winauth,azure)

**if authing with creds:**

- `/u:` or `/user:` :: username
- `/p:` or `/password:` :: password
- `/d:` or `/domain:` :: domain

**optional flags**

`/sessions` :: attempt to identify user SIDs to map user sessions from user folder data stored within USER_PROFILE_DATA
`/vaultedcredentials` :: gather vaulted credentials to map potential attack paths. No guarantees creds arent stale.


