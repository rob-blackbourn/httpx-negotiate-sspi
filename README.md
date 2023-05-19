# httpx-negotiate-sspi

This is a port of
[requests-negotiate-sspi](https://github.com/brandond/requests-negotiate-sspi)
for [httpx](https://github.com/encode/httpx).

The implmentation stays close to the original, in an attempt to make any fixes
or updates more straighforward.

The following is taken from the README of the original package with changes to
reflect httpx.

---

An implementation of HTTP Negotiate authentication for Requests. This
module provides single-sign-on using Kerberos or NTLM using the Windows
SSPI interface.

This module supports Extended Protection for Authentication (aka Channel
Binding Hash), which makes it usable for services that require it,
including Active Directory Federation Services.

## Usage

```python
import httpx
from httpx_negotiate_sspi import HttpSspiAuth

r = httpx.get('https://iis.contoso.com', auth=HttpSspiAuth())
```

## Options

  - `username`: Username.  
    Default: None

  - `password`: Password.  
    Default: None

  - `domain`: NT Domain name.  
    Default: '.' for local account.

  - `service`: Kerberos Service type for remote Service Principal
    Name.  
    Default: 'HTTP'

  - `host`: Host name for Service Principal Name.  
    Default: Extracted from request URI

  - `delegate`: Indicates that the user's credentials are to be delegated to the server.
    Default: False


If username and password are not specified, the user's default
credentials are used. This allows for single-sign-on to domain resources
if the user is currently logged on with a domain account.