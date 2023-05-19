# httpx-negotiate-sspi

An implementation of HTTP Negotiate authentication for httpx. This module provides single-sign-on using Kerberos or NTLM using the Windows SSPI interface.

This module supports Extended Protection for Authentication (aka Channel Binding Hash), which makes it usable for services that require it, including Active Directory Federation Services.

