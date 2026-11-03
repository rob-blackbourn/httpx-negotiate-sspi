"""Authentication scheme selection without domain credentials or a live server."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from httpx_negotiate_sspi import HttpSspiAuth
from httpx_negotiate_sspi import sspi as auth_module


@pytest.mark.parametrize(
    "headers, expected",
    [
        (["Negotiate", "NTLM"], "Negotiate"),
        (["NTLM", "Negotiate"], "Negotiate"),
        (["NTLM, Negotiate"], "Negotiate"),
        (["nEgOtIaTe", "ntlm"], "Negotiate"),
        (["Negotiate"], "Negotiate"),
        (["NTLM"], "NTLM"),
        (['Basic realm="Negotiate", NTLM'], "NTLM"),
        (['Basic realm="example, NTLM", Negotiate'], "Negotiate"),
    ],
)
def test_automatic_selection(headers, expected):
    request = auth_module.Request("GET", "https://example.test")
    response = auth_module.Response(
        401, headers=[("WWW-Authenticate", value) for value in headers],
        request=request,
    )
    clientauth = SimpleNamespace(
        authenticated=False,
        authorize=lambda _: (0, [SimpleNamespace(Buffer=b"initial-token")]),
    )
    with patch.object(
        auth_module.win32security, "QuerySecurityPackageInfo",
        return_value={"MaxToken": 4096},
    ) as query_package, patch.object(
        auth_module.sspi, "ClientAuth", return_value=clientauth,
    ) as client_auth:
        flow = HttpSspiAuth(host="example.test").auth_flow(request)
        assert next(flow) is request
        outgoing = flow.send(response)
        assert outgoing.headers["Authorization"].startswith(expected + " ")
        query_package.assert_called_once_with(expected)
        assert client_auth.call_args.args[0] == expected
        flow.close()


@pytest.mark.parametrize(
    "header, message",
    [
        (None, "missing www-authenticate header"),
        ("", "missing www-authenticate header"),
        ('Basic realm="Negotiate, NTLM"', "unhandled protocol"),
        ("NotNegotiate, NotNTLM", "unhandled protocol"),
        ("Kerberos", "unhandled protocol"),
    ],
)
def test_unsupported_challenges(header, message):
    request = auth_module.Request("GET", "https://example.test")
    headers = {} if header is None else {"WWW-Authenticate": header}
    response = auth_module.Response(401, headers=headers, request=request)
    flow = HttpSspiAuth().auth_flow(request)
    next(flow)
    with pytest.raises(auth_module.HTTPError, match=message):
        flow.send(response)
