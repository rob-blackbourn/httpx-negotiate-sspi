"""Authentication scheme selection without domain credentials or a live server."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from httpx_negotiate_sspi import HttpSspiAuth
from httpx_negotiate_sspi import sspi as auth_module


@pytest.mark.parametrize(
    "headers, option, expected",
    [
        (["Negotiate", "NTLM"], None, "Negotiate"),
        (["NTLM", "Negotiate"], None, "Negotiate"),
        (["NTLM, Negotiate"], None, "Negotiate"),
        (["nEgOtIaTe", "ntlm"], None, "Negotiate"),
        (["Negotiate"], None, "Negotiate"),
        (["NTLM"], None, "NTLM"),
        (['Basic realm="Negotiate", NTLM'], None, "NTLM"),
        (['Basic realm="example, NTLM", Negotiate'], None, "Negotiate"),
        (["NTLM, Negotiate"], "auto", "Negotiate"),
        (["NTLM"], "auto", "NTLM"),
        (["Negotiate", "NTLM"], "NTLM", "NTLM"),
        (["NTLM", "Negotiate"], "Negotiate", "Negotiate"),
        (["ntlm"], "NTLM", "NTLM"),
        (["negotiate"], "Negotiate", "Negotiate"),
    ],
)
def test_scheme_selection(headers, option, expected):
    """Choose only an advertised scheme, respecting an explicit override."""
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
        auth = (
            HttpSspiAuth(host="example.test") if option is None
            else HttpSspiAuth(host="example.test", scheme=option)
        )
        flow = auth.auth_flow(request)
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
    """Reject missing and unsupported authentication schemes."""
    request = auth_module.Request("GET", "https://example.test")
    headers = {} if header is None else {"WWW-Authenticate": header}
    response = auth_module.Response(401, headers=headers, request=request)
    flow = HttpSspiAuth().auth_flow(request)
    next(flow)
    with pytest.raises(auth_module.HTTPError, match=message):
        flow.send(response)


@pytest.mark.parametrize(
    "option, header",
    [
        ("Negotiate", "NTLM"),
        ("NTLM", "Negotiate"),
        ("Negotiate", 'Basic realm="Negotiate"'),
        ("NTLM", 'Basic realm="NTLM"'),
    ],
)
def test_explicit_scheme_must_be_advertised(option, header):
    """Do not initialize SSPI for an unadvertised explicit scheme."""
    request = auth_module.Request("GET", "https://example.test")
    response = auth_module.Response(
        401, headers={"WWW-Authenticate": header}, request=request,
    )
    flow = HttpSspiAuth(scheme=option).auth_flow(request)
    next(flow)
    with patch.object(auth_module.sspi, "ClientAuth") as client_auth:
        with pytest.raises(auth_module.HTTPError, match="does not advertise requested scheme"):
            flow.send(response)
        client_auth.assert_not_called()


@pytest.mark.parametrize("option", ["kerberos", "negotiate", "ntlm", "", None])
def test_invalid_scheme(option):
    """Validate the scheme at construction time."""
    with pytest.raises(ValueError, match="scheme must be"):
        HttpSspiAuth(scheme=option)


@pytest.mark.parametrize("option", ["auto", "Negotiate", "NTLM"])
@pytest.mark.parametrize("extra_challenge", [False, True])
def test_handshake_completion(option, extra_challenge):
    """Negotiate can need another challenge when SSPI selects NTLM internally."""
    scheme = "NTLM" if option == "NTLM" else "Negotiate"
    request = auth_module.Request("GET", "https://example.test")
    clientauth = SimpleNamespace(
        authenticated=False,
        authorize=lambda _: (0, [SimpleNamespace(Buffer=b"client-token")]),
    )
    with patch.object(
        auth_module.win32security, "QuerySecurityPackageInfo",
        return_value={"MaxToken": 4096},
    ), patch.object(auth_module.sspi, "ClientAuth", return_value=clientauth):
        flow = HttpSspiAuth(host="example.test", scheme=option).auth_flow(request)
        next(flow)
        flow.send(auth_module.Response(
            401, headers={"WWW-Authenticate": "NTLM, Negotiate"}, request=request,
        ))
        if extra_challenge:
            outgoing = flow.send(auth_module.Response(
                401, headers={"WWW-Authenticate": scheme + " c2VydmVyLXRva2Vu"},
                request=request,
            ))
            assert outgoing.headers["Authorization"].startswith(scheme + " ")
        with pytest.raises(StopIteration):
            flow.send(auth_module.Response(200, request=request))
