"""SSPI Authentication"""

import base64
import hashlib
import logging
import socket
import struct
from typing import Generator, Optional, Tuple

import pywintypes
import sspi
import sspicon
import win32security

from httpx import Auth, Request, Response, HTTPError

LOGGER = logging.getLogger(__name__)


class HttpSspiAuth(Auth):
    """Authentication for SSPI"""

    _auth_info: Optional[Tuple[str, str, str]] = None
    _service: str = 'HTTP'
    _host: Optional[str] = None
    _delegate: bool = False

    def __init__(
            self,
            username: Optional[str] = None,
            password: Optional[str] = None,
            domain: Optional[str] = None,
            service: Optional[str] = None,
            host: Optional[str] = None,
            delegate: bool = False
    ) -> None:
        """Create a new Negotiate auth handler.

        If username and password are not specified, the user's default credentials are used.
        This allows for single-sign-on to domain resources if the user is currently logged on
        with a domain account.

        Args:
            username (Optional[str], optional): Username. Defaults to None.
            password (Optional[str], optional): Password. Defaults to None.
            domain (Optional[str], optional): NT domain name, '.' for local account. Defaults to None.
            service (Optional[str], optional): Kerberos service type for remote service principal name. Defaults to None.
            host (Optional[str], optional): Host name for service principal name. Defaults to None.
            delegate (bool, optional): Indicates the user's credentials are to be delegated to the server. Defaults to False.
        """
        if domain is None:
            domain = '.'

        if username is not None and password is not None:
            self._auth_info = (username, domain, password)

        if service is not None:
            self._service = service

        if host is not None:
            self._host = host

        self._delegate = delegate

    def auth_flow(
            self,
            request: Request
    ) -> Generator[Request, Response, None]:
        response = yield request
        if response.status_code == 401:
            yield from self._handle_response(response)

    def _handle_response(
            self,
            response: Response
    ) -> Generator[Request, Response, None]:
        if 'Authorization' in response.request.headers:
            return

        auth_header = response.headers.get("www-authenticate")
        if not auth_header:
            raise HTTPError("missing www-authenticate header")

        auth_header = auth_header.lower()
        if 'ntlm' in auth_header:
            scheme = 'NTLM'
        elif 'negotiate' in auth_header:
            scheme = 'Negotiate'
        else:
            raise HTTPError('unhandled protocol')

        if self._host is None:
            self._host = response.request.url.host
            try:
                info = socket.getaddrinfo(
                    self._host, None,
                    0, 0, 0,
                    socket.AI_CANONNAME
                )
                self._host = info[0][3]
            except socket.gaierror as error:
                LOGGER.info(
                    'Skipping canonicalization of name %s due to error: %s',
                    self._host,
                    error
                )

        targetspn = f"{self._service}/{self._host}"

        # We request mutual auth by default.
        scflags = sspicon.ISC_REQ_MUTUAL_AUTH

        if self._delegate:
            scflags |= sspicon.ISC_REQ_DELEGATE

        # Set up SSPI connection structure.
        pkg_info = win32security.QuerySecurityPackageInfo(scheme)
        clientauth = sspi.ClientAuth(
            scheme,
            targetspn=targetspn,
            auth_info=self._auth_info,
            scflags=scflags,
            datarep=sspicon.SECURITY_NETWORK_DREP
        )
        sec_buffer = win32security.PySecBufferDescType()

        # Channel Binding Hash (aka Extended Protection for Authentication)
        # If this is a SSL connection, we need to hash the peer certificate, prepend the RFC5929 channel binding type,
        # and stuff it into a SEC_CHANNEL_BINDINGS structure.
        # This should be sent along in the initial handshake or Kerberos auth will fail.
        network_stream = response.extensions.get("network_stream")
        peercert = (
            None if network_stream is None
            else network_stream.get_extra_info('peercert')
        )
        if peercert is not None:
            md = hashlib.sha256()
            md.update(peercert)
            appdata = 'tls-server-end-point:'.encode('ASCII') + md.digest()
            cbtbuf = win32security.PySecBufferType(
                pkg_info['MaxToken'],
                sspicon.SECBUFFER_CHANNEL_BINDINGS
            )
            cbtbuf.Buffer = struct.pack(
                f'LLLLLLLL{len(appdata)}s',
                0, 0, 0, 0, 0, 0, len(appdata), 32, appdata
            )
            sec_buffer.append(cbtbuf)

        # this is important for some web applications that store
        # authentication-related info in cookies
        set_cookie = response.headers.get('set-cookie')
        if set_cookie is not None:
            response.request.headers['Cookie'] = set_cookie

        # Send initial challenge auth header
        try:
            err, auth = clientauth.authorize(sec_buffer)
            data = base64.b64encode(auth[0].Buffer).decode('ASCII')
            response.request.headers['Authorization'] = f'{scheme} {data}'
            LOGGER.debug(
                'Sending Initial Context Token - error=%s authenticated=%s',
                err,
                clientauth.authenticated
            )
        except pywintypes.error as error:
            LOGGER.debug(
                'Error calling %s: %s',
                error[1],
                error[2],
                exc_info=error
            )
            return

        response2 = yield response.request

        # Should get another 401 if we are doing challenge-response (NTLM)
        if response2.status_code != 401:
            # Kerberos may have succeeded; if so, finalize our auth context
            final = response2.headers.get('WWW-Authenticate')
            if final is not None:
                try:
                    # Sometimes Windows seems to forget to prepend 'Negotiate' to the success response,
                    # and we get just a bare chunk of base64 token. Not sure why.
                    final = final.replace(scheme, '', 1).lstrip()
                    tokenbuf = win32security.PySecBufferType(
                        pkg_info['MaxToken'],
                        sspicon.SECBUFFER_TOKEN
                    )
                    tokenbuf.Buffer = base64.b64decode(final.encode('ASCII'))
                    sec_buffer.append(tokenbuf)
                    err, auth = clientauth.authorize(sec_buffer)
                    LOGGER.debug(
                        'Kerberos Authentication succeeded - error=%s authenticated=%s',
                        err,
                        clientauth.authenticated
                    )
                except TypeError:
                    pass

            # Regardless of whether or not we finalized our auth context,
            # without a 401 we've got nothing to do. Update the history and return.
            response2.history.append(response)
            return

        # Keep passing the cookies along
        set_cookie = response2.headers.get('set-cookie')
        if set_cookie is not None:
            response2.request.headers['Cookie'] = set_cookie

        # Extract challenge message from server
        challenge = [
            val[len(scheme)+1:]
            for val in response2.headers.get('WWW-Authenticate', '').split(', ')
            if scheme in val
        ]
        if len(challenge) != 1:
            raise HTTPError(
                f'Did not get exactly one {scheme} challenge from server'
            )

        # Add challenge to security buffer
        tokenbuf = win32security.PySecBufferType(
            pkg_info['MaxToken'],
            sspicon.SECBUFFER_TOKEN
        )
        tokenbuf.Buffer = base64.b64decode(challenge[0])
        sec_buffer.append(tokenbuf)
        LOGGER.debug('Got Challenge Token (NTLM)')

        # Perform next authorization step
        try:
            err, auth = clientauth.authorize(sec_buffer)
            data = base64.b64encode(auth[0].Buffer).decode('ASCII')
            response2.request.headers['Authorization'] = f'{scheme} {data}'
            LOGGER.debug(
                'Sending Response - error=%s authenticated=%s',
                err,
                clientauth.authenticated
            )
        except pywintypes.error as error:
            LOGGER.debug(
                'Error calling %s: %s',
                error[1],
                error[2],
                exc_info=error
            )
            return

        response3 = yield response2.request

        # Update the history and return
        response3.history.append(response)
        response3.history.append(response2)

        return
