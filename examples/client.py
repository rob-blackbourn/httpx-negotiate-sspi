from typing import Literal, TypedDict, cast

import httpx2
from httpx_negotiate_sspi import HttpSspiAuth


class Claim(TypedDict):
    type: str
    value: str


class WhoAmI(TypedDict):
    name: str
    isAuthenticated: bool
    authenticationType: Literal['Negotiate', 'NTLM']
    claims: list[Claim]


def main() -> None:
    r = httpx2.get('http://localhost:5200/whoami', auth=HttpSspiAuth())
    print(r.status_code)
    whoami = cast(WhoAmI, r.json())
    print(f"name: {whoami['name']} ({whoami['authenticationType']})")


if __name__ == "__main__":
    main()
