"""A reCAPTCHA verification library."""

from json import load
from typing import Optional
from urllib.parse import urlencode, urlunparse
from urllib.request import urlopen


__all__ = ['VerificationError', 'verify']


VERIFICATION_URL = ('https', 'www.google.com', '/recaptcha/api/siteverify')


class VerificationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""

    def __init__(self, json):
        """Sets the response object."""
        super().__init__()
        self.json = json


def verify(secret: str, response: str,
           remote_ip: Optional[str] = None) -> bool:
    """Verifies reCAPTCHA data."""

    params = {'secret': secret, 'response': response}

    if remote_ip is not None:
        params['remoteip'] = remote_ip

    url = urlunparse((*VERIFICATION_URL, '', urlencode(params), ''))

    with urlopen(url) as request:
        json = load(request)

    if json.get('success', False):
        return True

    raise VerificationError(json)
