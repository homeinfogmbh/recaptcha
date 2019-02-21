"""A reCAPTCHA verification library."""

from json import loads
from urllib.request import urlopen
from urllib.parse import urlencode, ParseResult


__all__ = ['VerificationError', 'verify']


VERIFICATION_URL = ('https', 'www.google.com', '/recaptcha/api/siteverify')


class VerificationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""

    def __init__(self, json):
        """Sets the response object."""
        super().__init__()
        self.json = json


def verify(secret, response, remote_ip=None, *, url=VERIFICATION_URL):
    """Verifies reCAPTCHA data."""

    params = {'secret': secret, 'response': response}

    if remote_ip is not None:
        params['remoteip'] = remote_ip

    url = ParseResult(*VERIFICATION_URL, '', urlencode(params), '').geturl()

    with urlopen(url) as request:
        json = loads(request.read())

    if json.get('success', False):
        return True

    raise VerificationError(json)
