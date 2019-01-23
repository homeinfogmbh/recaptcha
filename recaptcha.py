"""A reCAPTCHA library."""

from json import loads

from requests import post


__all__ = ['VerificationError', 'verify']


VERIFICATION_URL = 'https://www.google.com/recaptcha/api/siteverify'


class VerificationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""


def verify(secret, response, remote_ip=None, *, url=VERIFICATION_URL):
    """Verifies reCAPTCHA data."""

    params = {'secret': secret, 'response': response}

    if remote_ip is not None:
        params['remoteip'] = remote_ip

    response = post(url, params=params)
    json = loads(response.text)

    if json.get('success', False):
        return True

    raise VerificationError()
