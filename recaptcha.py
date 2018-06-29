"""A reCAPTCHA library."""

from json import loads
from requests import post

__all__ = ['ValidationError', 'ReCaptcha']


VERIFICATION_URL = 'https://www.google.com/recaptcha/api/siteverify'


class ValidationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""

    pass


def query(params, url=VERIFICATION_URL, raw=False):
    """Queries the remote API."""

    response = post(url, params=params)

    if raw:
        return response

    return loads(response.text)


class ReCaptcha:
    """A ReCAPTCHA client."""

    def __init__(self, secret):
        """Sets the secret key."""
        self.secret = secret

    def gen_params(self, response, remote_ip=None):
        """Generates the query parameters."""
        params = {'secret': self.secret, 'response': response}

        if remote_ip is not None:
            params['remoteip'] = remote_ip

        return params

    def validate(self, response, remote_ip=None):
        """Verifies reCAPTCHA data."""
        params = self.gen_params(response, remote_ip=remote_ip)

        if query(params).get('success', False):
            return True

        raise ValidationError()
