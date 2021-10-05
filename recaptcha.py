"""A reCAPTCHA verification library."""

from configparser import ConfigParser
from functools import wraps
from json import load
from typing import Any, Callable, Optional
from urllib.parse import urlencode, urlunparse
from urllib.request import urlopen


__all__ = ['VerificationError', 'verify', 'recaptcha']


VERIFICATION_URL = ('https', 'www.google.com', '/recaptcha/api/siteverify')


class VerificationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""

    def __init__(self, json: dict):
        """Sets the response object."""
        super().__init__()
        self.json = json


def verify(secret: str, response: str, remote_ip: Optional[str] = None, *,
           fail_silently: bool = False) -> bool:
    """Verifies reCAPTCHA data."""

    params = {'secret': secret, 'response': response}

    if remote_ip is not None:
        params['remoteip'] = remote_ip

    url = urlunparse((*VERIFICATION_URL, '', urlencode(params), ''))

    with urlopen(url) as http_request:
        json = load(http_request)

    if json.get('success', False):
        return True

    if fail_silently:
        return False

    raise VerificationError(json)


def recaptcha(config: ConfigParser, *, section: str = 'recaptcha') -> Callable:
    """Decorator to run a function with previous recaptcha
    check as defined in the provided configuration.
    """

    from flask import request   # pylint: disable=C0415

    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args, **kwargs) -> Any:
            secret = config.get(section, 'secret')
            check_ip = config.get(section, 'check_ip', fallback=False)
            remote_ip = request.remote_addr if check_ip else None
            json_key = config.get(section, 'json_key', fallback='response')
            response = request.json.get(json_key)

            if verify(secret, response, remote_ip):
                return function(*args, **kwargs)

            raise VerificationError(None)

        return wrapper

    return decorator
