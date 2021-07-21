"""A reCAPTCHA verification library."""

from functools import wraps
from json import load
from logging import warning
from typing import Any, Callable, Optional, Union
from urllib.parse import urlencode, urlunparse
from urllib.request import urlopen

try:
    from flask import request
except ImportError:
    warning('flask not installed. @recaptcha() not available.')


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


def recaptcha(secret: Union[str, Callable[[], str]], *,
              accessor: lambda request: request.json.get('response'),
              check_ip: bool = False) -> Callable:
    """Decorator to run a function with previous recaptcha check."""

    def decorator(function: Callable) -> Callable:
        @wraps(function)
        def wrapper(*args, **kwargs) -> Any:    # pylint: disable=R1710
            remote_ip = request.remote_addr if check_ip else None
            key = secret() if callable(secret) else secret

            if verify(key, accessor(request), remote_ip):
                return function(*args, **kwargs)

        return wrapper

    return decorator
