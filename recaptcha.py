"""A reCAPTCHA verification library."""

from configparser import SectionProxy
from functools import wraps
from json import load
from typing import Any, Callable, Iterator, Optional, Union
from urllib.parse import urlencode, urlunparse
from urllib.request import urlopen


__all__ = ['VerificationError', 'verify', 'recaptcha']


VERIFICATION_URL = ('https', 'www.google.com', '/recaptcha/api/siteverify')
ConfigType = Union[SectionProxy, dict]
Config = Union[ConfigType, Callable[[], ConfigType]]


class VerificationError(Exception):
    """Indicates that the ReCAPTCHA validation was not successful."""

    def __init__(self, json: dict):
        """Sets the response object."""
        super().__init__(*json.get('error-codes', []))
        self.json = json


def get_url(params: dict) -> str:
    """Returns a URL with the given parameters."""

    return urlunparse((*VERIFICATION_URL, '', urlencode(params), ''))


def check_result(json: dict, *, fail_silently: bool = False) -> bool:
    """Checks the verification result."""

    if json.get('success', False):
        return True

    if fail_silently:
        return False

    raise VerificationError(json)


def verify(
        secret: str,
        response: str,
        remote_ip: Optional[str] = None,
        *,
        fail_silently: bool = False
) -> bool:
    """Verifies reCAPTCHA data."""

    params = {'secret': secret, 'response': response}

    if remote_ip is not None:
        params['remoteip'] = remote_ip

    with urlopen(get_url(params)) as http_request:
        return check_result(load(http_request), fail_silently=fail_silently)


def get_params(
        config: ConfigType,
        response_getter: Callable[[], str],
        ip_getter: Optional[Callable[[], str]]
) -> Iterator[str]:
    """Returns the verification parameters."""

    yield config.get('secret')
    yield response_getter()

    if isinstance(config, SectionProxy):
        check_ip = config.getboolean('check_ip', fallback=False)
    else:
        check_ip = config.get('check_ip', False)

    if check_ip:
        if ip_getter is None:
            raise ValueError('IP check requested, but no ip_getter provided.')

        yield ip_getter()


def recaptcha(
        config: Config,
        response_getter: Callable[[], str],
        ip_getter: Optional[Callable[[], str]] = None
) -> Callable:
    """Decorator to run a function with previous recaptcha
    check as defined in the provided configuration.
    """

    def decorator(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args, **kwargs) -> Any:
            configuration = config() if callable(config) else config
            params = get_params(configuration, response_getter, ip_getter)

            if verify(*params):
                return function(*args, **kwargs)

            raise Exception('Nasty bug in recaptcha.py. Please report.')

        return wrapper

    return decorator
