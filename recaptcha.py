"""A reCAPTCHA library"""

from json import loads
from requests import post

from fancylog import LoggingClass

__all__ = ['ReCaptcha']


class ReCaptcha(LoggingClass):
    """Google reCAPTCHA client"""

    VERIFICATION_URL = 'https://www.google.com/recaptcha/api/siteverify'

    def __init__(self, secret, logger=None):
        """Sets basic reCAPTCHA data"""
        super().__init__(logger=logger)
        self.secret = secret

    def validate(self, response, remote_ip=None):
        """Verifies reCAPTCHA data"""
        params = {'secret': self.secret, 'response': response}

        if remote_ip is not None:
            params['remoteip'] = remote_ip

        reply = post(self.VERIFICATION_URL, params=params)

        try:
            dictionary = loads(reply.text)
        except ValueError:
            self.logger.error('Invalid reCAPTCHA response: {}'.format(
                reply.text))
            return False
        else:
            return dictionary.get('success', False)
