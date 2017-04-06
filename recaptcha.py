"""A reCAPTCHA library"""

from json import loads
from requests import post

from fancylog import LoggingClass

__all__ = ['ReCaptcha']


class ReCaptcha(LoggingClass):
    """Google reCAPTCHA client"""

    VERIFICATION_URL = 'https://www.google.com/recaptcha/api/siteverify'

    def __init__(self, secret, response, remote_ip=None, logger=None):
        """Sets basic reCAPTCHA data"""
        super().__init__(logger=logger)
        self.secret = secret
        self.response = response
        self.remote_ip = remote_ip
        self.reply = None

    def __bool__(self):
        """Verifies reCAPTCHA data"""
        self.query()
        return True if self.verify() else False

    @property
    def _params(self):
        """Returns the parameters dictionary for requests"""
        params = {
            'secret': self.secret,
            'response': self.response}

        if self.remote_ip is not None:
            params['remoteip'] = self.remote_ip

        return params

    @property
    def dict(self):
        """Returns the response dictionary"""
        try:
            return loads(self.reply.text)
        except TypeError:
            self.logger.error('No response available yet')
        except ValueError:
            self.logger.error('Invalid reCAPTCHA response: {}'.format(
                self.reply.text))

        return {}

    def query(self, force=False):
        """Calls the web API"""
        if self.reply is None or force:
            self.reply = post(self.VERIFICATION_URL, params=self._params)

    def verify(self):
        """Verifies reCAPTCHA data"""
        return self.dict.get('success', False)
