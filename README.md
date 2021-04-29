# recaptcha
A Google™ reCAPTCHA™ library.

## Usage:

```python
from recaptcha import VerificationError, verify

try:
    verify('recaptcha_secret', 'recaptcha_response')
except VerificationError:
    print('Verification failed.')
else:
    print('Verification succeeded.')
```

or:

```python
from recaptcha import VerificationError, verify

if verify('recaptcha_secret', 'recaptcha_response', fail_silently=True):
    print('Verification succeeded.')
else:
    print('Verification failed.')
```

## Legal
This product is not affiliated with Google™ Inc.  
Google™ and reCAPTCHA™ are trademarks by Google™ Inc.
