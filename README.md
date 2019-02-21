# recaptcha
A Google™ reCAPTCHA™ library.

## Usage:

    from recaptcha import VerificationError, verify

    try:
        verify('recaptcha_secret', 'recaptcha_response')
    except VerificationError:
        print('Veirification failed.')
    else:
        print('Verification succeeded.')

## Legal
This product is not affiliated with Google™ Inc.  
Google™ and reCAPTCHA™ are trademarks by Google™ Inc.
