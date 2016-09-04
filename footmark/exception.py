
"""
Exception classes - Subclassing allows you to check for specific errors
"""

import footmark

import json

StandardError = Exception

class FootmarkClientError(StandardError):
    """
    General Footmark Client error (error accessing AWS)
    """
    def __init__(self, reason, *args):
        super(FootmarkClientError, self).__init__(reason, *args)
        self.reason = reason

    def __repr__(self):
        return 'FootmarkClientError: %s' % self.reason

    def __str__(self):
        return 'FootmarkClientError: %s' % self.reason

class FootmarkServerError(StandardError):
    def __init__(self, status, body=None, *args):
        super(FootmarkServerError, self).__init__(status, body, *args)
        self.status = status
        self.body = body or ''
        self.request_id = None
        self.error_code = None
        self.message = ''
        self.host_id = None
        if isinstance(self.body, bytes):
            try:
                self.body = self.body.decode('utf-8')
            except UnicodeDecodeError:
                footmark.log.debug('Unable to decode body from bytes!')

        # Attempt to parse the error response. If body isn't present,
        # then just ignore the error response.
        try:
            parsed = json.loads(self.body)

            if 'RequestId' in parsed:
                self.request_id = parsed['RequestId']
            if 'Code' in parsed:
                self.error_code = parsed['Code']
            if 'Message' in parsed:
                self.message = parsed['Message']
            if 'HostId' in parsed:
                self.host_id = parsed['HostId']

        except (TypeError, ValueError):
            # Remove unparsable message body so we don't include garbage
            # in exception. But first, save self.body in self.error_message
            # because occasionally we get error messages from Eucalyptus
            # that are just text strings that we want to preserve.
            self.message = self.body
            self.body = None

    def __getattr__(self, name):
        if name == 'error_message':
            return self.message
        if name == 'code':
            return self.error_code
        raise AttributeError

    def __setattr__(self, name, value):
        if name == 'error_message':
            self.message = value
        else:
            super(FootmarkServerError, self).__setattr__(name, value)

    def __repr__(self):
        return '%s: %s %s\n%s' % (self.__class__.__name__,
                                  self.status, self.message, self.body)

    def __str__(self):
        return '%s: %s %s\n%s' % (self.__class__.__name__,
                                  self.status, self.message, self.body)

class ECSResponseError(FootmarkServerError):
    """
    Error in response from ECS.
    """
    def __init__(self, status, body=None):
        super(ECSResponseError, self).__init__(status, body)

class JSONResponseError(FootmarkServerError):
    """
    This exception expects the fully parsed and decoded JSON response
    body to be passed as the body parameter.

    :ivar status: The HTTP status code.
    :ivar reason: The HTTP reason message.
    :ivar body: The Python dict that represents the decoded JSON
        response body.
    :ivar error_message: The full description of the AWS error encountered.
    :ivar error_code: A short string that identifies the AWS error
        (e.g. ConditionalCheckFailedException)
    """
    def __init__(self, status, reason, body=None, *args):
        self.status = status
        self.body = body
        if self.body:
            self.error_message = self.body.get('message', None)
            self.error_code = self.body.get('__type', None)
            if self.error_code:
                self.error_code = self.error_code.split('#')[-1]


