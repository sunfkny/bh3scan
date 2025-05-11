class Bh3ScanBaseError(Exception):
    pass


class RequestError(Bh3ScanBaseError):
    pass


class InvalidTicketError(Bh3ScanBaseError):
    pass


class QRCodeExpiredError(RequestError):
    pass


class AccessTokenExpiredError(Bh3ScanBaseError):
    pass
