"""
RFC 8707 - Resource Indicators for OAuth 2.0

https://www.rfc-editor.org/rfc/rfc8707.html

A resource indicator is an absolute URI that identifies the resource(s) an
access token will be allowed to access. Clients send one or more ``resource``
request parameters at the authorization endpoint and/or the token endpoint;
the authorization server binds the resulting access token to the indicated
resources (the token's audience).
"""

from urllib.parse import urlparse

from oauthlib.oauth2.rfc6749.errors import OAuth2Error


class InvalidTargetError(OAuth2Error):
    """
    The requested resource indicator is invalid, unknown, or malformed.

    https://www.rfc-editor.org/rfc/rfc8707.html#section-2.2
    """

    error = "invalid_target"
    status_code = 400


def resources_to_str(resources):
    """
    Serialize a list of resource indicator URIs into a space-separated string
    for storage in text fields.
    """
    return " ".join(resources)


def resources_from_str(value):
    """
    Parse a space-separated list of resource indicator URIs.
    """
    if not value:
        return []
    return value.split()


def parse_resources(querydict):
    """
    Extract the (possibly repeated) ``resource`` parameters from a
    Django ``QueryDict`` (request.GET / request.POST), preserving order and
    de-duplicating values.
    """
    resources = []
    for resource in querydict.getlist("resource"):
        if resource and resource not in resources:
            resources.append(resource)
    return resources


def validate_resource_indicator(resource):
    """
    Validate a single resource indicator as required by RFC 8707:

    * it MUST be an absolute URI; and
    * it MUST NOT contain a fragment component.

    Raises :class:`InvalidTargetError` when the indicator is not acceptable.
    """
    parsed = urlparse(resource)
    if not parsed.scheme or not parsed.netloc or parsed.fragment:
        raise InvalidTargetError(description=f"The resource indicator {resource!r} is malformed.")
