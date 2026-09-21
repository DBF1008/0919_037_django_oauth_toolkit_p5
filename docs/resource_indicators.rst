.. _resource_indicators:

Resource Indicators (RFC 8707)
==============================

`RFC 8707 <https://www.rfc-editor.org/rfc/rfc8707.html>`_ introduces the
``resource`` request parameter. A *resource indicator* is an absolute URI that
identifies the resource server an access token is intended for. The
authorization server binds every issued access token to the indicated
resources (the token's *audience*), which prevents a token minted for one
resource server from being replayed against another.

Registering resources
---------------------

Each application declares the resource indicators it is allowed to request in
the new ``allowed_resources`` field of
:class:`~oauth2_provider.models.AbstractApplication`. It holds a
space-separated list of absolute URIs and can be managed through the Django
admin:

.. code-block:: python

    application.allowed_resources = (
        "https://photos.example.com/api https://calendar.example.com/api"
    )
    application.save()

Any ``resource`` parameter presented by the client MUST be registered for the
application, otherwise the server responds with the ``invalid_target`` error
defined by RFC 8707.

Authorization request
---------------------

The client adds one or more ``resource`` parameters to the authorization
request. The indicators are validated, stored on the authorization grant and
round-tripped through the consent form automatically:

.. code-block:: http

    GET /o/authorize/?response_type=code
        &client_id=...
        &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
        &scope=read
        &resource=https%3A%2F%2Fphotos.example.com%2Fapi HTTP/1.1

Token request
-------------

When exchanging the authorization code, the client MUST present the same
resource indicator(s) (RFC 8707 requires the indicator at the token endpoint
when it was used at the authorization endpoint):

.. code-block:: http

    POST /o/token/ HTTP/1.1

    grant_type=authorization_code&code=...&redirect_uri=...
    &resource=https%3A%2F%2Fphotos.example.com%2Fapi

The resulting access token is persisted with its audience in the new
``resources`` field of
:class:`~oauth2_provider.models.AbstractAccessToken`. The same mechanism works
with the ``client_credentials`` and ``refresh_token`` grant types; refreshing
a token without a ``resource`` parameter preserves the original audience.

Introspection
-------------

The :class:`~oauth2_provider.views.introspect.IntrospectTokenView` exposes the
audience through the standard ``aud`` claim as recommended by `Section 5
<https://www.rfc-editor.org/rfc/rfc8707.html#name-resource-server-processing>`_
of the RFC:

.. code-block:: json

    {
        "active": true,
        "scope": "read",
        "client_id": "...",
        "aud": ["https://photos.example.com/api"]
    }

Error responses
---------------

The following failures produce an HTTP 400 response (or an error redirect at
the authorization endpoint) with ``error=invalid_target``:

* a resource indicator is malformed (not an absolute URI, or contains a
  fragment);
* the indicator is not registered in the application's ``allowed_resources``;
* the indicator at the token endpoint was not part of the authorization
  request;
* the token endpoint omits a required indicator.

.. _hierarchical_scopes:

Hierarchical scopes
===================

Scopes can be organized as hierarchies using the ``:`` separator, for example
``read:photos`` and ``write:photos``. The scopes backend
(:class:`~oauth2_provider.scopes.SettingsScopes`) understands two relationships:

* **prefix matching** — a granted scope covers more specific scopes that share
  it as a prefix, so ``read:photos`` covers ``read:photos:albums``;
* **action implications** — granting an action on a resource implies the
  weaker actions on the same resource, so ``write:photos`` automatically
  grants ``read:photos``.

The implication table is configured with the ``SCOPE_ACTION_IMPLICATIONS``
setting, which defaults to ``{"write": "read"}``:

.. code-block:: python

    OAUTH2_PROVIDER = {
        "SCOPES": {
            "read:photos": "Read photos",
            "write:photos": "Create or update photos",
            "read:calendar": "Read the calendar",
            "write:calendar": "Modify the calendar",
        },
        "SCOPE_ACTION_IMPLICATIONS": {"write": "read"},
    }

Classic flat scopes such as plain ``read`` and ``write`` are intentionally
kept independent: the hierarchy rules only apply to scopes that contain a
``:`` separator.

Custom scopes backends can override
:meth:`~oauth2_provider.scopes.BaseScopes.scope_is_granted` and
:meth:`~oauth2_provider.scopes.BaseScopes.allow_scopes` to implement different
matching strategies.
