from .settings import oauth2_settings


class BaseScopes:
    def get_all_scopes(self):
        """
        Return a dict-like object with all the scopes available in the
        system. The key should be the scope name and the value should be
        the description.

        ex: {"read": "A read scope", "write": "A write scope"}
        """
        raise NotImplementedError("")

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return a list of scopes available for the current application/request.

        TODO: add info on where and why this method is called.

        ex: ["read", "write"]
        """
        raise NotImplementedError("")

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        """
        Return a list of the default scopes for the current application/request.
        This MUST be a subset of the scopes returned by `get_available_scopes`.

        TODO: add info on where and why this method is called.

        ex: ["read"]
        """
        raise NotImplementedError("")

    def scope_is_granted(self, granted_scope, required_scope, *args, **kwargs):
        """
        Return True if having been granted ``granted_scope`` satisfies the
        requirement for ``required_scope``.

        Hierarchical scopes use a hierarchical naming convention with a ":"
        separator, e.g. ``write:photos`` / ``read:photos``. A granted scope
        satisfies a required scope when:

        * they are equal; or
        * the granted scope is a prefix of the required scope
          (e.g. ``read`` grants ``read:photos``); or
        * the granted scope's action implies the required scope's action and
          its resource path is equal to or a prefix of the required resource
          path (e.g. ``write:photos`` grants ``read:photos``).

        The action implications are configured through the
        ``SCOPE_ACTION_IMPLICATIONS`` setting (default: ``{"write": "read"}``).

        :param granted_scope: A scope string the token holder was granted.
        :param required_scope: A scope string required to access a resource.
        """
        if granted_scope == required_scope:
            return True

        granted_parts = granted_scope.split(":")
        required_parts = required_scope.split(":")

        # The granted scope is strictly more general. Prefix matching only
        # applies within a hierarchy (scopes using the ":" separator) so that
        # classic flat scopes such as "read"/"write" keep their independent
        # meaning. e.g. "read:photos" covers "read:photos:albums".
        if (
            ":" in granted_scope
            and len(granted_parts) < len(required_parts)
            and required_parts[: len(granted_parts)] == granted_parts
        ):
            return True

        implications = oauth2_settings.SCOPE_ACTION_IMPLICATIONS

        # Same-or-higher action on the same or a less specific resource path,
        # e.g. "write:photos" covers "read:photos" but bare "write" does not
        # cover bare "read".
        if (
            ":" in granted_scope
            and ":" in required_scope
            and granted_parts
            and required_parts
            and implications.get(granted_parts[0]) == required_parts[0]
        ):
            granted_path = granted_parts[1:]
            required_path = required_parts[1:]
            if len(granted_path) <= len(required_path) and required_path[: len(granted_path)] == granted_path:
                return True

        return False

    def allow_scopes(self, granted_scopes, required_scopes, *args, **kwargs):
        """
        Return True if every scope in ``required_scopes`` is covered by at
        least one scope in ``granted_scopes`` according to
        :meth:`scope_is_granted`.
        """
        if not required_scopes:
            return True

        granted_scopes = list(granted_scopes or [])
        for required_scope in required_scopes:
            if not any(self.scope_is_granted(granted, required_scope) for granted in granted_scopes):
                return False
        return True


class SettingsScopes(BaseScopes):
    def get_all_scopes(self):
        return oauth2_settings.SCOPES

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._SCOPES

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._DEFAULT_SCOPES


def get_scopes_backend():
    scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
    return scopes_class()
