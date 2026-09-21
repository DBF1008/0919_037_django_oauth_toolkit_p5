from .settings import oauth2_settings


#: Separator used to express hierarchy in scope names, e.g. "read:photos:albums".
SCOPE_HIERARCHY_SEPARATOR = ":"


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

    def check_scope_covered(self, provided_scope, required_scope):
        """
        Return True if `provided_scope` covers (grants) `required_scope`.

        The default implementation only allows exact matches; backends may
        override this to implement hierarchical or wildcard scope semantics.
        """
        return provided_scope == required_scope

    def check_scopes(self, required_scopes, provided_scopes):
        """
        Return True if every scope in `required_scopes` is covered by at least
        one scope in `provided_scopes`.

        :param required_scopes: An iterable of scope names that must be granted.
        :param provided_scopes: An iterable of scope names that have been granted.
        """
        provided_scopes = list(provided_scopes)
        return all(
            any(self.check_scope_covered(provided, required) for provided in provided_scopes)
            for required in required_scopes
        )


class SettingsScopes(BaseScopes):
    """
    Scopes backend reading scopes from the ``OAUTH2_PROVIDER`` settings.

    Supports hierarchical scope definitions using ``:`` as separator,
    e.g. ``read:photos`` and ``write:photos``. When matching scopes:

    * a scope covers any of its descendants, so ``read:photos`` covers
      ``read:photos:albums`` (prefix matching);
    * a *write* scope implies the corresponding *read* scope on the same
      subtree, so ``write:photos`` also covers ``read:photos`` (and
      ``read:photos:albums``).

    The read/write action names are taken from the ``READ_SCOPE`` and
    ``WRITE_SCOPE`` settings. Scopes without the hierarchy separator keep
    the classic exact-match semantics.
    """

    def get_all_scopes(self):
        return oauth2_settings.SCOPES

    def get_available_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._SCOPES

    def get_default_scopes(self, application=None, request=None, *args, **kwargs):
        return oauth2_settings._DEFAULT_SCOPES

    def check_scope_covered(self, provided_scope, required_scope):
        if provided_scope == required_scope:
            return True

        separator = SCOPE_HIERARCHY_SEPARATOR
        # Hierarchical descent: "read:photos" covers "read:photos:albums".
        if required_scope.startswith(provided_scope + separator):
            return True

        # A write scope implies the read scope on the same (sub)tree:
        # "write:photos" covers "read:photos" and "read:photos:albums".
        read_prefix = oauth2_settings.READ_SCOPE + separator
        write_prefix = oauth2_settings.WRITE_SCOPE + separator
        if provided_scope.startswith(write_prefix) and required_scope.startswith(read_prefix):
            provided_path = provided_scope[len(write_prefix) :]
            required_path = required_scope[len(read_prefix) :]
            return required_path == provided_path or required_path.startswith(provided_path + separator)

        return False


def get_scopes_backend():
    scopes_class = oauth2_settings.SCOPES_BACKEND_CLASS
    return scopes_class()
