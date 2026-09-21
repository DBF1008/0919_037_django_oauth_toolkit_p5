import datetime

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from django.utils import timezone

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.scopes import SettingsScopes, get_scopes_backend
from oauth2_provider.views import ScopedProtectedResourceView

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

HIERARCHICAL_SCOPE_SETTINGS = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "read:photos": "Read photos",
        "write:photos": "Write photos",
        "read:photos:albums": "Read photo albums",
    },
}


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(HIERARCHICAL_SCOPE_SETTINGS)
class TestHierarchicalScopeMatching(TestCase):
    def setUp(self):
        self.scopes_backend = get_scopes_backend()
        assert isinstance(self.scopes_backend, SettingsScopes)

    def test_exact_match(self):
        self.assertTrue(self.scopes_backend.check_scope_covered("read:photos", "read:photos"))
        self.assertTrue(self.scopes_backend.check_scopes(["read:photos"], ["read:photos"]))

    def test_prefix_match_covers_descendants(self):
        self.assertTrue(self.scopes_backend.check_scope_covered("read:photos", "read:photos:albums"))
        self.assertTrue(self.scopes_backend.check_scopes(["read:photos:albums"], ["read:photos"]))

    def test_write_implies_read(self):
        self.assertTrue(self.scopes_backend.check_scope_covered("write:photos", "read:photos"))
        self.assertTrue(self.scopes_backend.check_scopes(["read:photos"], ["write:photos"]))

    def test_write_implies_read_on_descendants(self):
        self.assertTrue(self.scopes_backend.check_scope_covered("write:photos", "read:photos:albums"))
        self.assertTrue(self.scopes_backend.check_scopes(["read:photos:albums"], ["write:photos"]))

    def test_read_does_not_imply_write(self):
        self.assertFalse(self.scopes_backend.check_scope_covered("read:photos", "write:photos"))
        self.assertFalse(self.scopes_backend.check_scopes(["write:photos"], ["read:photos"]))

    def test_sibling_branches_do_not_match(self):
        self.assertFalse(self.scopes_backend.check_scope_covered("read:photos", "read:videos"))
        self.assertFalse(self.scopes_backend.check_scope_covered("write:photos", "read:videos"))

    def test_partial_prefix_does_not_match(self):
        # "read:photo" is not a hierarchy ancestor of "read:photos"
        self.assertFalse(self.scopes_backend.check_scope_covered("read:photo", "read:photos"))

    def test_plain_scopes_keep_exact_semantics(self):
        # Without the hierarchy separator, "write" does not imply "read"
        self.assertFalse(self.scopes_backend.check_scope_covered("write", "read"))
        self.assertTrue(self.scopes_backend.check_scope_covered("read", "read:photos"))

    def test_check_scopes_requires_all(self):
        self.assertTrue(self.scopes_backend.check_scopes(["read:photos", "write:photos"], ["write:photos"]))
        self.assertFalse(self.scopes_backend.check_scopes(["read:photos", "write:videos"], ["write:photos"]))


class ReadPhotosResourceView(ScopedProtectedResourceView):
    required_scopes = ["read:photos"]

    def get(self, request, *args, **kwargs):
        return "This is a read:photos protected resource"


@pytest.mark.usefixtures("oauth2_settings")
@pytest.mark.oauth2_settings(HIERARCHICAL_SCOPE_SETTINGS)
class TestHierarchicalScopesProtection(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")
        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )

    def get_resource(self, scope):
        access_token = AccessToken.objects.create(
            user=self.test_user,
            application=self.application,
            token="tok_" + scope.replace(":", "_"),
            scope=scope,
            expires=timezone.now() + datetime.timedelta(days=1),
        )
        auth_headers = {"HTTP_AUTHORIZATION": "Bearer " + access_token.token}
        request = self.factory.get("/fake-resource", **auth_headers)
        request.user = self.test_user
        view = ReadPhotosResourceView.as_view()
        return view(request)

    def test_write_photos_grants_read_photos(self):
        response = self.get_resource("write:photos")
        self.assertEqual(response, "This is a read:photos protected resource")

    def test_read_photos_grants_read_photos(self):
        response = self.get_resource("read:photos")
        self.assertEqual(response, "This is a read:photos protected resource")

    def test_unrelated_scope_forbidden(self):
        response = self.get_resource("write")
        self.assertEqual(response.status_code, 403)
