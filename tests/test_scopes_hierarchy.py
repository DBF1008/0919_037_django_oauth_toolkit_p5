import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.scopes import SettingsScopes
from oauth2_provider.views import ScopedProtectedResourceView

from .common_testing import OAuth2ProviderTestCase as TestCase


HIERARCHICAL_SCOPE_SETTINGS = {
    "SCOPES": {
        "read": "Read scope",
        "write": "Write scope",
        "read:photos": "Read photos",
        "write:photos": "Write photos",
        "read:photos:albums": "Read photo albums",
        "write:photos:albums": "Write photo albums",
    },
}

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"


@pytest.mark.oauth2_settings(HIERARCHICAL_SCOPE_SETTINGS)
@pytest.mark.usefixtures("oauth2_settings")
class TestHierarchicalScopes:
    @pytest.mark.parametrize(
        "granted_scope,required_scope,expected",
        [
            # equal scopes always match
            ("read", "read", True),
            ("write:photos", "write:photos", True),
            # action implication, same resource path
            ("write:photos", "read:photos", True),
            ("write:photos:albums", "read:photos:albums", True),
            ("read:photos", "write:photos", False),
            ("read:photos:albums", "write:photos:albums", False),
            # prefix matching on hierarchical paths
            ("read:photos", "read:photos:albums", True),
            ("write:photos", "read:photos:albums", True),
            ("read:photos:albums", "read:photos", False),
            ("write:photos:albums", "read:photos", False),
            # classic flat scopes stay independent
            ("write", "read", False),
            ("read", "write", False),
            # unrelated scopes
            ("scope1", "scope2", False),
        ],
    )
    def test_scope_is_granted(self, granted_scope, required_scope, expected):
        backend = SettingsScopes()
        assert backend.scope_is_granted(granted_scope, required_scope) is expected

    def test_allow_scopes_empty_requirement(self):
        backend = SettingsScopes()
        assert backend.allow_scopes(["write:photos"], []) is True
        assert backend.allow_scopes(["write:photos"], None) is True

    def test_allow_scopes_multiple(self):
        backend = SettingsScopes()
        assert backend.allow_scopes(["write:photos"], ["read:photos", "write:photos"]) is True
        assert backend.allow_scopes(["read:photos"], ["read:photos", "read:photos:albums"]) is True
        assert backend.allow_scopes(["read:photos"], ["write:photos"]) is False

    def test_custom_action_implications(self, oauth2_settings):
        oauth2_settings.SCOPE_ACTION_IMPLICATIONS = {"admin": "write", "write": "read"}
        backend = SettingsScopes()
        assert backend.scope_is_granted("admin:photos", "read:photos") is False
        assert backend.scope_is_granted("admin:photos", "write:photos") is True


class ReadPhotosView(ScopedProtectedResourceView):
    required_scopes = ["read:photos"]

    def get(self, request, *args, **kwargs):
        return HttpResponse("photos")


Application = get_application_model()
AccessToken = get_access_token_model()
UserModel = get_user_model()


@pytest.mark.django_db
@pytest.mark.oauth2_settings(HIERARCHICAL_SCOPE_SETTINGS)
@pytest.mark.usefixtures("oauth2_settings")
class TestHierarchicalScopeProtection(TestCase):
    def setUp(self):
        self.user = UserModel.objects.create_user("hier_user", "h@example.com", "123456")
        self.application = Application.objects.create(
            name="Hier App",
            redirect_uris="http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
        )
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="hier_user", password="123456")

    def _token_with_scope(self, scope):
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "state": "s",
                "scope": scope,
                "redirect_uri": "http://example.org",
                "response_type": "code",
                "allow": True,
            },
        )
        code = parse_qs(urlparse(response["Location"]).query)["code"].pop()
        credentials = f"{self.application.client_id}:{CLEARTEXT_SECRET}".encode()
        auth = {"HTTP_AUTHORIZATION": "Basic " + base64.b64encode(credentials).decode()}
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "authorization_code", "code": code, "redirect_uri": "http://example.org"},
            **auth,
        )
        return json.loads(response.content)["access_token"]

    def test_write_photos_token_can_read_photos(self):
        token = self._token_with_scope("write:photos")
        request = RequestFactory().get("/fake", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = ReadPhotosView.as_view()(request)
        assert response.status_code == 200

    def test_plain_write_token_cannot_read_photos(self):
        token = self._token_with_scope("write")
        request = RequestFactory().get("/fake", HTTP_AUTHORIZATION=f"Bearer {token}")
        response = ReadPhotosView.as_view()(request)
        assert response.status_code == 403
