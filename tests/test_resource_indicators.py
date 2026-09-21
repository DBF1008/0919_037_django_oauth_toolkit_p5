import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.http import QueryDict
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.models import get_access_token_model, get_application_model, get_grant_model
from oauth2_provider.resource_indicators import (
    InvalidTargetError,
    parse_resources,
    resources_from_str,
    resources_to_str,
    validate_resource_indicator,
)

from .common_testing import OAuth2ProviderTestCase as TestCase


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"
RESOURCE_1 = "https://rs1.example.com/api"
RESOURCE_2 = "https://rs2.example.com/api"
RESOURCE_3 = "https://rs3.example.com/"


@pytest.mark.usefixtures("oauth2_settings")
class BaseResourceTest(TestCase):
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("test_user", "test@example.com", "123456")
        cls.dev_user = UserModel.objects.create_user("dev_user", "dev@example.com", "123456")

        cls.application = Application.objects.create(
            name="Test Application",
            redirect_uris="http://localhost http://example.org",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            allowed_resources=f"{RESOURCE_1} {RESOURCE_2}",
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="test_user", password="123456")

    def basic_auth(self):
        token = base64.b64encode(f"{self.application.client_id}:{CLEARTEXT_SECRET}".encode()).decode()
        return {"HTTP_AUTHORIZATION": f"Basic {token}"}

    def authorize(self, resource=RESOURCE_1, scope="read"):
        data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": scope,
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        if resource is not None:
            data["resource"] = resource
        response = self.client.post(reverse("oauth2_provider:authorize"), data=data)
        return response

    def get_code(self, response):
        return parse_qs(urlparse(response["Location"]).query)["code"].pop()

    def exchange_code(self, code, resource=RESOURCE_1):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://example.org",
        }
        if resource is not None:
            data["resource"] = resource
        return self.client.post(reverse("oauth2_provider:token"), data=data, **self.basic_auth())


class TestResourceIndicatorHelpers:
    def test_serialization_roundtrip(self):
        resources = [RESOURCE_1, RESOURCE_2]
        assert resources_from_str(resources_to_str(resources)) == resources

    def test_resources_from_empty_string(self):
        assert resources_from_str("") == []
        assert resources_from_str(None) == []

    def test_parse_resources_deduplicates_and_orders(self, rf):
        request = rf.get("/authorize", {"resource": [RESOURCE_1, RESOURCE_2, RESOURCE_1]})
        assert parse_resources(request.GET) == [RESOURCE_1, RESOURCE_2]

    @pytest.mark.parametrize("value", ["https://rs.example.com/api", "https://rs.example.com"])
    def test_validate_absolute_https_uri(self, value):
        validate_resource_indicator(value)  # must not raise

    @pytest.mark.parametrize("value", ["not-a-uri", "/relative/path", "https://rs.example.com/api#fragment"])
    def test_invalid_indicators_raise(self, value):
        with pytest.raises(InvalidTargetError):
            validate_resource_indicator(value)


class TestApplicationModel(TestCase):
    def test_resource_allowed(self):
        application = Application(allowed_resources=f"{RESOURCE_1} {RESOURCE_2}")
        assert application.resource_allowed(RESOURCE_1) is True
        assert application.resource_allowed(RESOURCE_3) is False

    def test_empty_allowed_resources(self):
        application = Application(allowed_resources="")
        assert application.resource_allowed(RESOURCE_1) is False


class TestAuthorizationEndpointResources(BaseResourceTest):
    def test_resource_persisted_on_grant(self):
        response = self.authorize()
        assert response.status_code == 302
        code = self.get_code(response)
        grant = Grant.objects.get(code=code)
        assert grant.resources == RESOURCE_1

    def test_resource_not_registered_rejected(self):
        response = self.authorize(resource=RESOURCE_3)
        assert response.status_code == 302
        query = parse_qs(urlparse(response["Location"]).query)
        assert query["error"] == ["invalid_target"]

    def test_malformed_resource_rejected(self):
        response = self.authorize(resource="https://rs.example.com/api#frag")
        query = parse_qs(urlparse(response["Location"]).query)
        assert query["error"] == ["invalid_target"]

    def test_no_resource_grant_has_no_resources(self):
        response = self.authorize(resource=None)
        code = self.get_code(response)
        grant = Grant.objects.get(code=code)
        assert grant.resources == ""

    def test_get_request_resource_persisted(self):
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "scope": "read",
                "redirect_uri": "http://example.org",
                "response_type": "code",
                "resource": RESOURCE_1,
            },
        )
        # Consent screen is shown; submit it (resource round-trips via hidden field)
        assert response.status_code == 200
        assert b'name="resource"' in response.content
        assert RESOURCE_1.encode() in response.content
        form_response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "scope": "read",
                "redirect_uri": "http://example.org",
                "response_type": "code",
                "state": "",
                "allow": True,
                "resource": RESOURCE_1,
            },
        )
        code = self.get_code(form_response)
        assert Grant.objects.get(code=code).resources == RESOURCE_1


class TestTokenEndpointResources(BaseResourceTest):
    def test_resource_bound_to_access_token(self):
        code = self.get_code(self.authorize())
        response = self.exchange_code(code)
        assert response.status_code == 200
        content = json.loads(response.content)
        token = AccessToken.objects.get(token=content["access_token"])
        assert token.resources == RESOURCE_1
        assert token.audience == [RESOURCE_1]

    def test_missing_resource_when_required(self):
        code = self.get_code(self.authorize())
        response = self.exchange_code(code, resource=None)
        assert response.status_code == 400
        assert json.loads(response.content)["error"] == "invalid_target"

    def test_resource_not_in_authorization_request(self):
        code = self.get_code(self.authorize())
        response = self.exchange_code(code, resource=RESOURCE_2)
        assert response.status_code == 400
        assert json.loads(response.content)["error"] == "invalid_target"

    def test_unregistered_resource_at_token_endpoint(self):
        code = self.get_code(self.authorize(resource=None))
        response = self.exchange_code(code, resource=RESOURCE_3)
        assert response.status_code == 400
        assert json.loads(response.content)["error"] == "invalid_target"

    def test_no_resource_flow_unchanged(self):
        code = self.get_code(self.authorize(resource=None))
        response = self.exchange_code(code, resource=None)
        assert response.status_code == 200
        content = json.loads(response.content)
        token = AccessToken.objects.get(token=content["access_token"])
        assert token.resources == ""

    def test_resource_refresh_keeps_audience(self):
        code = self.get_code(self.authorize())
        content = json.loads(self.exchange_code(code).content)

        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "refresh_token", "refresh_token": content["refresh_token"]},
            **self.basic_auth(),
        )
        assert response.status_code == 200
        refreshed = json.loads(response.content)
        token = AccessToken.objects.get(token=refreshed["access_token"])
        assert token.audience == [RESOURCE_1]

    def test_resource_refresh_with_subset(self):
        code = self.get_code(self.authorize())
        content = json.loads(self.exchange_code(code).content)

        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": content["refresh_token"],
                "resource": RESOURCE_1,
            },
            **self.basic_auth(),
        )
        assert response.status_code == 200

    def test_resource_refresh_with_unknown_resource(self):
        code = self.get_code(self.authorize())
        content = json.loads(self.exchange_code(code).content)

        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={
                "grant_type": "refresh_token",
                "refresh_token": content["refresh_token"],
                "resource": RESOURCE_3,
            },
            **self.basic_auth(),
        )
        assert response.status_code == 400
        assert json.loads(response.content)["error"] == "invalid_target"


class TestClientCredentialsResources(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("cc_user", "cc@example.com", "123456")
        cls.application = Application.objects.create(
            name="CC Application",
            user=cls.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
            allowed_resources=RESOURCE_1,
        )

    def basic_auth(self):
        token = base64.b64encode(f"{self.application.client_id}:{CLEARTEXT_SECRET}".encode()).decode()
        return {"HTTP_AUTHORIZATION": f"Basic {token}"}

    def test_resource_bound(self):
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "client_credentials", "resource": RESOURCE_1},
            **self.basic_auth(),
        )
        assert response.status_code == 200
        content = json.loads(response.content)
        token = AccessToken.objects.get(token=content["access_token"])
        assert token.audience == [RESOURCE_1]

    def test_unregistered_resource_rejected(self):
        response = self.client.post(
            reverse("oauth2_provider:token"),
            data={"grant_type": "client_credentials", "resource": RESOURCE_3},
            **self.basic_auth(),
        )
        assert response.status_code == 400
        assert json.loads(response.content)["error"] == "invalid_target"


class TestIntrospectionAudience(BaseResourceTest):
    def test_introspection_exposes_aud(self):
        from oauth2_provider.views.introspect import IntrospectTokenView

        code = self.get_code(self.authorize())
        content = json.loads(self.exchange_code(code).content)

        response = IntrospectTokenView.get_token_response(content["access_token"])
        assert response.status_code == 200
        data = json.loads(response.content)
        assert data["active"] is True
        assert data["aud"] == [RESOURCE_1]


class TestAllowedResourcesValidation(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = UserModel.objects.create_user("vr_user", "vr@example.com", "123456")

    def _application(self, allowed_resources):
        return Application(
            name="Validate",
            redirect_uris="http://example.org",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_secret=CLEARTEXT_SECRET,
            allowed_resources=allowed_resources,
        )

    def test_valid_allowed_resources(self):
        self._application(RESOURCE_1).full_clean()

    def test_relative_resource_invalid(self):
        application = self._application("/relative")
        with pytest.raises(ValidationError):
            application.full_clean()

    def test_fragment_resource_invalid(self):
        application = self._application("https://rs.example.com/api#frag")
        with pytest.raises(ValidationError):
            application.full_clean()


class TestMultipleResourceIndicators(BaseResourceTest):
    def setUp(self):
        super().setUp()
        self.application.allowed_resources = f"{RESOURCE_1} {RESOURCE_2}"
        self.application.save()

    def _authorize(self, resources):
        body = QueryDict(mutable=True)
        body.update(
            {
                "client_id": self.application.client_id,
                "state": "s",
                "scope": "read",
                "redirect_uri": "http://example.org",
                "response_type": "code",
                "allow": "True",
            }
        )
        body.setlist("resource", resources)
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data=body.urlencode(),
            content_type="application/x-www-form-urlencoded",
        )
        return self.get_code(response)

    def _exchange(self, code, resources):
        body = QueryDict(mutable=True)
        body.update(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://example.org",
            }
        )
        body.setlist("resource", resources)
        return self.client.post(
            reverse("oauth2_provider:token"),
            data=body.urlencode(),
            content_type="application/x-www-form-urlencoded",
            **self.basic_auth(),
        )

    def test_multiple_resources_authorized_and_bound(self):
        code = self._authorize([RESOURCE_1, RESOURCE_2])
        assert Grant.objects.get(code=code).resources.split() == [RESOURCE_1, RESOURCE_2]

        response = self._exchange(code, [RESOURCE_1, RESOURCE_2])
        assert response.status_code == 200
        content = json.loads(response.content)
        token = AccessToken.objects.get(token=content["access_token"])
        assert token.audience == [RESOURCE_1, RESOURCE_2]

    def test_token_endpoint_subset_of_authorized_resources(self):
        code = self._authorize([RESOURCE_1, RESOURCE_2])

        response = self._exchange(code, [RESOURCE_2])
        assert response.status_code == 200
        content = json.loads(response.content)
        token = AccessToken.objects.get(token=content["access_token"])
        assert token.audience == [RESOURCE_2]


@pytest.mark.usefixtures("oauth2_settings")
class TestImplicitGrantResources(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.test_user = UserModel.objects.create_user("imp_user", "imp@example.com", "123456")
        cls.application = Application.objects.create(
            name="Implicit App",
            redirect_uris="http://example.org",
            user=cls.test_user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_IMPLICIT,
            client_secret="",
            allowed_resources=RESOURCE_1,
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False
        self.client.login(username="imp_user", password="123456")

    def test_resource_bound_to_implicit_token(self):
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "scope": "read",
                "redirect_uri": "http://example.org",
                "response_type": "token",
                "allow": True,
                "resource": RESOURCE_1,
            },
        )
        assert response.status_code == 302
        fragment = urlparse(response["Location"]).fragment
        token_value = parse_qs(fragment)["access_token"].pop()
        token = AccessToken.objects.get(token=token_value)
        assert token.audience == [RESOURCE_1]

    def test_unregistered_resource_rejected(self):
        response = self.client.post(
            reverse("oauth2_provider:authorize"),
            data={
                "client_id": self.application.client_id,
                "scope": "read",
                "redirect_uri": "http://example.org",
                "response_type": "token",
                "allow": True,
                "resource": RESOURCE_3,
            },
        )
        fragment = urlparse(response["Location"]).fragment
        assert parse_qs(fragment)["error"] == ["invalid_target"]
