"""
Tests for RFC 8707 - Resource Indicators for OAuth 2.0.
"""

import json
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import RequestFactory
from django.urls import reverse

from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
    get_refresh_token_model,
)
from oauth2_provider.oauth2_validators import OAuth2Validator

from .common_testing import OAuth2ProviderTestCase as TestCase
from .utils import get_basic_auth_header


Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()
RefreshToken = get_refresh_token_model()
UserModel = get_user_model()

CLEARTEXT_SECRET = "1234567890abcdefghijklmnopqrstuvwxyz"

RESOURCE_API = "https://api.example.com"
RESOURCE_PHOTOS = "https://photos.example.com"
RESOURCE_UNREGISTERED = "https://evil.example.com"


@pytest.mark.usefixtures("oauth2_settings")
class BaseTest(TestCase):
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
            allowed_resources=f"{RESOURCE_API} {RESOURCE_PHOTOS}",
        )

    def setUp(self):
        self.oauth2_settings.PKCE_REQUIRED = False


class TestApplicationModel(BaseTest):
    def test_resource_allowed(self):
        self.assertTrue(self.application.resource_allowed(RESOURCE_API))
        self.assertTrue(self.application.resource_allowed(RESOURCE_PHOTOS))
        self.assertFalse(self.application.resource_allowed(RESOURCE_UNREGISTERED))
        self.assertFalse(self.application.resource_allowed(""))

    def test_clean_valid_allowed_resources(self):
        self.application.clean()

    def test_clean_rejects_invalid_uri(self):
        self.application.allowed_resources = "not-a-uri"
        with self.assertRaises(ValidationError):
            self.application.clean()

    def test_clean_rejects_fragment(self):
        self.application.allowed_resources = "https://api.example.com/#fragment"
        with self.assertRaises(ValidationError):
            self.application.clean()


class TestValidateResource(BaseTest):
    def setUp(self):
        super().setUp()
        self.validator = OAuth2Validator()

    def test_no_resources_is_valid(self):
        self.assertTrue(self.validator.validate_resource(self.application.client_id, []))
        self.assertTrue(self.validator.validate_resource(self.application.client_id, None))

    def test_registered_resource_is_valid(self):
        self.assertTrue(self.validator.validate_resource(self.application.client_id, [RESOURCE_API]))
        self.assertTrue(
            self.validator.validate_resource(self.application.client_id, [RESOURCE_API, RESOURCE_PHOTOS])
        )

    def test_unregistered_resource_is_invalid(self):
        self.assertFalse(
            self.validator.validate_resource(self.application.client_id, [RESOURCE_UNREGISTERED])
        )

    def test_malformed_resource_is_invalid(self):
        self.assertFalse(self.validator.validate_resource(self.application.client_id, ["not-a-uri"]))
        self.assertFalse(self.validator.validate_resource(self.application.client_id, ["/relative/path"]))

    def test_resource_with_fragment_is_invalid(self):
        self.assertFalse(
            self.validator.validate_resource(self.application.client_id, [RESOURCE_API + "/#fragment"])
        )

    def test_unknown_client_is_invalid(self):
        self.assertFalse(self.validator.validate_resource("unknown-client-id", [RESOURCE_API]))


class TestAuthorizationCodeFlow(BaseTest):
    def get_authorization_code(self, resources, scope="read"):
        self.client.login(username="test_user", password="123456")
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": scope,
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
        }
        if resources:
            authcode_data["resource"] = " ".join(resources)
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        self.assertEqual(response.status_code, 302)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        return query_dict["code"].pop()

    def exchange_code(self, authorization_code, resources=None):
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        if resources:
            token_request_data["resource"] = " ".join(resources)
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        return self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)

    def test_resource_persisted_in_grant_and_access_token(self):
        authorization_code = self.get_authorization_code([RESOURCE_API])

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.resource, RESOURCE_API)

        response = self.exchange_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, RESOURCE_API)

    def test_multiple_resources_persisted(self):
        authorization_code = self.get_authorization_code([RESOURCE_API, RESOURCE_PHOTOS])

        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.resource.split(), [RESOURCE_API, RESOURCE_PHOTOS])

        response = self.exchange_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource.split(), [RESOURCE_API, RESOURCE_PHOTOS])

    def test_token_request_without_resource_inherits_grant_resource(self):
        authorization_code = self.get_authorization_code([RESOURCE_API])
        # token request without explicit resource parameter
        response = self.exchange_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, RESOURCE_API)

    def test_token_request_with_subset_resource(self):
        authorization_code = self.get_authorization_code([RESOURCE_API, RESOURCE_PHOTOS])
        response = self.exchange_code(authorization_code, resources=[RESOURCE_PHOTOS])
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, RESOURCE_PHOTOS)

    def test_token_request_with_repeated_resource_parameters(self):
        authorization_code = self.get_authorization_code([RESOURCE_API, RESOURCE_PHOTOS])
        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
            "resource": [RESOURCE_API, RESOURCE_PHOTOS],
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource.split(), [RESOURCE_API, RESOURCE_PHOTOS])

    def test_token_request_with_resource_not_in_grant_is_rejected(self):
        authorization_code = self.get_authorization_code([RESOURCE_API])
        # RESOURCE_PHOTOS is registered on the Application but was not granted
        response = self.exchange_code(authorization_code, resources=[RESOURCE_PHOTOS])
        self.assertEqual(response.status_code, 400)
        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["error"], "invalid_target")

    def test_token_request_with_unregistered_resource_is_rejected(self):
        authorization_code = self.get_authorization_code([RESOURCE_API])
        response = self.exchange_code(authorization_code, resources=[RESOURCE_UNREGISTERED])
        self.assertEqual(response.status_code, 400)
        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["error"], "invalid_target")

    def test_no_resource_anywhere(self):
        authorization_code = self.get_authorization_code([])
        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.resource, "")
        response = self.exchange_code(authorization_code)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, "")


class TestAuthorizationEndpointResourceValidation(BaseTest):
    def test_get_authorize_with_allowed_resource(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read",
                "redirect_uri": "http://example.org",
                "resource": RESOURCE_API,
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_get_authorize_with_repeated_resource_parameters(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read",
                "redirect_uri": "http://example.org",
                "resource": [RESOURCE_API, RESOURCE_PHOTOS],
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_get_authorize_with_unregistered_resource_redirects_with_invalid_target(self):
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read",
                "redirect_uri": "http://example.org",
                "resource": RESOURCE_UNREGISTERED,
            },
        )
        self.assertEqual(response.status_code, 302)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        self.assertEqual(query_dict["error"], ["invalid_target"])

    def test_get_authorize_skip_authorization_with_resource(self):
        self.application.skip_authorization = True
        self.application.save()
        self.client.login(username="test_user", password="123456")
        response = self.client.get(
            reverse("oauth2_provider:authorize"),
            {
                "client_id": self.application.client_id,
                "response_type": "code",
                "state": "random_state_string",
                "scope": "read",
                "redirect_uri": "http://example.org",
                "resource": RESOURCE_API,
            },
        )
        self.assertEqual(response.status_code, 302)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()
        grant = Grant.objects.get(code=authorization_code)
        self.assertEqual(grant.resource, RESOURCE_API)

    def test_post_authorize_with_tampered_resource_is_rejected(self):
        self.client.login(username="test_user", password="123456")
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
            "resource": RESOURCE_UNREGISTERED,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        self.assertEqual(response.status_code, 302)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        self.assertEqual(query_dict["error"], ["invalid_target"])


class TestClientCredentialsResource(BaseTest):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.cc_application = Application.objects.create(
            name="Client Credentials Application",
            user=cls.dev_user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_CLIENT_CREDENTIALS,
            client_secret=CLEARTEXT_SECRET,
            allowed_resources=RESOURCE_API,
        )

    def test_client_credentials_with_allowed_resource(self):
        token_request_data = {
            "grant_type": "client_credentials",
            "scope": "read",
            "resource": RESOURCE_API,
        }
        auth_headers = get_basic_auth_header(self.cc_application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, RESOURCE_API)

    def test_client_credentials_with_unregistered_resource(self):
        token_request_data = {
            "grant_type": "client_credentials",
            "scope": "read",
            "resource": RESOURCE_UNREGISTERED,
        }
        auth_headers = get_basic_auth_header(self.cc_application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 400)
        content = json.loads(response.content.decode("utf-8"))
        self.assertEqual(content["error"], "invalid_target")


class TestRefreshTokenResource(BaseTest):
    def test_refresh_token_inherits_resource(self):
        self.client.login(username="test_user", password="123456")
        authcode_data = {
            "client_id": self.application.client_id,
            "state": "random_state_string",
            "scope": "read",
            "redirect_uri": "http://example.org",
            "response_type": "code",
            "allow": True,
            "resource": RESOURCE_API,
        }
        response = self.client.post(reverse("oauth2_provider:authorize"), data=authcode_data)
        query_dict = parse_qs(urlparse(response["Location"]).query)
        authorization_code = query_dict["code"].pop()

        token_request_data = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": "http://example.org",
        }
        auth_headers = get_basic_auth_header(self.application.client_id, CLEARTEXT_SECRET)
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        content = json.loads(response.content.decode("utf-8"))
        refresh_token = content["refresh_token"]

        # exchange the refresh token for a new access token
        token_request_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        response = self.client.post(reverse("oauth2_provider:token"), data=token_request_data, **auth_headers)
        self.assertEqual(response.status_code, 200)
        content = json.loads(response.content.decode("utf-8"))
        access_token = AccessToken.objects.get(token=content["access_token"])
        self.assertEqual(access_token.resource, RESOURCE_API)
