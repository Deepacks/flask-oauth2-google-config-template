import os
import requests
import google.auth.transport.requests
from dotenv import load_dotenv
from google.oauth2 import id_token
from pip._vendor import cachecontrol
from google_auth_oauthlib.flow import Flow
from flask import abort, make_response, redirect, request, Response


def configure_oauth(app):
    load_dotenv()

    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = os.getenv(
        "OAUTH_OAUTHLIB_INSECURE_TRANSPORT"
    )

    client_secrets = {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "project_id": os.getenv("GOOGLE_PROJECT_ID"),
            "auth_uri": os.getenv("GOOGLE_AUTH_URI"),
            "token_uri": os.getenv("GOOGLE_TOKEN_URI"),
            "auth_provider_x509_cert_url": os.getenv(
                "GOOGLE_AUTH_PROVIDER_X509_CERT_URL"
            ),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uris": [os.getenv("GOOGLE_REDIRECT_URI")],
            "javascript_origins": [os.getenv("GOOGLE_JAVASCRIPT_ORIGIN")],
        }
    }

    flow = Flow.from_client_config(
        client_config=client_secrets,
        scopes=[
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid",
        ],
        redirect_uri=os.getenv("GOOGLE_REDIRECT_URI"),
    )

    @app.route("/api/v1/oauth/login")
    def login():
        authorization_url, new_state = flow.authorization_url()

        response = make_response(redirect(authorization_url))
        response.set_cookie("oauth_state", new_state)
        return response

    @app.route("/api/v1/oauth/callback")
    def callback():
        flow.fetch_token(authorization_response=request.url)

        if not request.cookies.get("oauth_state") == request.args["state"]:
            abort(500)

        credentials = flow.credentials
        request_session = requests.session()
        cached_session = cachecontrol.CacheControl(request_session)
        token_request = google.auth.transport.requests.Request(session=cached_session)

        id_info = id_token.verify_oauth2_token(
            id_token=credentials._id_token,
            request=token_request,
            audience=os.getenv("GOOGLE_CLIENT_ID"),
        )
        print(id_info)

        # Do what you need with the id_info (sub = google id)

        response = Response("ok", 200)
        response.delete_cookie("oauth_state")

        return response
