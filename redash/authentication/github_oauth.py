import logging
import requests
from flask import redirect, url_for, Blueprint, flash, request, session
from authlib.integrations.flask_client import OAuth

from redash import models, settings
from redash.authentication import (
    create_and_login_user,
    logout_and_redirect_to_index,
    get_next_path
)
from redash.authentication.org_resolving import current_org

# Anyone with email could do self-registration
def verify_profile(org, profile, profile_emails):
    for email in [obj['email'] for obj in profile_emails]:
        profile['email'] = email
        return True

    return False
    # if org.is_public:
    #     return True
    #
    # emails = [obj['email'] for obj in profile_emails]
    # for email in emails:
    #     domain = email.split('@')[-1]
    #     if domain in org.github_apps_domains:
    #         profile['email'] = email
    #         return True
    #
    #     if org.has_user(email) == 1:
    #         profile['email'] = email
    #         return True

    # return False

def create_github_oauth_blueprint(app):
    oauth = OAuth(app)

    logger = logging.getLogger("github_oauth")
    blueprint = Blueprint("github_oauth", __name__)
    oauth = OAuth(app)
    oauth.register(
        name="github",
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={"scope": "user:email"},
    )


    def get_user_profile(access_token):
        headers = {'Authorization': 'token {}'.format(access_token)}
        response = requests.get('https://api.github.com/user', headers=headers)

        if response.status_code == 401:
            logger.warning("Failed getting user profile (response code 401).")
            return None

        return response.json()


    def get_user_emails(access_token):
        headers = {'Authorization': 'token {}'.format(access_token)}
        response = requests.get('https://api.github.com/user/emails', headers=headers)

        if response.status_code == 401:
            logger.warning("Failed getting user profile (response code 401).")
            return None

        return response.json()


    @blueprint.route('/<org_slug>/oauth/github', endpoint="authorize_org")
    def org_login(org_slug):
        session['org_slug'] = current_org.slug
        return redirect(url_for(".authorize", next=request.args.get('next', None)))


    @blueprint.route('/oauth/github', endpoint="authorize")
    def login():
        callback = url_for('.callback', _external=True)
        next_path = request.args.get('next', url_for("redash.index", org_slug=session.get('org_slug')))
        logger.debug("Callback url: %s", callback)
        logger.debug("Next is: %s", next_path)
        session["next_url"] = next_path
        return oauth.github.authorize_redirect(callback)

    @blueprint.route('/oauth/github_callback', endpoint="callback")
    def authorized():
        resp = oauth.github.authorize_access_token()
        if 'error' in resp:
            logger.warning("Incorrect GitHub client configurations: %s", resp['error'])
            return redirect(resp['error_uri'])

        access_token = resp['access_token']

        if access_token is None:
            logger.warning("Access token missing in call back request.")
            flash("Validation error. Please retry.")
            return redirect(url_for('redash.login'))

        profile = get_user_profile(access_token)
        logger.info("Profile: %s" % profile)
        if profile is None:
            flash("Validation error. Please retry.")
            return redirect(url_for('redash.login'))

        emails = get_user_emails(access_token)
        logger.info("Emails: %s" % emails)
        if emails is None:
            flash("Validation error. Please retry.")
            return redirect(url_for('redash.login'))

        if 'org_slug' in session:
            org = models.Organization.get_by_slug(session.pop('org_slug'))
        else:
            org = current_org

        if not verify_profile(org, profile, emails):
            logger.warning("User tried to login with unauthorized domain name: %s (org: %s)", profile['email'], org)
            flash("Your GitHub Apps account ({}) isn't allowed.".format(profile['email']))
            return redirect(url_for('redash.login', org_slug=org.slug))

        picture_url = "%s" % profile['avatar_url']
        user = create_and_login_user(org, profile['login'], profile['email'], picture_url)
        if user is None:
            return logout_and_redirect_to_index()

        unsafe_next_path = url_for(
            "redash.index", org_slug=org.slug
        )
        next_path = get_next_path(unsafe_next_path)

        return redirect(next_path)

    return blueprint
