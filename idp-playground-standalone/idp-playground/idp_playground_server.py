# -*- coding: utf-8 -*-
"""
IDP-Playground -- Identity Platform
File : idp_playground_server.py
Port : 8080

Two-module architecture:
  IDP-DS  -- Directory Domain Services (user/group/domain directory, SQLite backend)
  IDP-TS  -- Token Generator Service (JWT/SAML/OIDC token engine)

Run: python idp_playground_server.py
"""
import os, sys, json, uuid, hashlib, secrets, base64, datetime, io, smtplib, logging

# Force UTF-8 output on Windows (default console is CP1252).
if sys.stdout.encoding and sys.stdout.encoding.upper() not in ("UTF-8", "UTF8"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import jwt as pyjwt
import bcrypt
import pyotp
import qrcode
import qrcode.image.svg

# ──────────────────────────────────────────────────────────
#  App bootstrap
# ──────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(BASE_DIR, "instance", "idp_playground.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["IDPPLAYGROUND_ISSUER"] = "https://idp-playground.local"
flask_app = app   # stable alias — prevents 'app' local variables shadowing Flask app in helpers

# ── Email / SMTP config (edit these for your mail server) ──
app.config["SMTP_HOST"]     = os.environ.get("SMTP_HOST", "smtp.gmail.com")
app.config["SMTP_PORT"]     = int(os.environ.get("SMTP_PORT", "587"))
app.config["SMTP_USER"]     = os.environ.get("SMTP_USER", "")        # your Gmail address
app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "")    # Gmail app password
app.config["SMTP_FROM"]     = os.environ.get("SMTP_FROM", "IDP-Playground <no-reply@idp-playground.local>")

db = SQLAlchemy(app)
os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)

# ──────────────────────────────────────────────────────────
#  ██████  ███████     ███    ███  ██████  ██████  ███████ ██      ███████
#  ██   ██ ██          ████  ████ ██    ██ ██   ██ ██      ██      ██
#  ██   ██ ███████     ██ ████ ██ ██    ██ ██   ██ █████   ██      ███████
#  ██   ██      ██     ██  ██  ██ ██    ██ ██   ██ ██      ██           ██
#  ██████  ███████     ██      ██  ██████  ██████  ███████ ███████ ███████
# ──────────────────────────────────────────────────────────

class Domain(db.Model):
    """Organisational domain — top of the directory tree."""
    __tablename__ = "domains"
    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(128), unique=True, nullable=False)   # e.g. corp.local
    netbios     = db.Column(db.String(32))                                 # CORP
    description = db.Column(db.String(256))
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    users       = db.relationship("DSUser",  backref="domain", lazy=True, cascade="all, delete-orphan")
    groups      = db.relationship("DSGroup", backref="domain", lazy=True, cascade="all, delete-orphan")
    ous         = db.relationship("OrgUnit",  backref="domain", lazy=True, cascade="all, delete-orphan")


class OrgUnit(db.Model):
    """Organisational Unit (OU)."""
    __tablename__ = "org_units"
    id          = db.Column(db.Integer, primary_key=True)
    domain_id   = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    name        = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))
    parent_id   = db.Column(db.Integer, db.ForeignKey("org_units.id"), nullable=True)
    children    = db.relationship("OrgUnit", backref=db.backref("parent", remote_side="OrgUnit.id"))
    users       = db.relationship("DSUser", backref="ou", lazy=True)


class DSUser(db.Model):
    """Directory user account — mirrors AD user object."""
    __tablename__ = "ds_users"
    id              = db.Column(db.Integer, primary_key=True)
    guid            = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    domain_id       = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    ou_id           = db.Column(db.Integer, db.ForeignKey("org_units.id"), nullable=True)
    # Core identity
    sam_account     = db.Column(db.String(64), nullable=False)   # short account name
    upn             = db.Column(db.String(256), unique=True, nullable=False)  # userPrincipalName
    display_name    = db.Column(db.String(128))
    given_name      = db.Column(db.String(64))
    surname         = db.Column(db.String(64))
    email           = db.Column(db.String(256))
    phone           = db.Column(db.String(32))
    title           = db.Column(db.String(128))
    department      = db.Column(db.String(128))
    company         = db.Column(db.String(128))
    manager_id      = db.Column(db.Integer, db.ForeignKey("ds_users.id"), nullable=True)
    # Auth
    password_hash   = db.Column(db.String(128))
    # Account control (mirrors userAccountControl flags)
    enabled         = db.Column(db.Boolean, default=True)
    locked          = db.Column(db.Boolean, default=False)
    pwd_never_expires = db.Column(db.Boolean, default=False)
    must_change_pwd = db.Column(db.Boolean, default=False)
    mfa_enabled     = db.Column(db.Boolean, default=False)
    mfa_method      = db.Column(db.String(32), default="totp")  # totp / email / cert
    totp_secret     = db.Column(db.String(64), nullable=True)
    email_otp_code  = db.Column(db.String(8),  nullable=True)
    email_otp_exp   = db.Column(db.DateTime,   nullable=True)
    # Certificate-Based Auth token (short-lived, set when cert is verified)
    cert_auth_token = db.Column(db.String(64), nullable=True)
    cert_auth_exp   = db.Column(db.DateTime,   nullable=True)
    sms_enrolled    = db.Column(db.Boolean, default=False)  # SMS / Voice OTP enrolled (demo)
    push_enrolled   = db.Column(db.Boolean, default=False)  # Push Notification enrolled (demo)
    # Timestamps
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_logon      = db.Column(db.DateTime, nullable=True)
    pwd_last_set    = db.Column(db.DateTime, nullable=True)
    # Extra attributes
    description     = db.Column(db.String(256))
    thumbnail_letter = db.Column(db.String(4))  # avatar fallback

    def set_password(self, raw: str):
        self.password_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()
        self.pwd_last_set = datetime.datetime.utcnow()

    def check_password(self, raw: str) -> bool:
        if not self.password_hash:
            return False
        return bcrypt.checkpw(raw.encode(), self.password_hash.encode())

    def generate_totp_secret(self) -> str:
        """Generate and store a new TOTP secret. Returns the secret."""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        """Return an otpauth:// URI for QR code generation."""
        if not self.totp_secret:
            self.generate_totp_secret()
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.upn,
            issuer_name="IDP-Playground"
        )

    def verify_totp(self, code: str) -> bool:
        """
        Verify a TOTP code.
        valid_window=2 allows ±60 seconds clock drift (2 x 30-second windows).
        This handles cases where the server clock and phone clock are slightly off.
        """
        if not self.totp_secret:
            return False
        code = code.strip().replace(" ", "")
        if len(code) != 6 or not code.isdigit():
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=2)

    def generate_email_otp(self) -> str:
        """Generate a 6-digit email OTP valid for 10 minutes."""
        code = str(secrets.randbelow(900000) + 100000)  # 100000-999999
        self.email_otp_code = code
        self.email_otp_exp  = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        return code

    def verify_email_otp(self, code: str) -> bool:
        """Verify email OTP — single use, expires after 10 min."""
        if not self.email_otp_code or not self.email_otp_exp:
            return False
        if datetime.datetime.utcnow() > self.email_otp_exp:
            return False
        if self.email_otp_code != code.strip():
            return False
        # Invalidate after use
        self.email_otp_code = None
        self.email_otp_exp  = None
        return True

    def to_dict(self):
        return {
            "id": self.id, "guid": self.guid,
            "sam_account": self.sam_account, "upn": self.upn,
            "display_name": self.display_name, "given_name": self.given_name,
            "surname": self.surname, "email": self.email,
            "phone": self.phone, "title": self.title,
            "department": self.department, "company": self.company,
            "enabled": self.enabled, "locked": self.locked,
            "mfa_enabled": self.mfa_enabled, "mfa_method": self.mfa_method,
            "totp_secret": self.totp_secret,
            "has_cert": UserCertificate.query.filter_by(user_id=self.id, revoked=False).first() is not None,
            "pwd_never_expires": self.pwd_never_expires,
            "must_change_pwd": self.must_change_pwd,
            "ou_id": self.ou_id,
            "description": self.description,
            "thumbnail_letter": self.thumbnail_letter or (self.given_name or "U")[0].upper(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_logon": self.last_logon.isoformat() if self.last_logon else None,
        }


# Many-to-many: users ↔ groups
user_groups = db.Table(
    "user_groups",
    db.Column("user_id",  db.Integer, db.ForeignKey("ds_users.id"),  primary_key=True),
    db.Column("group_id", db.Integer, db.ForeignKey("ds_groups.id"), primary_key=True),
)


class CertificateAuthority(db.Model):
    """
    IDP-Playground Root Certificate Authority.
    Generated once; used to sign all user client certificates.
    Acts as the root CA that issues and signs certificates for the platform.
    """
    __tablename__ = "certificate_authority"
    id            = db.Column(db.Integer, primary_key=True)
    common_name   = db.Column(db.String(256), default="IDP-Playground Root CA")
    private_pem   = db.Column(db.Text, nullable=False)   # CA private key (never exposed)
    cert_pem      = db.Column(db.Text, nullable=False)   # CA certificate (public)
    fingerprint   = db.Column(db.String(64))             # SHA-256 hex
    serial        = db.Column(db.String(40))
    not_before    = db.Column(db.DateTime)
    not_after     = db.Column(db.DateTime)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "common_name": self.common_name,
            "cert_pem":    self.cert_pem,
            "fingerprint": self.fingerprint,
            "serial":      self.serial,
            "not_before":  self.not_before.isoformat() if self.not_before else None,
            "not_after":   self.not_after.isoformat()  if self.not_after  else None,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
        }


class UserCertificate(db.Model):
    """
    Client certificate issued to a directory user for Certificate-Based Authentication.
    Stores both the certificate and encrypted private key so users can download
    a PKCS#12 bundle (.p12) to import into their browser or OS keystore.
    """
    __tablename__ = "user_certificates"
    id            = db.Column(db.Integer, primary_key=True)
    user_id       = db.Column(db.Integer, db.ForeignKey("ds_users.id"), nullable=False)
    serial        = db.Column(db.String(40), unique=True)
    common_name   = db.Column(db.String(256))
    cert_pem      = db.Column(db.Text, nullable=False)
    private_pem   = db.Column(db.Text, nullable=False)   # stored for PKCS#12 export
    fingerprint   = db.Column(db.String(64))             # SHA-256 of DER bytes
    not_before    = db.Column(db.DateTime)
    not_after     = db.Column(db.DateTime)
    revoked       = db.Column(db.Boolean, default=False)
    revoked_at    = db.Column(db.DateTime, nullable=True)
    created_at    = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user          = db.relationship("DSUser", backref="certificates", lazy=True)

    def to_dict(self):
        return {
            "id":          self.id,
            "user_id":     self.user_id,
            "serial":      self.serial,
            "common_name": self.common_name,
            "cert_pem":    self.cert_pem,
            "fingerprint": self.fingerprint,
            "not_before":  self.not_before.isoformat() if self.not_before else None,
            "not_after":   self.not_after.isoformat()  if self.not_after  else None,
            "revoked":     self.revoked,
            "revoked_at":  self.revoked_at.isoformat() if self.revoked_at else None,
            "created_at":  self.created_at.isoformat() if self.created_at else None,
        }


class DSGroup(db.Model):
    """Directory security / distribution group."""
    __tablename__ = "ds_groups"
    id          = db.Column(db.Integer, primary_key=True)
    guid        = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    domain_id   = db.Column(db.Integer, db.ForeignKey("domains.id"), nullable=False)
    name        = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))
    group_type  = db.Column(db.String(32), default="security")   # security / distribution
    group_scope = db.Column(db.String(32), default="global")     # local / global / universal
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    members     = db.relationship("DSUser", secondary=user_groups, backref="groups", lazy=True)

    def to_dict(self):
        return {
            "id": self.id, "guid": self.guid, "name": self.name,
            "description": self.description, "group_type": self.group_type,
            "group_scope": self.group_scope, "domain_id": self.domain_id,
            "member_count": len(self.members),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ──────────────────────────────────────────────────────────
#  ███████ ███████     ███    ███  ██████  ██████  ███████ ██      ███████
#  ██      ██          ████  ████ ██    ██ ██   ██ ██      ██      ██
#  █████   ███████     ██ ████ ██ ██    ██ ██   ██ █████   ██      ███████
#  ██           ██     ██  ██  ██ ██    ██ ██   ██ ██      ██           ██
#  ██      ███████     ██      ██  ██████  ██████  ███████ ███████ ███████
# ──────────────────────────────────────────────────────────

class FSApplication(db.Model):
    """
    Relying Party / OIDC Client — registered application.
    Fields mirror Azure Entra App Registration + Enterprise App configuration
    per protocol (OIDC, SAML, OAuth 2.0, WS-Fed).
    """
    __tablename__ = "fs_applications"
    id              = db.Column(db.Integer, primary_key=True)
    app_guid        = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    client_id       = db.Column(db.String(64), unique=True, nullable=False)
    client_secret   = db.Column(db.String(128))
    name            = db.Column(db.String(128), nullable=False)
    description     = db.Column(db.String(512))
    protocol        = db.Column(db.String(32), default="OIDC")
    icon_emoji      = db.Column(db.String(8),  default="🔐")
    brand_color     = db.Column(db.String(16), default="#38b6ff")
    enabled         = db.Column(db.Boolean, default=True)
    require_mfa     = db.Column(db.Boolean, default=False)
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # ── OIDC / OAuth 2.0 ──────────────────────────────────────────────────
    redirect_uris       = db.Column(db.Text, default="[]")   # JSON list of callback URLs
    logout_uris         = db.Column(db.Text, default="[]")   # post-logout redirect URIs
    allowed_scopes      = db.Column(db.String(512), default="openid profile email groups")
    token_lifetime      = db.Column(db.Integer, default=3600)
    refresh_enabled     = db.Column(db.Boolean, default=True)
    refresh_lifetime    = db.Column(db.Integer, default=2592000)  # 30 days
    app_id_uri          = db.Column(db.String(256))        # Application ID URI e.g. api://client_id
    front_channel_logout = db.Column(db.String(512))       # Front-channel logout URL
    # Grant types: JSON list e.g. ["authorization_code","client_credentials"]
    grant_types         = db.Column(db.Text, default='["authorization_code"]')
    # Response types allowed
    response_types      = db.Column(db.Text, default='["code"]')
    # PKCE required (recommended for public clients / SPAs)
    pkce_required       = db.Column(db.Boolean, default=True)
    # Allowed token audiences (JSON list)
    allowed_audiences   = db.Column(db.Text, default="[]")
    # Client type: confidential / public
    client_type         = db.Column(db.String(16), default="confidential")
    # Platform: web / spa / native
    platform_type       = db.Column(db.String(16), default="web")

    # ── SAML 2.0 ──────────────────────────────────────────────────────────
    saml_entity_id          = db.Column(db.String(512))    # SP Entity ID / Audience
    saml_acs_url            = db.Column(db.String(512))    # Assertion Consumer Service URL
    saml_slo_url            = db.Column(db.String(512))    # Single Logout URL
    saml_name_id_format     = db.Column(db.String(128),
                                default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    saml_name_id_value      = db.Column(db.String(64), default="user.email")
    saml_sign_response      = db.Column(db.Boolean, default=True)
    saml_sign_assertion     = db.Column(db.Boolean, default=True)
    saml_encrypt_assertion  = db.Column(db.Boolean, default=False)
    saml_signature_algorithm = db.Column(db.String(64),
                                default="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    saml_digest_algorithm   = db.Column(db.String(64),
                                default="http://www.w3.org/2001/04/xmlenc#sha256")
    # SP metadata XML (uploaded by user)
    saml_sp_metadata        = db.Column(db.Text)

    # ── WS-Federation ──────────────────────────────────────────────────────
    wsfed_realm             = db.Column(db.String(512))    # wtrealm
    wsfed_reply_url         = db.Column(db.String(512))    # wreply
    wsfed_token_type        = db.Column(db.String(64),
                                default="urn:oasis:names:tc:SAML:1.0:assertion")

    # ── Claims configuration ───────────────────────────────────────────────
    # JSON list of claim objects:
    # [{"name":"email","source":"user.email","essential":true,"token_types":["id","access","saml"]}]
    custom_claims           = db.Column(db.Text, default="[]")
    # Group claims: all / security / none
    group_claims            = db.Column(db.String(32), default="security")
    # Include standard claims: sub, name, email, groups, department, etc.
    include_standard_claims = db.Column(db.Boolean, default=True)

    # ── SSO (SP-side) configuration ────────────────────────────────────────
    # Metadata XML provided by the SP (for SSO config page)
    sp_metadata_xml         = db.Column(db.Text)
    # Parsed SSO endpoint returned to the SP
    sso_login_url           = db.Column(db.String(512))    # auto-computed
    sso_logout_url          = db.Column(db.String(512))    # auto-computed
    # ── Extra auth methods ─────────────────────────────────────────────────
    allow_cba               = db.Column(db.Boolean, default=False)  # Certificate-Based Auth
    allow_passkey           = db.Column(db.Boolean, default=False)  # WebAuthn / Passkey
    allow_authenticator     = db.Column(db.Boolean, default=False)  # Authenticator app (TOTP)
    allow_email             = db.Column(db.Boolean, default=False)  # Email OTP
    allow_push              = db.Column(db.Boolean, default=False)  # Push Notification (demo)
    allow_sms               = db.Column(db.Boolean, default=False)  # SMS / Voice OTP (demo)

    tokens = db.relationship("IssuedToken", backref="application",
                              lazy=True, cascade="all, delete-orphan")

    def get_redirect_uris(self):
        try: return json.loads(self.redirect_uris or "[]")
        except: return []

    def get_custom_claims(self):
        try: return json.loads(self.custom_claims or "[]")
        except: return []

    def to_dict(self):
        base = app.config.get("IDPPLAYGROUND_ISSUER","https://idp-playground.local")
        return {
            "id": self.id, "app_guid": self.app_guid,
            "client_id": self.client_id, "name": self.name,
            "description": self.description or "",
            "protocol": self.protocol,
            "icon_emoji": self.icon_emoji, "brand_color": self.brand_color,
            "enabled": self.enabled, "require_mfa": self.require_mfa,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            # OIDC/OAuth
            "redirect_uris": self.get_redirect_uris(),
            "logout_uris": json.loads(self.logout_uris or "[]"),
            "allowed_scopes": self.allowed_scopes or "openid profile email groups",
            "token_lifetime": self.token_lifetime or 3600,
            "refresh_enabled": self.refresh_enabled,
            "refresh_lifetime": self.refresh_lifetime or 2592000,
            "app_id_uri": self.app_id_uri or f"api://{self.client_id}",
            "front_channel_logout": self.front_channel_logout or "",
            "grant_types": json.loads(self.grant_types or '["authorization_code"]'),
            "response_types": json.loads(self.response_types or '["code"]'),
            "pkce_required": self.pkce_required,
            "allowed_audiences": json.loads(self.allowed_audiences or "[]"),
            "client_type": self.client_type or "confidential",
            "platform_type": self.platform_type or "web",
            # SAML
            "saml_entity_id": self.saml_entity_id or "",
            "saml_acs_url": self.saml_acs_url or "",
            "saml_slo_url": self.saml_slo_url or "",
            "saml_name_id_format": self.saml_name_id_format or "",
            "saml_name_id_value": self.saml_name_id_value or "user.email",
            "saml_sign_response": self.saml_sign_response,
            "saml_sign_assertion": self.saml_sign_assertion,
            "saml_encrypt_assertion": self.saml_encrypt_assertion,
            "saml_signature_algorithm": self.saml_signature_algorithm or "",
            "saml_digest_algorithm": self.saml_digest_algorithm or "",
            # WS-Fed
            "wsfed_realm": self.wsfed_realm or "",
            "wsfed_reply_url": self.wsfed_reply_url or "",
            "wsfed_token_type": self.wsfed_token_type or "",
            # Claims
            "custom_claims": self.get_custom_claims(),
            "group_claims": self.group_claims or "security",
            "include_standard_claims": self.include_standard_claims,
            # SSO endpoints (computed)
            "sso_login_url":  f"{base}/saml/sso"  if self.protocol == "SAML"   else
                              f"{base}/wsfed"      if self.protocol == "WS-Fed" else
                              f"{base}/oauth2/authorize",
            "sso_logout_url": f"{base}/saml/slo"  if self.protocol == "SAML"   else
                              f"{base}/wsfed?wa=wsignout1.0" if self.protocol == "WS-Fed" else
                              f"{base}/oauth2/logout",
            "metadata_url": f"{base}/apps/{self.id}/metadata.xml"
                             if self.protocol in ("SAML","WS-Fed") else
                             f"{base}/.well-known/openid-configuration",
            "sp_metadata_xml": self.sp_metadata_xml or "",
            "allow_cba":     self.allow_cba     or False,
            "allow_passkey": self.allow_passkey or False,
            "allow_authenticator": self.allow_authenticator or False,
            "allow_email":   self.allow_email   or False,
            "allow_push":    self.allow_push    or False,
            "allow_sms":     self.allow_sms     or False,
            "is_demo":       self.name in ("OIDC Test Client", "SAML Demo SP",
                                           "OAuth2 Demo Client", "WS-Fed Demo App"),
        }


class SigningKey(db.Model):
    """RSA/EC signing key for token signing (JWK)."""
    __tablename__ = "signing_keys"
    id          = db.Column(db.Integer, primary_key=True)
    kid         = db.Column(db.String(64), unique=True, nullable=False)
    algorithm   = db.Column(db.String(16), default="RS256")
    key_use     = db.Column(db.String(8),  default="sig")
    active      = db.Column(db.Boolean, default=True)
    private_pem = db.Column(db.Text, nullable=False)
    public_pem  = db.Column(db.Text, nullable=False)
    created_at  = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def to_dict(self, include_private=False):
        d = {
            "id": self.id, "kid": self.kid,
            "algorithm": self.algorithm, "key_use": self.key_use,
            "active": self.active,
            "public_pem": self.public_pem,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_private:
            d["private_pem"] = self.private_pem
        return d


class IssuedToken(db.Model):
    """Audit record for every token issued."""
    __tablename__ = "issued_tokens"
    id          = db.Column(db.Integer, primary_key=True)
    jti         = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    app_id      = db.Column(db.Integer, db.ForeignKey("fs_applications.id"), nullable=True)
    subject     = db.Column(db.String(256))
    token_type  = db.Column(db.String(32), default="access_token")
    scopes      = db.Column(db.String(512))
    extra_claims = db.Column(db.Text, default="{}")
    revoked     = db.Column(db.Boolean, default=False)
    issued_at   = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at  = db.Column(db.DateTime)
    raw_token   = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id, "jti": self.jti,
            "subject": self.subject, "token_type": self.token_type,
            "scopes": self.scopes, "revoked": self.revoked,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "raw_token": self.raw_token,
            "app_name": self.application.name if self.application else "—",
        }


class AuditLog(db.Model):
    """System-wide audit log."""
    __tablename__ = "audit_logs"
    id        = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    level     = db.Column(db.String(8),  default="INFO")   # INFO/OK/WARN/ERROR
    module    = db.Column(db.String(32))                   # DS / FS / SYSTEM
    action    = db.Column(db.String(128))
    detail    = db.Column(db.String(512))
    actor     = db.Column(db.String(128), default="admin")

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime("%H:%M:%S"),
            "level": self.level, "module": self.module,
            "action": self.action, "detail": self.detail,
            "actor": self.actor,
        }


class MFAPolicy(db.Model):
    """Global MFA policy per method."""
    __tablename__ = "mfa_policies"
    id      = db.Column(db.Integer, primary_key=True)
    method  = db.Column(db.String(32), unique=True)
    enabled = db.Column(db.Boolean, default=False)
    label   = db.Column(db.String(64))
    icon    = db.Column(db.String(8))


# ──────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────

def _extract_cert_fingerprint(cert_bytes):
    """
    Extract a SHA-256 fingerprint from an uploaded certificate in ANY common
    format: PEM (.cer/.pem/.crt, including combined key+cert), DER (binary .cer),
    or PKCS#12 (.p12/.pfx, including password-protected), or bare base64.
    Returns (fingerprint_hex, None) on success or (None, error_message).
    """
    import base64 as _b64, re as _re
    from cryptography import x509 as _x509
    from cryptography.hazmat.primitives import hashes as _hh
    from cryptography.hazmat.primitives.serialization import pkcs12 as _p12

    if not cert_bytes:
        return None, "file was empty"

    def _fp(c):
        return c.fingerprint(_hh.SHA256()).hex()

    if b"-----BEGIN" in cert_bytes:
        try:
            blocks = _re.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                cert_bytes, _re.DOTALL)
            if blocks:
                return _fp(_x509.load_pem_x509_certificate(blocks[0], default_backend())), None
            return _fp(_x509.load_pem_x509_certificate(cert_bytes, default_backend())), None
        except Exception:
            pass

    for pw in (None, b"", b"idp-playground", b"changeit", b"password"):
        try:
            _k, _c, _chain = _p12.load_key_and_certificates(cert_bytes, pw, default_backend())
            if _c is not None:
                return _fp(_c), None
        except Exception:
            continue

    try:
        return _fp(_x509.load_der_x509_certificate(cert_bytes, default_backend())), None
    except Exception:
        pass

    try:
        compact = b"".join(cert_bytes.split())
        der = _b64.b64decode(compact, validate=False)
        return _fp(_x509.load_der_x509_certificate(der, default_backend())), None
    except Exception:
        pass

    head = cert_bytes[:16]
    if head[:1] == b"<":
        diag = "file looks like HTML (download may have failed)"
    else:
        diag = f"first bytes={head!r}"
    return None, (f"unrecognized certificate ({diag}). Supported: .cer .pem .crt .p12")


def audit(level: str, module: str, action: str, detail: str = "", actor: str = "admin"):
    log = AuditLog(level=level, module=module, action=action, detail=detail, actor=actor)
    db.session.add(log)
    db.session.commit()


def send_email_otp(to_address: str, display_name: str, code: str) -> tuple[bool, str]:
    """
    Send an OTP code by email using configured SMTP.
    Returns (success: bool, message: str).
    """
    smtp_user = app.config["SMTP_USER"]
    smtp_pwd  = app.config["SMTP_PASSWORD"]
    smtp_host = app.config["SMTP_HOST"]
    smtp_port = app.config["SMTP_PORT"]

    if not smtp_user or not smtp_pwd:
        # SMTP not configured — log code to console for testing
        logging.warning(f"[IDP-Playground MFA] EMAIL OTP for {to_address}: {code}  (SMTP not configured)")
        return False, "SMTP not configured — code printed to server console"

    subject = "IDP-Playground — Your login verification code"
    body_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;background:#05080d;color:#d4e4f5;border-radius:12px;padding:32px;border:1px solid #1f3349">
      <div style="text-align:center;margin-bottom:24px">
        <div style="font-size:32px">🔐</div>
        <div style="font-size:22px;font-weight:900;color:#fff">IDP-Playground</div>
        <div style="font-size:11px;color:#4a6685;letter-spacing:2px">IDENTITY PLATFORM</div>
      </div>
      <p style="color:#d4e4f5;margin-bottom:16px">Hi <strong>{display_name}</strong>,</p>
      <p style="color:#4a6685;margin-bottom:24px">Your one-time verification code is:</p>
      <div style="background:#090e16;border:1px solid #1f3349;border-radius:10px;padding:24px;text-align:center;margin-bottom:24px">
        <div style="font-size:42px;font-weight:900;letter-spacing:12px;font-family:monospace;color:#e8ff47">{code}</div>
        <div style="font-size:11px;color:#4a6685;margin-top:8px">Expires in 10 minutes</div>
      </div>
      <p style="font-size:12px;color:#4a6685">If you did not request this code, someone may be trying to access your account. Ignore this email if that is the case.</p>
      <hr style="border:1px solid #172333;margin:20px 0">
      <p style="font-size:11px;color:#1e3148;text-align:center">Sent by IDP-Playground Identity Platform</p>
    </div>
    """
    body_plain = f"Your IDP-Playground verification code is: {code}\nExpires in 10 minutes."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = app.config["SMTP_FROM"]
    msg["To"]      = to_address
    msg.attach(MIMEText(body_plain, "plain"))
    msg.attach(MIMEText(body_html,  "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pwd)
            server.sendmail(smtp_user, to_address, msg.as_string())
        return True, f"OTP sent to {to_address}"
    except Exception as e:
        logging.error(f"[IDP-Playground SMTP] Failed to send to {to_address}: {e}")
        return False, str(e)


def generate_rsa_keypair(bits=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def get_active_key():
    """Return the active signing key, auto-generating one if none exists."""
    k = SigningKey.query.filter_by(active=True).order_by(SigningKey.id.desc()).first()
    if k:
        return k
    # Auto-heal: if no active key exists (e.g. after manual DB manipulation),
    # try to activate the most recent key, or generate a brand-new one.
    any_key = SigningKey.query.order_by(SigningKey.id.desc()).first()
    if any_key:
        any_key.active = True
        db.session.commit()
        return any_key
    # No keys at all — generate one now
    priv, pub = generate_rsa_keypair()
    kid = f"idp-key-auto-{secrets.token_hex(4)}"
    new_k = SigningKey(kid=kid, algorithm="RS256", active=True,
                       private_pem=priv, public_pem=pub)
    db.session.add(new_k)
    db.session.commit()
    return new_k


def issue_jwt(subject: str, fs_app, extra_claims: dict, lifetime: int):
    """
    Issue a signed RS256 JWT.
    Parameters
    ----------
    subject  : UPN / email of the authenticated user
    fs_app   : FSApplication instance (or None for internal tokens)
    extra_claims : dict of additional claims to embed
    lifetime : token TTL in seconds
    Returns (raw_token_str, expiry_datetime)
    """
    key = get_active_key()
    if not key:
        raise ValueError("No active signing key — go to Signing Keys and generate one first")
    now    = datetime.datetime.utcnow()
    exp    = now + datetime.timedelta(seconds=lifetime)
    issuer = flask_app.config.get("IDPPLAYGROUND_ISSUER", "https://idp-playground.local")
    payload = {
        "iss":   issuer,
        "sub":   subject,
        "aud":   fs_app.client_id if isinstance(fs_app, FSApplication) else "idp-playground",
        "iat":   int(now.timestamp()),
        "exp":   int(exp.timestamp()),
        "jti":   str(uuid.uuid4()),
        "scope": fs_app.allowed_scopes if isinstance(fs_app, FSApplication) else "openid",
        **extra_claims,
    }
    token = pyjwt.encode(
        payload,
        key.private_pem,
        algorithm="RS256",
        headers={"kid": key.kid},
    )
    return token, exp


def seed_database():
    """Populate default data on first run."""
    # Default domain
    if not Domain.query.first():
        d = Domain(name="corp.idp-playground.local", netbios="CORP", description="Default IDP-Playground domain")
        db.session.add(d)
        db.session.flush()

        # OUs
        for ou_name in ["Users", "Groups", "Computers", "Service Accounts"]:
            db.session.add(OrgUnit(domain_id=d.id, name=ou_name, description=f"Default {ou_name} OU"))
        db.session.flush()

        users_ou = OrgUnit.query.filter_by(name="Users", domain_id=d.id).first()

        # Default admin user
        admin = DSUser(
            domain_id=d.id, ou_id=users_ou.id if users_ou else None,
            sam_account="administrator", upn="administrator@corp.idp-playground.local",
            display_name="Administrator", given_name="Admin", surname="User",
            email="administrator@corp.idp-playground.local",
            title="Domain Administrator", department="IT", company="IDP-Playground Corp",
            enabled=True, mfa_enabled=True, mfa_method="totp",
            thumbnail_letter="A",
        )
        admin.set_password("Admin@IDP-Playground1")
        db.session.add(admin)

        # Demo users
        demo_users = [
            ("jsmith", "John", "Smith", "john.smith@corp.idp-playground.local", "Developer", "Engineering"),
            ("mjones", "Maria", "Jones", "maria.jones@corp.idp-playground.local", "DevOps Engineer", "Operations"),
            ("rlee",   "Robert", "Lee",  "r.lee@corp.idp-playground.local",      "Security Analyst", "Security"),
        ]
        for sam, fn, ln, upn, title, dept in demo_users:
            u = DSUser(
                domain_id=d.id, ou_id=users_ou.id if users_ou else None,
                sam_account=sam, upn=upn,
                display_name=f"{fn} {ln}", given_name=fn, surname=ln,
                email=upn, title=title, department=dept, company="IDP-Playground Corp",
                enabled=True, thumbnail_letter=fn[0].upper(),
            )
            u.set_password("Welcome@1")
            db.session.add(u)

        # Groups
        for gname, gtype in [("Domain Admins","security"),("Domain Users","security"),("Developers","security"),("DevOps","security"),("Security Team","security")]:
            db.session.add(DSGroup(domain_id=d.id, name=gname, group_type=gtype, group_scope="global"))

        db.session.commit()
        audit("OK", "SYSTEM", "Database seeded", "Default domain, OUs, users and groups created")

    # Default signing key
    if not SigningKey.query.first():
        priv, pub = generate_rsa_keypair()
        k = SigningKey(kid="idp-key-001", algorithm="RS256", active=True, private_pem=priv, public_pem=pub)
        db.session.add(k)
        db.session.commit()
        audit("OK", "FS", "Signing key generated", "idp-key-001 (RS256 2048-bit)")

    # Default demo applications — mirror the auto-registration payloads used
    # by the test_apps/* clients so they always show under Applications,
    # even before a demo process has been started.
    if not FSApplication.query.first():
        demo_apps = [
            dict(
                name="OIDC Test Client",
                description="Auto-registered test client at localhost:5000",
                protocol="OIDC",
                redirect_uris=json.dumps(["http://localhost:5000/auth/callback"]),
                allowed_scopes="openid profile email groups",
                icon_emoji="🧪", brand_color="#34d399",
                token_lifetime=3600, refresh_enabled=True,
            ),
            dict(
                name="SAML Demo SP",
                description="Auto-registered test client at localhost:5001",
                protocol="SAML",
                redirect_uris=json.dumps(["http://localhost:5001/saml/acs"]),
                allowed_scopes="openid profile email groups",
                icon_emoji="📄", brand_color="#a78bfa",
            ),
            dict(
                name="OAuth2 Demo Client",
                description="Auto-registered test client at localhost:5002",
                protocol="OAuth",
                redirect_uris=json.dumps(["http://localhost:5002/oauth2/callback"]),
                allowed_scopes="openid profile email groups",
                icon_emoji="⚡", brand_color="#34d399",
            ),
            dict(
                name="WS-Fed Demo App",
                description="Auto-registered test client at localhost:5003",
                protocol="WS-Fed",
                redirect_uris=json.dumps(["http://localhost:5003/wsfed/callback"]),
                allowed_scopes="openid profile email groups",
                icon_emoji="🏢", brand_color="#fb923c",
            ),
        ]
        for da in demo_apps:
            db.session.add(FSApplication(
                client_id=secrets.token_hex(16),
                client_secret=secrets.token_hex(32),
                logout_uris="[]",
                grant_types='["authorization_code"]',
                **da
            ))
        db.session.commit()
        audit("OK", "FS", "Demo applications registered",
              "OIDC Test Client, SAML Demo SP, OAuth2 Demo Client, WS-Fed Demo App")

    # MFA policies
    if not MFAPolicy.query.first():
        for method, label, icon, enabled in [
            ("totp",   "TOTP Authenticator",          "🔐", True),
            ("email",  "Email OTP",                   "📧", True),
            ("cert",   "Certificate-Based Auth (CBA)", "🪪", True),
            ("push",   "Push Notification",            "📱", False),
            ("fido2",  "FIDO2 / WebAuthn",             "🗝", False),
            ("sms",    "SMS / Voice OTP",              "📞", False),
        ]:
            db.session.add(MFAPolicy(method=method, label=label, icon=icon, enabled=enabled))
        db.session.commit()
    else:
        # Ensure CBA policy exists even in older DBs
        if not MFAPolicy.query.filter_by(method="cert").first():
            db.session.add(MFAPolicy(
                method="cert", label="Certificate-Based Auth (CBA)", icon="🪪", enabled=True))
            db.session.commit()

    audit("OK", "SYSTEM", "IDP-Playground started", "All services online")


# ──────────────────────────────────────────────────────────
#  Routes — Main UI
# ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ──────────────────────────────────────────────────────────
#  API — Directory Services (DS)
# ──────────────────────────────────────────────────────────

@app.route("/api/ds/stats")
def ds_stats():
    return jsonify({
        "domains":  Domain.query.count(),
        "users":    DSUser.query.count(),
        "groups":   DSGroup.query.count(),
        "ous":      OrgUnit.query.count(),
        "enabled":  DSUser.query.filter_by(enabled=True).count(),
        "locked":   DSUser.query.filter_by(locked=True).count(),
        "mfa":      DSUser.query.filter_by(mfa_enabled=True).count(),
    })


@app.route("/api/ds/domains", methods=["GET", "POST"])
def ds_domains():
    if request.method == "GET":
        return jsonify([{
            "id": d.id, "name": d.name, "netbios": d.netbios,
            "description": d.description,
            "user_count":  DSUser.query.filter_by(domain_id=d.id).count(),
            "group_count": DSGroup.query.filter_by(domain_id=d.id).count(),
            "created_at":  d.created_at.isoformat() if d.created_at else None,
        } for d in Domain.query.all()])
    data = request.json
    d = Domain(name=data["name"], netbios=data.get("netbios",""), description=data.get("description",""))
    db.session.add(d)
    db.session.commit()
    # Create default OUs
    for ou_name in ["Users","Groups","Computers","Service Accounts"]:
        db.session.add(OrgUnit(domain_id=d.id, name=ou_name))
    db.session.commit()
    audit("OK", "DS", "Domain created", f"{d.name}")
    return jsonify({"ok": True, "id": d.id})


@app.route("/api/ds/domains/<int:did>", methods=["DELETE"])
def ds_domain_delete(did):
    d = Domain.query.get_or_404(did)
    name = d.name
    db.session.delete(d)
    db.session.commit()
    audit("WARN", "DS", "Domain deleted", name)
    return jsonify({"ok": True})


@app.route("/api/ds/ous")
def ds_ous():
    ous = OrgUnit.query.all()
    return jsonify([{
        "id": o.id, "name": o.name, "domain_id": o.domain_id,
        "description": o.description, "parent_id": o.parent_id,
        "user_count": DSUser.query.filter_by(ou_id=o.id).count(),
    } for o in ous])


@app.route("/api/ds/ous", methods=["POST"])
def ds_ou_create():
    data = request.json
    ou = OrgUnit(domain_id=data["domain_id"], name=data["name"],
                 description=data.get("description",""), parent_id=data.get("parent_id"))
    db.session.add(ou)
    db.session.commit()
    audit("OK", "DS", "OU created", f"{ou.name}")
    return jsonify({"ok": True, "id": ou.id})


@app.route("/api/ds/users", methods=["GET"])
def ds_users():
    q = request.args.get("q","").lower()
    domain_id = request.args.get("domain_id", type=int)
    query = DSUser.query
    if domain_id:
        query = query.filter_by(domain_id=domain_id)
    if q:
        query = query.filter(
            db.or_(
                DSUser.display_name.ilike(f"%{q}%"),
                DSUser.upn.ilike(f"%{q}%"),
                DSUser.sam_account.ilike(f"%{q}%"),
                DSUser.email.ilike(f"%{q}%"),
            )
        )
    return jsonify([u.to_dict() for u in query.order_by(DSUser.display_name).all()])


@app.route("/api/ds/users", methods=["POST"])
def ds_user_create():
    data = request.json
    if DSUser.query.filter_by(upn=data["upn"]).first():
        return jsonify({"error": "UPN already exists"}), 400
    u = DSUser(
        domain_id=data["domain_id"],
        ou_id=data.get("ou_id"),
        sam_account=data["sam_account"],
        upn=data["upn"],
        display_name=data.get("display_name", ""),
        given_name=data.get("given_name", ""),
        surname=data.get("surname", ""),
        email=data.get("email", data["upn"]),
        phone=data.get("phone", ""),
        title=data.get("title", ""),
        department=data.get("department", ""),
        company=data.get("company", ""),
        description=data.get("description", ""),
        enabled=data.get("enabled", True),
        mfa_enabled=data.get("mfa_enabled", False),
        mfa_method=data.get("mfa_method", "totp"),
        pwd_never_expires=data.get("pwd_never_expires", False),
        must_change_pwd=data.get("must_change_pwd", False),
        thumbnail_letter=(data.get("given_name","U") or "U")[0].upper(),
    )
    if data.get("password"):
        u.set_password(data["password"])
    db.session.add(u)
    db.session.commit()
    audit("OK", "DS", "User created", f"{u.upn}")
    return jsonify({"ok": True, "id": u.id})


@app.route("/api/ds/users/<int:uid>", methods=["GET"])
def ds_user_get(uid):
    u = DSUser.query.get_or_404(uid)
    d = u.to_dict()
    d["groups"] = [{"id": g.id, "name": g.name} for g in u.groups]
    return jsonify(d)


@app.route("/api/ds/users/<int:uid>", methods=["PUT"])
def ds_user_update(uid):
    u = DSUser.query.get_or_404(uid)
    data = request.json
    for field in ["display_name","given_name","surname","email","phone",
                  "title","department","company","description",
                  "enabled","locked","mfa_enabled","mfa_method",
                  "pwd_never_expires","must_change_pwd","ou_id"]:
        if field in data:
            setattr(u, field, data[field])
    if data.get("password"):
        u.set_password(data["password"])
    db.session.commit()
    audit("OK", "DS", "User updated", f"{u.upn}")
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>", methods=["DELETE"])
def ds_user_delete(uid):
    u = DSUser.query.get_or_404(uid)
    upn = u.upn
    db.session.delete(u)
    db.session.commit()
    audit("WARN", "DS", "User deleted", upn)
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>/lock", methods=["POST"])
def ds_user_lock(uid):
    u = DSUser.query.get_or_404(uid)
    u.locked = True
    db.session.commit()
    audit("WARN", "DS", "Account locked", u.upn)
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>/unlock", methods=["POST"])
def ds_user_unlock(uid):
    u = DSUser.query.get_or_404(uid)
    u.locked = False
    db.session.commit()
    audit("OK", "DS", "Account unlocked", u.upn)
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>/reset-password", methods=["POST"])
def ds_user_reset_password(uid):
    u = DSUser.query.get_or_404(uid)
    new_pw = request.json.get("password","")
    if not new_pw:
        return jsonify({"error": "Password required"}), 400
    u.set_password(new_pw)
    u.must_change_pwd = request.json.get("force_change", True)
    db.session.commit()
    audit("WARN", "DS", "Password reset", u.upn)
    return jsonify({"ok": True})


@app.route("/api/ds/groups", methods=["GET"])
def ds_groups():
    return jsonify([g.to_dict() for g in DSGroup.query.order_by(DSGroup.name).all()])


@app.route("/api/ds/groups", methods=["POST"])
def ds_group_create():
    data = request.json
    g = DSGroup(
        domain_id=data["domain_id"], name=data["name"],
        description=data.get("description",""),
        group_type=data.get("group_type","security"),
        group_scope=data.get("group_scope","global"),
    )
    db.session.add(g)
    db.session.commit()
    audit("OK", "DS", "Group created", g.name)
    return jsonify({"ok": True, "id": g.id})


@app.route("/api/ds/groups/<int:gid>", methods=["DELETE"])
def ds_group_delete(gid):
    g = DSGroup.query.get_or_404(gid)
    name = g.name
    db.session.delete(g)
    db.session.commit()
    audit("WARN", "DS", "Group deleted", name)
    return jsonify({"ok": True})


@app.route("/api/ds/groups/<int:gid>/members", methods=["GET"])
def ds_group_members(gid):
    g = DSGroup.query.get_or_404(gid)
    return jsonify([u.to_dict() for u in g.members])


@app.route("/api/ds/groups/<int:gid>/members", methods=["POST"])
def ds_group_add_member(gid):
    g = DSGroup.query.get_or_404(gid)
    uid = request.json.get("user_id")
    u = DSUser.query.get_or_404(uid)
    if u not in g.members:
        g.members.append(u)
        db.session.commit()
        audit("OK", "DS", "Group member added", f"{u.upn} → {g.name}")
    return jsonify({"ok": True})


@app.route("/api/ds/groups/<int:gid>/members/<int:uid>", methods=["DELETE"])
def ds_group_remove_member(gid, uid):
    g = DSGroup.query.get_or_404(gid)
    u = DSUser.query.get_or_404(uid)
    if u in g.members:
        g.members.remove(u)
        db.session.commit()
        audit("OK", "DS", "Group member removed", f"{u.upn} ← {g.name}")
    return jsonify({"ok": True})


# ──────────────────────────────────────────────────────────
#  API — Token Generator Service (FS)
# ──────────────────────────────────────────────────────────

@app.route("/api/fs/stats")
def fs_stats():
    return jsonify({
        "applications": FSApplication.query.count(),
        "tokens_total": IssuedToken.query.count(),
        "tokens_active": IssuedToken.query.filter_by(revoked=False).filter(
            IssuedToken.expires_at > datetime.datetime.utcnow()).count(),
        "signing_keys": SigningKey.query.count(),
        "active_keys":  SigningKey.query.filter_by(active=True).count(),
    })


@app.route("/api/fs/applications", methods=["GET"])
def fs_apps_list():
    return jsonify([a.to_dict() for a in FSApplication.query.order_by(FSApplication.name).all()])


@app.route("/api/fs/applications/<int:aid>", methods=["GET"])
def fs_app_get(aid):
    """Get a single application by ID — needed for the Edit modal."""
    a = FSApplication.query.get_or_404(aid)
    return jsonify(a.to_dict())


@app.route("/api/fs/applications", methods=["POST"])
def fs_app_create():
    data = request.json or {}
    cid  = secrets.token_hex(16)
    csec = secrets.token_hex(32)
    proto = data.get("protocol","OIDC")

    # Parse redirect URIs — accept list, newline-separated, or comma-separated
    def _parse_uris(v):
        if isinstance(v, list):  return v
        if not v:                return []
        sep = "\n" if "\n" in v else ","
        return [u.strip() for u in v.split(sep) if u.strip()]

    a = FSApplication(
        client_id=cid, client_secret=csec,
        name=data.get("name",""),
        description=data.get("description",""),
        protocol=proto,
        icon_emoji=data.get("icon_emoji","🔐"),
        brand_color=data.get("brand_color","#38b6ff"),
        enabled=data.get("enabled", True),
        require_mfa=data.get("require_mfa", False),
        token_lifetime=int(data.get("token_lifetime", 3600)),
        refresh_enabled=data.get("refresh_enabled", True),
        refresh_lifetime=int(data.get("refresh_lifetime", 2592000)),
        # OIDC/OAuth
        redirect_uris=json.dumps(_parse_uris(data.get("redirect_uris",""))),
        logout_uris=json.dumps(_parse_uris(data.get("logout_uris",""))),
        allowed_scopes=data.get("allowed_scopes","openid profile email groups"),
        app_id_uri=data.get("app_id_uri",""),
        front_channel_logout=data.get("front_channel_logout",""),
        grant_types=json.dumps(data.get("grant_types",["authorization_code"])),
        pkce_required=data.get("pkce_required", True),
        client_type=data.get("client_type","confidential"),
        platform_type=data.get("platform_type","web"),
        allowed_audiences=json.dumps(data.get("allowed_audiences",[])),
        # SAML
        saml_entity_id=data.get("saml_entity_id",""),
        saml_acs_url=data.get("saml_acs_url",""),
        saml_slo_url=data.get("saml_slo_url",""),
        saml_name_id_format=data.get("saml_name_id_format",
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"),
        saml_name_id_value=data.get("saml_name_id_value","user.email"),
        saml_sign_response=data.get("saml_sign_response", True),
        saml_sign_assertion=data.get("saml_sign_assertion", True),
        saml_encrypt_assertion=data.get("saml_encrypt_assertion", False),
        saml_signature_algorithm=data.get("saml_signature_algorithm",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
        saml_digest_algorithm=data.get("saml_digest_algorithm",
            "http://www.w3.org/2001/04/xmlenc#sha256"),
        # WS-Fed
        wsfed_realm=data.get("wsfed_realm",""),
        wsfed_reply_url=data.get("wsfed_reply_url",""),
        wsfed_token_type=data.get("wsfed_token_type",
            "urn:oasis:names:tc:SAML:1.0:assertion"),
        # Claims
        custom_claims=json.dumps(data.get("custom_claims",[])),
        group_claims=data.get("group_claims","security"),
        include_standard_claims=data.get("include_standard_claims", True),
        # Extra auth methods
        allow_cba    =data.get("allow_cba",     False),
        allow_passkey=data.get("allow_passkey",  False),
        allow_authenticator=data.get("allow_authenticator", False),
        allow_email  =data.get("allow_email",   False),
        allow_push   =data.get("allow_push",    False),
        allow_sms    =data.get("allow_sms",     False),
    )
    db.session.add(a)
    db.session.commit()
    audit("OK","FS","Application registered", f"{a.name} ({proto}) client_id={cid}")
    return jsonify({"ok": True, "id": a.id, "client_id": cid, "client_secret": csec})


@app.route("/api/fs/applications/<int:aid>", methods=["PUT"])
def fs_app_update(aid):
    a    = FSApplication.query.get_or_404(aid)
    data = request.json or {}

    # Basic
    for f in ["name","description","protocol","icon_emoji","brand_color","enabled",
              "require_mfa","allow_cba","allow_passkey","allow_authenticator",
              "allow_email","allow_push","allow_sms",
              "token_lifetime","refresh_enabled","refresh_lifetime",
              "app_id_uri","front_channel_logout","pkce_required","client_type","platform_type",
              "allowed_scopes","saml_name_id_value","saml_sign_response","saml_sign_assertion",
              "saml_encrypt_assertion","saml_signature_algorithm","saml_digest_algorithm",
              "saml_entity_id","saml_acs_url","saml_slo_url","saml_name_id_format",
              "wsfed_realm","wsfed_reply_url","wsfed_token_type","group_claims",
              "include_standard_claims"]:
        if f in data:
            setattr(a, f, data[f])

    # JSON list fields
    for jf in ["redirect_uris","logout_uris","grant_types","response_types",
               "allowed_audiences","custom_claims"]:
        if jf in data:
            v = data[jf]
            setattr(a, jf, json.dumps(v) if isinstance(v, list) else v)

    # Parse comma-separated URIs if sent as string
    if "redirect_uris" in data and isinstance(data["redirect_uris"], str):
        uris = [u.strip() for u in data["redirect_uris"].split(",") if u.strip()]
        a.redirect_uris = json.dumps(uris)

    db.session.commit()
    audit("OK","FS","Application updated", a.name)
    return jsonify({"ok": True})


@app.route("/api/fs/applications/<int:aid>", methods=["DELETE"])
def fs_app_delete(aid):
    a    = FSApplication.query.get_or_404(aid)
    name = a.name
    db.session.delete(a)
    db.session.commit()
    audit("WARN","FS","Application deleted", name)
    return jsonify({"ok": True})


@app.route("/api/fs/applications/<int:aid>/rotate-secret", methods=["POST"])
def fs_app_rotate_secret(aid):
    a = FSApplication.query.get_or_404(aid)
    a.client_secret = secrets.token_hex(32)
    db.session.commit()
    audit("WARN","FS","Client secret rotated", a.name)
    return jsonify({"ok": True, "client_secret": a.client_secret})


# Per-protocol default template used by "Restore Defaults". Mirrors the demo
# seed defaults and the FSApplication column defaults so an app can be reset to
# a known-good baseline for its protocol without touching its identity
# (client_id / client_secret / name / protocol are preserved).
_APP_PROTOCOL_DEFAULTS = {
    "OIDC":   dict(icon_emoji="🧪", brand_color="#34d399",
                   redirect_uris=json.dumps(["http://localhost:5000/auth/callback"])),
    "OAuth":  dict(icon_emoji="⚡", brand_color="#34d399",
                   redirect_uris=json.dumps(["http://localhost:5002/oauth2/callback"])),
    "SAML":   dict(icon_emoji="📄", brand_color="#a78bfa",
                   redirect_uris=json.dumps(["http://localhost:5001/saml/acs"])),
    "WS-Fed": dict(icon_emoji="🏢", brand_color="#fb923c",
                   redirect_uris=json.dumps(["http://localhost:5003/wsfed/callback"])),
}


@app.route("/api/fs/applications/<int:aid>/restore-defaults", methods=["POST"])
def fs_app_restore_defaults(aid):
    """
    Reset an application's settings to the IDP-Playground default template for its
    protocol. Identity fields (id, app_guid, client_id, client_secret, name,
    protocol, created_at) are preserved; everything else returns to defaults.
    """
    a = FSApplication.query.get_or_404(aid)
    proto = a.protocol if a.protocol in _APP_PROTOCOL_DEFAULTS else "OIDC"
    tmpl  = _APP_PROTOCOL_DEFAULTS[proto]

    # Branding & core toggles
    a.icon_emoji   = tmpl["icon_emoji"]
    a.brand_color  = tmpl["brand_color"]
    a.enabled      = True
    a.require_mfa  = False
    a.allow_cba    = False
    a.allow_passkey = False
    a.allow_authenticator = False
    a.allow_email = False
    a.allow_push = False
    a.allow_sms = False

    # OIDC / OAuth
    a.redirect_uris        = tmpl["redirect_uris"]
    a.logout_uris          = "[]"
    a.allowed_scopes       = "openid profile email groups"
    a.token_lifetime       = 3600
    a.refresh_enabled      = True
    a.refresh_lifetime     = 2592000
    a.app_id_uri           = None
    a.front_channel_logout = None
    a.grant_types          = '["authorization_code"]'
    a.response_types       = '["code"]'
    a.pkce_required        = True
    a.allowed_audiences    = "[]"
    a.client_type          = "confidential"
    a.platform_type        = "web"

    # SAML
    a.saml_entity_id           = None
    a.saml_acs_url             = None
    a.saml_slo_url             = None
    a.saml_name_id_format      = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    a.saml_name_id_value       = "user.email"
    a.saml_sign_response       = True
    a.saml_sign_assertion      = True
    a.saml_encrypt_assertion   = False
    a.saml_signature_algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    a.saml_digest_algorithm    = "http://www.w3.org/2001/04/xmlenc#sha256"
    a.saml_sp_metadata         = None

    # WS-Fed
    a.wsfed_realm       = None
    a.wsfed_reply_url   = None
    a.wsfed_token_type  = "urn:oasis:names:tc:SAML:1.0:assertion"

    # Claims
    a.custom_claims           = "[]"
    a.group_claims            = "security"
    a.include_standard_claims = True

    # SSO (SP-side)
    a.sp_metadata_xml = None
    a.sso_login_url   = None
    a.sso_logout_url  = None

    db.session.commit()
    audit("WARN", "FS", "Application restored to defaults", f"{a.name} ({proto})")
    return jsonify({"ok": True, "application": a.to_dict()})


@app.route("/apps/<int:aid>/metadata.xml")
def app_metadata_xml(aid):
    """
    Generate and return SAML / WS-Fed / OIDC metadata for an application.
    - SAML  → SP Metadata XML (EntityDescriptor)
    - WS-Fed → Federation metadata XML
    - OIDC  → Redirect to /.well-known/openid-configuration
    """
    a    = FSApplication.query.get_or_404(aid)
    base = app.config.get("IDPPLAYGROUND_ISSUER","https://idp-playground.local")
    key  = get_active_key()

    if a.protocol in ("SAML","WS-Fed"):
        # Load signing cert for metadata
        cert_b64 = ""
        if key:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key as _lpk
            # Strip PEM headers for inclusion in XML
            cert_b64 = key.public_pem.replace("-----BEGIN PUBLIC KEY-----","") \
                                      .replace("-----END PUBLIC KEY-----","") \
                                      .replace("\n","").strip()

        if a.protocol == "SAML":
            entity_id = a.saml_entity_id or f"{base}/apps/{aid}/metadata.xml"
            acs       = a.saml_acs_url or ""
            slo       = a.saml_slo_url or ""
            sig_alg   = a.saml_signature_algorithm or \
                        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="{entity_id}"
  validUntil="{(datetime.datetime.utcnow()+datetime.timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')}">

  <!-- IDP-Playground SAML IDP Metadata for: {a.name} -->
  <md:IDPSSODescriptor
    WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>

    <md:NameIDFormat>{a.saml_name_id_format or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"}</md:NameIDFormat>

    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="{base}/saml/sso"/>
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{base}/saml/sso"/>
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="{base}/saml/slo"/>
  </md:IDPSSODescriptor>

  <!-- Service Provider ACS -->
  <md:SPSSODescriptor
    AuthnRequestsSigned="false" WantAssertionsSigned="{str(a.saml_sign_assertion).lower()}"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="'+acs+'" index="0"/>' if acs else '<!-- ACS URL not configured -->'}
    {'<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="'+slo+'"/>' if slo else ''}
  </md:SPSSODescriptor>

</md:EntityDescriptor>"""

        else:  # WS-Fed
            realm = a.wsfed_realm or f"{base}/apps/{aid}"
            xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<fed:Federation xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
  xmlns:wsa="http://www.w3.org/2005/08/addressing"
  xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706"
  FederationID="{realm}">

  <!-- IDP-Playground WS-Federation Metadata for: {a.name} -->
  <fed:TargetScopes>
    <wsa:EndpointReference><wsa:Address>{realm}</wsa:Address></wsa:EndpointReference>
  </fed:TargetScopes>

  <fed:ApplicationServiceEndpoint>
    <wsa:EndpointReference>
      <wsa:Address>{a.wsfed_reply_url or ''}</wsa:Address>
    </wsa:EndpointReference>
  </fed:ApplicationServiceEndpoint>

  <fed:SecurityTokenServiceEndpoint>
    <wsa:EndpointReference>
      <wsa:Address>{base}/wsfed</wsa:Address>
    </wsa:EndpointReference>
  </fed:SecurityTokenServiceEndpoint>

</fed:Federation>"""

        from flask import Response
        return Response(xml, mimetype="application/xml",
            headers={"Content-Disposition": f"attachment; filename=idp-playground_metadata_{a.id}.xml"})
    else:
        # OIDC / OAuth — generate federation metadata XML (like Azure Entra)
        from flask import Response
        base_url = "http://localhost:8080"
        key  = get_active_key()
        cert_b64 = ""
        if key:
            cert_b64 = key.public_pem.replace("-----BEGIN PUBLIC KEY-----","") \
                                      .replace("-----END PUBLIC KEY-----","") \
                                      .replace("\n","").strip()
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
  entityID="{base_url}/apps/{a.id}"
  validUntil="{(datetime.datetime.utcnow()+datetime.timedelta(days=365)).strftime('%Y-%m-%dT%H:%M:%SZ')}">

  <!-- IDP-Playground OIDC/OAuth2 Federation Metadata for: {a.name} -->
  <!-- Protocol: {a.protocol} | Client ID: {a.client_id} -->

  <IDPSSODescriptor
    WantAuthnRequestsSigned="false"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo>
        <ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="{base_url}/oauth2/authorize"/>
  </IDPSSODescriptor>

  <Extensions>
    <fed:ApplicationServiceEndpoint>
      <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
        <wsa:Address>{a.get_redirect_uris()[0] if a.get_redirect_uris() else ''}</wsa:Address>
      </wsa:EndpointReference>
    </fed:ApplicationServiceEndpoint>
    <Issuer xmlns="http://www.w3.org/2000/09/xmldsig#">{base_url}</Issuer>
    <ClientID>{a.client_id}</ClientID>
    <AppName>{a.name}</AppName>
    <TokenEndpoint>{base_url}/oauth2/token</TokenEndpoint>
    <UserInfoEndpoint>{base_url}/oauth2/userinfo</UserInfoEndpoint>
    <JWKSUri>{base_url}/.well-known/jwks.json</JWKSUri>
    <Scopes>{a.allowed_scopes or "openid profile email groups"}</Scopes>
  </Extensions>

</EntityDescriptor>"""
        return Response(xml, mimetype="application/xml",
            headers={"Content-Disposition": f"attachment; filename=idp-playground_metadata_{a.id}.xml"})


@app.route("/api/fs/applications/<int:aid>/import-sp-metadata", methods=["POST"])
def fs_app_import_sp_metadata(aid):
    """
    Accept SP metadata XML (uploaded file or pasted string).
    Parse EntityID, ACS URL, SLO URL, NameID format and pre-populate the app record.
    """
    a = FSApplication.query.get_or_404(aid)

    xml_text = ""
    if "file" in request.files:
        xml_text = request.files["file"].read().decode("utf-8", errors="replace")
    elif request.is_json:
        xml_text = request.json.get("xml","")
    else:
        xml_text = request.form.get("xml","")

    if not xml_text.strip():
        return jsonify({"ok": False, "error": "No metadata provided"}), 400

    try:
        root = ET.fromstring(xml_text)
        ns   = {
            "md":  "urn:oasis:names:tc:SAML:2.0:metadata",
            "fed": "http://docs.oasis-open.org/wsfed/federation/200706",
            "wsa": "http://www.w3.org/2005/08/addressing",
        }

        parsed = {}

        # SAML parsing
        entity_id = root.get("entityID") or root.get("FederationID","")
        if entity_id:
            parsed["entity_id"] = entity_id

        acs = root.find(".//md:AssertionConsumerService", ns)
        if acs is not None:
            parsed["acs_url"] = acs.get("Location","")

        slo = root.find(".//md:SingleLogoutService", ns)
        if slo is not None:
            parsed["slo_url"] = slo.get("Location","")

        nid = root.find(".//md:NameIDFormat", ns)
        if nid is not None and nid.text:
            parsed["name_id_format"] = nid.text.strip()

        # WS-Fed parsing
        app_ep = root.find(".//fed:ApplicationServiceEndpoint/wsa:EndpointReference/wsa:Address", ns)
        if app_ep is not None and app_ep.text:
            parsed["wsfed_reply_url"] = app_ep.text.strip()

        target = root.find(".//fed:TargetScopes/wsa:EndpointReference/wsa:Address", ns)
        if target is not None and target.text:
            parsed["wsfed_realm"] = target.text.strip()

        # Apply parsed values
        if "entity_id" in parsed:
            a.saml_entity_id = parsed["entity_id"]
            a.wsfed_realm    = a.wsfed_realm or parsed["entity_id"]
        if "acs_url" in parsed:
            a.saml_acs_url = parsed["acs_url"]
            uris = a.get_redirect_uris()
            if parsed["acs_url"] not in uris:
                uris.append(parsed["acs_url"])
                a.redirect_uris = json.dumps(uris)
        if "slo_url"         in parsed: a.saml_slo_url       = parsed["slo_url"]
        if "name_id_format"  in parsed: a.saml_name_id_format = parsed["name_id_format"]
        if "wsfed_reply_url" in parsed: a.wsfed_reply_url     = parsed["wsfed_reply_url"]
        if "wsfed_realm"     in parsed: a.wsfed_realm         = parsed["wsfed_realm"]

        a.sp_metadata_xml = xml_text
        db.session.commit()
        audit("OK","FS","SP metadata imported", a.name)
        return jsonify({"ok": True, "parsed": parsed})

    except Exception as e:
        return jsonify({"ok": False, "error": f"XML parse error: {e}"}), 400


@app.route("/api/fs/applications/<int:aid>/sso-config", methods=["GET"])
def fs_app_sso_config(aid):
    """Return full SSO configuration for an app including all endpoint URLs."""
    a    = FSApplication.query.get_or_404(aid)
    d    = a.to_dict()
    base = app.config.get("IDPPLAYGROUND_ISSUER","https://idp-playground.local")
    key  = get_active_key()
    d["signing_key_kid"]     = key.kid if key else ""
    d["signing_cert_pem"]    = key.public_pem if key else ""
    d["idp_issuer"]          = base
    d["idp_saml_sso_post"]   = f"{base}/saml/sso"
    d["idp_saml_sso_redirect"]= f"{base}/saml/sso"
    d["idp_saml_slo"]        = f"{base}/saml/slo"
    d["idp_wsfed"]           = f"{base}/wsfed"
    d["idp_oauth_authorize"] = f"{base}/oauth2/authorize"
    d["idp_oauth_token"]     = f"{base}/oauth2/token"
    d["idp_userinfo"]        = f"{base}/oauth2/userinfo"
    d["idp_jwks"]            = f"{base}/.well-known/jwks.json"
    d["idp_discovery"]       = f"{base}/.well-known/openid-configuration"
    d["metadata_xml_url"]    = f"{base}/apps/{aid}/metadata.xml"
    return jsonify(d)


@app.route("/api/fs/tokens/issue", methods=["POST"])
def fs_token_issue():
    data = request.json
    app_id = data.get("app_id")
    subject = data.get("subject","")
    lifetime = int(data.get("lifetime", 3600))
    scopes = data.get("scopes","openid profile email")
    extra = data.get("extra_claims", {})

    a = FSApplication.query.get(app_id) if app_id else None
    if not a:
        return jsonify({"error": "Application not found"}), 404

    # Resolve user groups from DS
    user = DSUser.query.filter(
        db.or_(DSUser.upn==subject, DSUser.email==subject, DSUser.sam_account==subject)
    ).first()
    if user:
        extra.setdefault("groups", [g.name for g in user.groups])
        extra.setdefault("name", user.display_name)
        extra.setdefault("email", user.email)
        extra.setdefault("department", user.department)

    try:
        raw_token, exp = issue_jwt(subject, a, extra, lifetime)
    except ValueError as e:
        return jsonify({"error": str(e)}), 500

    rec = IssuedToken(
        app_id=a.id, subject=subject,
        scopes=scopes,
        extra_claims=json.dumps(extra),
        expires_at=exp,
        raw_token=raw_token,
    )
    db.session.add(rec)
    db.session.commit()
    audit("OK", "FS", "Token issued", f"sub={subject} app={a.name}")
    return jsonify({"ok": True, "token": raw_token, "expires_at": exp.isoformat(), "jti": rec.jti})


@app.route("/api/fs/tokens", methods=["GET"])
def fs_tokens_list():
    tokens = IssuedToken.query.order_by(IssuedToken.issued_at.desc()).limit(100).all()
    return jsonify([t.to_dict() for t in tokens])


@app.route("/api/fs/tokens/<int:tid>/revoke", methods=["POST"])
def fs_token_revoke(tid):
    t = IssuedToken.query.get_or_404(tid)
    t.revoked = True
    db.session.commit()
    audit("WARN", "FS", "Token revoked", f"jti={t.jti} sub={t.subject}")
    return jsonify({"ok": True})


@app.route("/api/fs/tokens/<int:tid>", methods=["DELETE"])
def fs_token_delete(tid):
    """Permanently delete a single token record."""
    t = IssuedToken.query.get_or_404(tid)
    jti = t.jti
    db.session.delete(t)
    db.session.commit()
    audit("WARN", "FS", "Token deleted", f"jti={jti}")
    return jsonify({"ok": True})


@app.route("/api/fs/tokens/delete-revoked", methods=["POST"])
def fs_tokens_delete_revoked():
    """Permanently delete all revoked tokens."""
    count = IssuedToken.query.filter_by(revoked=True).count()
    IssuedToken.query.filter_by(revoked=True).delete()
    db.session.commit()
    audit("WARN", "FS", "Bulk delete revoked tokens", f"{count} tokens deleted")
    return jsonify({"ok": True, "deleted": count})


@app.route("/api/fs/tokens/inspect", methods=["POST"])
def fs_token_inspect():
    raw = request.json.get("token","").strip()
    if not raw:
        return jsonify({"error":"No token"}), 400
    try:
        parts = raw.split(".")
        if len(parts) != 3:
            raise ValueError("Not a JWT (expected 3 parts)")
        pad = lambda s: s + "=" * ((4 - len(s) % 4) % 4)
        header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
        now = datetime.datetime.utcnow().timestamp()
        expired = payload.get("exp", 0) < now
        return jsonify({"ok": True, "header": header, "payload": payload, "expired": expired})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/fs/keys", methods=["GET"])
def fs_keys_list():
    return jsonify([k.to_dict() for k in SigningKey.query.order_by(SigningKey.id.desc()).all()])


@app.route("/api/fs/keys/rotate", methods=["POST"])
def fs_key_rotate():
    """
    Generate a new RSA-2048 signing key.
    If an active key already exists, return an error asking the user to
    delete or deactivate it first.  This prevents accidental key proliferation.
    Pass {"force": true} in the JSON body to override.
    """
    force = (request.json or {}).get("force", False)
    existing_active = SigningKey.query.filter_by(active=True).first()

    if existing_active and not force:
        return jsonify({
            "ok": False,
            "error": f"An active key already exists: {existing_active.kid}. "
                     "Delete it first, or pass force=true to generate alongside it.",
        }), 400

    # Deactivate existing keys
    SigningKey.query.update({"active": False})
    db.session.commit()

    count = SigningKey.query.count() + 1
    kid   = f"idp-key-{count:03d}"
    priv, pub = generate_rsa_keypair()
    k = SigningKey(kid=kid, algorithm="RS256", active=True,
                  private_pem=priv, public_pem=pub)
    db.session.add(k)
    db.session.commit()
    audit("WARN", "FS", "Signing key generated", f"New active key: {kid}")
    return jsonify({"ok": True, "kid": kid})


@app.route("/api/fs/keys/<int:kid>/export-public")
def fs_key_export_public(kid):
    k = SigningKey.query.get_or_404(kid)
    return jsonify({"public_pem": k.public_pem, "kid": k.kid})


@app.route("/api/fs/keys/<int:kid>/download-pem")
def fs_key_download_pem(kid):
    """Download public key as .pem file."""
    k = SigningKey.query.get_or_404(kid)
    from flask import Response
    return Response(k.public_pem, mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={k.kid}-public.pem"})


@app.route("/api/fs/keys/<int:kid>/download-cert")
def fs_key_download_cert(kid):
    """Download as self-signed X.509 certificate PEM (.cer) — import into browser/OS keystore."""
    k = SigningKey.query.get_or_404(kid)
    from flask import Response
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        private_key = load_pem_private_key(k.private_pem.encode(), password=None,
                                           backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,             "IDP-Playground Signing Key"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "IDP-Playground IDP"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, k.kid),
        ])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(private_key, _hashes.SHA256(), default_backend()))
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        audit("OK", "FS", "Certificate (PEM) downloaded", k.kid)
        return Response(cert_pem, mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={k.kid}-cert.cer"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/keys/<int:kid>/download-cert-base64")
def fs_key_download_cert_base64(kid):
    """
    Download certificate in Base64-encoded DER format (.cer) —
    identical to Azure Entra 'Certificate (Base64)' download.
    This is the format most SPs expect for SAML signature verification.
    """
    k = SigningKey.query.get_or_404(kid)
    from flask import Response
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        private_key = load_pem_private_key(k.private_pem.encode(), password=None,
                                           backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,       "IDP-Playground Signing Key"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IDP-Playground IDP"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, k.kid),
        ])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, _hashes.SHA256(), default_backend()))
        # Base64-encoded DER — same as Azure "Certificate (Base64)"
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        b64_cert   = base64.b64encode(der_bytes).decode()
        # Wrap at 64 chars like openssl does
        wrapped = "\n".join(b64_cert[i:i+64] for i in range(0, len(b64_cert), 64))
        pem_b64 = f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"
        audit("OK", "FS", "Certificate (Base64) downloaded", k.kid)
        return Response(pem_b64, mimetype="application/x-pem-file",
            headers={"Content-Disposition": f"attachment; filename={k.kid}-cert-base64.cer"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/keys/<int:kid>/download-cert-raw")
def fs_key_download_cert_raw(kid):
    """
    Download certificate as raw DER binary (.cer) —
    identical to Azure Entra 'Certificate (Raw)' download.
    """
    k = SigningKey.query.get_or_404(kid)
    from flask import Response
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        private_key = load_pem_private_key(k.private_pem.encode(), password=None,
                                           backend=default_backend())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME,       "IDP-Playground Signing Key"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IDP-Playground IDP"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, k.kid),
        ])
        now = datetime.datetime.utcnow()
        cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, _hashes.SHA256(), default_backend()))
        der_bytes = cert.public_bytes(serialization.Encoding.DER)
        audit("OK", "FS", "Certificate (Raw/DER) downloaded", k.kid)
        return Response(der_bytes, mimetype="application/pkix-cert",
            headers={"Content-Disposition": f"attachment; filename={k.kid}-cert-raw.cer"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/fs/keys/<int:kid>/activate", methods=["POST"])
def fs_key_activate(kid):
    """Set this key as the active signing key, deactivate all others."""
    target = SigningKey.query.get_or_404(kid)
    SigningKey.query.update({"active": False})
    target.active = True
    db.session.commit()
    audit("WARN", "FS", "Signing key activated", target.kid)
    return jsonify({"ok": True, "kid": target.kid})


@app.route("/api/fs/keys/<int:kid>", methods=["DELETE"])
def fs_key_delete(kid):
    """Delete a signing key. Cannot delete the last active key."""
    k = SigningKey.query.get_or_404(kid)
    if k.active:
        active_count = SigningKey.query.filter_by(active=True).count()
        if active_count <= 1:
            return jsonify({"ok": False,
                            "error": "Cannot delete the only active signing key. "
                                     "Rotate first to create a new one."}), 400
    kid_val = k.kid
    db.session.delete(k)
    db.session.commit()
    audit("WARN", "FS", "Signing key deleted", kid_val)
    return jsonify({"ok": True})


# ──────────────────────────────────────────────────────────
#  Certificate Authority + Certificate-Based Authentication
# ──────────────────────────────────────────────────────────

@app.route("/api/ds/ca/info", methods=["GET"])
def ds_ca_info():
    """Return the IDP-Playground Root CA certificate details."""
    ca = CertificateAuthority.query.first()
    if not ca:
        return jsonify({"exists": False})
    return jsonify({"exists": True, **ca.to_dict()})


@app.route("/api/ds/ca/generate", methods=["POST"])
def ds_ca_generate():
    """
    Generate the IDP-Playground Root CA keypair (RSA-4096).
    Should only be called once. Subsequent calls regenerate the CA
    and invalidate all previously issued user certificates.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    existing = CertificateAuthority.query.first()
    if existing and not (request.json or {}).get("force", False):
        return jsonify({"ok": False,
                        "error": "CA already exists. Pass force=true to regenerate."}), 400

    # Generate RSA-4096 CA keypair
    priv_key = _rsa.generate_private_key(
        public_exponent=65537, key_size=4096, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,             "IDP-Playground Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,       "IDP-Playground Identity Platform"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,"Certificate Authority"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,            "US"),
    ])
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(days=3650)   # 10 years
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(exp)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(priv_key, _hashes.SHA256(), default_backend()))

    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    fingerprint = cert.fingerprint(_hashes.SHA256()).hex()
    serial = str(cert.serial_number)

    if existing:
        db.session.delete(existing)
    ca = CertificateAuthority(
        common_name="IDP-Playground Root CA",
        private_pem=priv_pem, cert_pem=cert_pem,
        fingerprint=fingerprint, serial=serial,
        not_before=now, not_after=exp,
    )
    db.session.add(ca)
    db.session.commit()
    audit("OK", "DS", "Root CA generated", f"serial={serial[:16]}")
    return jsonify({"ok": True, **ca.to_dict()})


@app.route("/api/ds/ca/download-cert")
def ds_ca_download_cert():
    """Download the Root CA certificate as PEM."""
    ca = CertificateAuthority.query.first()
    if not ca:
        return jsonify({"error": "No CA generated yet"}), 404
    from flask import Response
    return Response(ca.cert_pem, mimetype="application/x-pem-file",
        headers={"Content-Disposition": "attachment; filename=idp-playground-root-ca.pem"})


@app.route("/api/ds/users/<int:uid>/cert/generate", methods=["POST"])
def ds_user_cert_generate(uid):
    """
    Issue a client certificate for a user, signed by the IDP-Playground Root CA.
    The certificate can be imported into a browser for Certificate-Based Auth.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    u  = DSUser.query.get_or_404(uid)
    ca = CertificateAuthority.query.first()
    if not ca:
        return jsonify({"ok": False, "error": "No Root CA — generate one first in Security → IDP-Playground Root CA"}), 400

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    ca_key  = load_pem_private_key(ca.private_pem.encode(), password=None, backend=default_backend())
    ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode(), default_backend())

    lifetime_days = (request.json or {}).get("lifetime_days", 365)

    # Generate user keypair
    user_priv = _rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,          u.display_name or u.upn),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS,        u.email or u.upn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,    "IDP-Playground Identity Platform"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u.department or "Users"),
    ])
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(days=lifetime_days)

    cert = (x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(exp)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.RFC822Name(u.email or u.upn),
        ]), critical=False)
        .sign(ca_key, _hashes.SHA256(), default_backend()))

    from cryptography.hazmat.primitives import hashes as _h
    fingerprint = cert.fingerprint(_h.SHA256()).hex()
    serial      = str(cert.serial_number)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    priv_pem = user_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()

    # Revoke only the user's existing CLIENT CERTIFICATE (not passkeys). Passkeys
    # (WebAuthn / PIN) are stored as UserCertificate rows too, so they must be
    # excluded here — otherwise issuing a cert would silently disable a user's
    # passkey and remove it as a login option.
    UserCertificate.query.filter_by(user_id=uid, revoked=False)\
        .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))\
        .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))\
        .update({"revoked": True}, synchronize_session=False)

    uc = UserCertificate(
        user_id=uid, serial=serial,
        common_name=u.display_name or u.upn,
        cert_pem=cert_pem, private_pem=priv_pem,
        fingerprint=fingerprint,
        not_before=now, not_after=exp,
    )
    db.session.add(uc)

    # Enable CBA on the user
    u.mfa_method  = "cert"
    u.mfa_enabled = True
    db.session.commit()
    audit("OK", "DS", "Client certificate issued", f"{u.upn} serial={serial[:16]}")
    return jsonify({"ok": True, **uc.to_dict()})


@app.route("/api/ds/users/<int:uid>/cert", methods=["GET"])
def ds_user_cert_info(uid):
    """Return the active certificate for a user."""
    uc = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
           .order_by(UserCertificate.id.desc()).first()
    if not uc:
        return jsonify({"exists": False})
    return jsonify({"exists": True, **uc.to_dict()})


@app.route("/api/ds/users/<int:uid>/cert/download-p12", methods=["GET"])
def ds_user_cert_download_p12(uid):
    """
    Download a PKCS#12 bundle (.p12) containing the user's certificate + private key.
    Import this into your browser or OS keystore to enable Certificate-Based Auth.
    """
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404

    from cryptography.hazmat.primitives.serialization import pkcs12 as _pkcs12
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography import x509

    priv = load_pem_private_key(uc.private_pem.encode(), password=None, backend=default_backend())
    cert = x509.load_pem_x509_certificate(uc.cert_pem.encode(), default_backend())

    ca = CertificateAuthority.query.first()
    ca_certs = []
    if ca:
        ca_certs = [x509.load_pem_x509_certificate(ca.cert_pem.encode(), default_backend())]

    p12_bytes = _pkcs12.serialize_key_and_certificates(
        name=uc.common_name.encode(),
        key=priv, cert=cert, cas=ca_certs,
        encryption_algorithm=serialization.NoEncryption(),
    )
    u = DSUser.query.get(uid)
    fname = f"{(u.sam_account or 'user').replace(' ','_')}-cert.p12"
    from flask import Response
    audit("OK", "DS", "PKCS#12 bundle downloaded", u.upn if u else str(uid))
    return Response(p12_bytes, mimetype="application/x-pkcs12",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


def _get_user_cert(uid):
    """Return the latest non-revoked, non-passkey UserCertificate for a user."""
    return (UserCertificate.query.filter_by(user_id=uid, revoked=False)
            .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))
            .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))
            .order_by(UserCertificate.id.desc()).first())


@app.route("/api/ds/users/<int:uid>/cert/download-pem", methods=["GET"])
def ds_user_cert_download_pem(uid):
    """Download the user certificate as a PEM (.cer) file — public cert only."""
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404
    u = DSUser.query.get(uid)
    fname = f"{(u.sam_account or 'user').replace(' ','_')}-cert.cer"
    from flask import Response
    audit("OK", "DS", "Certificate (PEM) downloaded", u.upn if u else str(uid))
    return Response(uc.cert_pem, mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/ds/users/<int:uid>/cert/download-base64", methods=["GET"])
def ds_user_cert_download_base64(uid):
    """Download the user certificate as Base64-encoded DER in PEM wrapper (Azure style)."""
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(uc.cert_pem.encode(), default_backend())
    der  = cert.public_bytes(serialization.Encoding.DER)
    b64  = base64.b64encode(der).decode()
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    pem_b64 = f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----\n"
    u = DSUser.query.get(uid)
    fname = f"{(u.sam_account or 'user').replace(' ','_')}-cert-base64.cer"
    from flask import Response
    audit("OK", "DS", "Certificate (Base64) downloaded", u.upn if u else str(uid))
    return Response(pem_b64, mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/ds/users/<int:uid>/cert/download-raw", methods=["GET"])
def ds_user_cert_download_raw(uid):
    """Download the user certificate as raw binary DER (.cer)."""
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(uc.cert_pem.encode(), default_backend())
    der  = cert.public_bytes(serialization.Encoding.DER)
    u = DSUser.query.get(uid)
    fname = f"{(u.sam_account or 'user').replace(' ','_')}-cert-raw.cer"
    from flask import Response
    audit("OK", "DS", "Certificate (Raw DER) downloaded", u.upn if u else str(uid))
    return Response(der, mimetype="application/pkix-cert",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/ds/users/<int:uid>/cert/download-key", methods=["GET"])
def ds_user_cert_download_key(uid):
    """Download the user's private key as a PEM (.key) file."""
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404
    u = DSUser.query.get(uid)
    fname = f"{(u.sam_account or 'user').replace(' ','_')}-private.key"
    from flask import Response
    audit("WARN", "DS", "Private key downloaded", u.upn if u else str(uid))
    return Response(uc.private_pem, mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/ds/users/<int:uid>/cert/install-script", methods=["GET"])
def ds_user_cert_install_script(uid):
    """
    Download a Windows PowerShell script that imports the user's .p12 into the
    Windows certificate trust store (CurrentUser\\My + Root for the CA) so the
    browser stops prompting for the cert until it is removed or expires.
    """
    uc = _get_user_cert(uid)
    if not uc:
        return jsonify({"error": "No certificate found"}), 404
    u  = DSUser.query.get(uid)
    ca = CertificateAuthority.query.first()
    sam = (u.sam_account or "user").replace(" ", "_")
    base = "http://localhost:8080"
    ca_block = ""
    if ca:
        ca_block = f'''
# Import the IDP-Playground Root CA into Trusted Root so the client cert chain is trusted
Write-Host "Downloading IDP-Playground Root CA..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "{base}/api/ds/ca/download-cert" -OutFile "$env:TEMP\\idp-playground-root-ca.cer"
Import-Certificate -FilePath "$env:TEMP\\idp-playground-root-ca.cer" -CertStoreLocation Cert:\\CurrentUser\\Root
Write-Host "Root CA installed into CurrentUser\\Root" -ForegroundColor Green
'''
    script = f'''# IDP-Playground Certificate Installer for {u.display_name or u.upn}
# Run in PowerShell. This installs your client certificate into the Windows
# certificate store so your browser uses it automatically for Certificate-Based Auth.
# The certificate stays installed until you remove it or it expires.

$ErrorActionPreference = "Stop"
Write-Host "IDP-Playground Certificate Installer" -ForegroundColor Cyan
Write-Host "User: {u.display_name or u.upn}" -ForegroundColor Cyan
{ca_block}
# Download the personal certificate bundle (.p12)
Write-Host "Downloading your certificate bundle..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "{base}/api/ds/users/{uid}/cert/download-p12" -OutFile "$env:TEMP\\{sam}-cert.p12"

# Import into CurrentUser\\My (personal certificates). No password was set on the bundle.
$empty = New-Object System.Security.SecureString
Import-PfxCertificate -FilePath "$env:TEMP\\{sam}-cert.p12" -CertStoreLocation Cert:\\CurrentUser\\My -Password $empty
Write-Host "Client certificate installed into CurrentUser\\My" -ForegroundColor Green

# Clean up temp files
Remove-Item "$env:TEMP\\{sam}-cert.p12" -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\\idp-playground-root-ca.cer" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done. Restart your browser. It will now offer this certificate automatically." -ForegroundColor Green
Write-Host "To remove later: open certmgr.msc, find the cert under Personal, and delete it." -ForegroundColor Yellow
'''
    fname = f"install-{sam}-cert.ps1"
    from flask import Response
    audit("OK", "DS", "Cert install script downloaded", u.upn if u else str(uid))
    return Response(script, mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/ds/users/<int:uid>/cert/revoke", methods=["POST"])
def ds_user_cert_revoke(uid):
    """Revoke the user's current certificate and disable CBA."""
    UserCertificate.query.filter_by(user_id=uid, revoked=False).update({
        "revoked": True,
        "revoked_at": datetime.datetime.utcnow(),
    })
    u = DSUser.query.get_or_404(uid)
    if u.mfa_method == "cert":
        u.mfa_enabled = False
        u.mfa_method  = "totp"
    db.session.commit()
    audit("WARN", "DS", "User certificate revoked", u.upn)
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>/mfa/verify-cert", methods=["POST"])
def ds_user_mfa_verify_cert(uid):
    """
    Verify certificate-based auth. Accepts EITHER:
      - a JSON body {"fingerprint": "..."} (client computed the fingerprint), OR
      - a multipart file upload field "cert_file" (server parses it directly).
    The file path is preferred because the server uses its own robust parser,
    so the client never has to understand certificate formats.
    """
    u = DSUser.query.get(uid)
    if not u:
        return jsonify({"ok": False, "verified": False, "error": "User not found"}), 404

    fingerprint = ""
    # Path A: raw file upload
    cert_file = request.files.get("cert_file")
    if cert_file is not None and (cert_file.filename or "").strip():
        cert_bytes = cert_file.read()
        fp, perr = _extract_cert_fingerprint(cert_bytes)
        if not fp:
            audit("WARN", "DS", "CBA parse failed", f"{u.upn}: {perr}")
            return jsonify({"ok": False, "verified": False,
                            "error": f"Invalid certificate: {perr}"}), 400
        fingerprint = fp
    else:
        # Path B: JSON fingerprint
        body = request.json or {}
        fingerprint = body.get("fingerprint", "")

    fingerprint = fingerprint.strip().lower().replace(":", "")
    if not fingerprint:
        return jsonify({"ok": False, "verified": False,
                        "error": "No certificate or fingerprint provided"}), 400

    # Latest active certificate, excluding passkey rows stored in the same table
    uc = (UserCertificate.query.filter_by(user_id=uid, revoked=False)
          .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))
          .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))
          .order_by(UserCertificate.id.desc()).first())
    if not uc:
        return jsonify({"ok": False, "verified": False,
                        "error": "No active certificate for this user"}), 400

    stored_fp = (uc.fingerprint or "").strip().lower().replace(":", "")
    if fingerprint == stored_fp:
        token = secrets.token_hex(32)
        u.cert_auth_token = token
        u.cert_auth_exp   = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        db.session.commit()
        audit("OK", "DS", "CBA verified", u.upn)
        return jsonify({"ok": True, "verified": True, "auth_token": token})

    audit("WARN", "DS", "CBA failed", u.upn)
    return jsonify({"ok": False, "verified": False,
                    "error": "Certificate does not match the one on file"})


# ──────────────────────────────────────────────────────────
#  WebAuthn / Passkey  (FIDO2 — biometric / hardware key)
# ──────────────────────────────────────────────────────────

@app.route("/api/ds/users/<int:uid>/passkey/register-options", methods=["POST"])
def passkey_register_options(uid):
    """Return WebAuthn creation options for passkey registration."""
    u = DSUser.query.get_or_404(uid)
    rp_id     = request.host.split(":")[0]
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    user_id_b64 = base64.urlsafe_b64encode(str(uid).encode()).decode()
    # Store challenge temporarily
    u.cert_auth_token = f"passkey_reg:{challenge}"
    u.cert_auth_exp   = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    db.session.commit()
    options = {
        "rp":      {"id": rp_id, "name": "IDP-Playground Identity Platform"},
        "user":    {"id": user_id_b64, "name": u.upn, "displayName": u.display_name or u.upn},
        "challenge": challenge,
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},    # ES256
            {"type": "public-key", "alg": -257},   # RS256
        ],
        "timeout": 60000,
        "attestation": "none",
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "preferred",
        },
    }
    audit("OK", "DS", "Passkey registration options issued", u.upn)
    return jsonify(options)


@app.route("/api/ds/users/<int:uid>/passkey/register-complete", methods=["POST"])
def passkey_register_complete(uid):
    """Store the passkey credential ID after successful browser registration."""
    u    = DSUser.query.get_or_404(uid)
    data = request.json or {}
    cred_id = data.get("id", "")
    if not cred_id:
        return jsonify({"ok": False, "error": "No credential ID provided"}), 400
    # Revoke any existing passkey for this user
    UserCertificate.query.filter_by(user_id=uid, revoked=False)\
        .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))\
        .update({"revoked": True})
    # Store credential as a special certificate record
    uc = UserCertificate(
        user_id=uid,
        serial=f"passkey-{secrets.token_hex(8)}",
        common_name=f"Passkey — {u.display_name or u.upn}",
        cert_pem=f"PASSKEY_CRED_ID:{cred_id}",
        private_pem="PASSKEY_NO_PRIVATE_KEY",
        fingerprint=base64.urlsafe_b64encode(cred_id.encode()).decode()[:64],
        not_before=datetime.datetime.utcnow(),
        not_after=datetime.datetime.utcnow() + datetime.timedelta(days=3650),
    )
    db.session.add(uc)
    u.mfa_method  = "passkey"
    u.mfa_enabled = True
    u.cert_auth_token = None
    db.session.commit()
    audit("OK", "DS", "Passkey registered", u.upn)
    return jsonify({"ok": True, "credential_id": cred_id})


@app.route("/api/ds/users/<int:uid>/passkey/auth-options", methods=["POST"])
def passkey_auth_options(uid):
    """Return WebAuthn request options for passkey authentication."""
    u = DSUser.query.get_or_404(uid)
    rp_id     = request.host.split(":")[0]
    challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    u.cert_auth_token = f"passkey_auth:{challenge}"
    u.cert_auth_exp   = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    db.session.commit()
    passkeys = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
                 .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%")).all()
    allow_credentials = [
        {"type": "public-key", "id": pk.cert_pem.replace("PASSKEY_CRED_ID:", "")}
        for pk in passkeys
    ]
    return jsonify({
        "challenge": challenge, "timeout": 60000,
        "rpId": rp_id, "allowCredentials": allow_credentials,
        "userVerification": "preferred",
    })


@app.route("/api/ds/users/<int:uid>/passkey/auth-complete", methods=["POST"])
def passkey_auth_complete(uid):
    """Verify passkey authentication — match credential ID against stored passkeys."""
    u       = DSUser.query.get_or_404(uid)
    data    = request.json or {}
    cred_id = data.get("id", "")
    if not cred_id:
        return jsonify({"ok": False, "verified": False, "error": "No credential ID"}), 400
    passkeys = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
                 .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%")).all()
    matched = any(pk.cert_pem.replace("PASSKEY_CRED_ID:", "") == cred_id for pk in passkeys)
    if matched:
        token = secrets.token_hex(32)
        u.cert_auth_token = token
        u.cert_auth_exp   = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        db.session.commit()
        audit("OK", "DS", "Passkey auth verified", u.upn)
        return jsonify({"ok": True, "verified": True, "auth_token": token})
    audit("WARN", "DS", "Passkey auth failed", u.upn)
    return jsonify({"ok": False, "verified": False, "error": "Credential not recognized"})


@app.route("/api/ds/users/<int:uid>/passkey/register-pin", methods=["POST"])
def passkey_register_pin(uid):
    """
    Register a simple 4-digit PIN as a passkey credential.
    This is an alternative to a WebAuthn biometric/hardware passkey for
    environments without a platform authenticator. The PIN is stored hashed.
    """
    u    = DSUser.query.get_or_404(uid)
    data = request.json or {}
    pin  = str(data.get("pin", "")).strip()
    if not (pin.isdigit() and len(pin) == 4):
        return jsonify({"ok": False, "error": "PIN must be exactly 4 digits"}), 400
    pin_hash = bcrypt.hashpw(pin.encode(), bcrypt.gensalt()).decode()
    # Revoke any existing PIN passkey
    UserCertificate.query.filter_by(user_id=uid, revoked=False)\
        .filter(UserCertificate.cert_pem.like("PASSKEY_PIN:%"))\
        .update({"revoked": True})
    uc = UserCertificate(
        user_id=uid,
        serial=f"pinpasskey-{secrets.token_hex(8)}",
        common_name=f"PIN Passkey — {u.display_name or u.upn}",
        cert_pem=f"PASSKEY_PIN:{pin_hash}",
        private_pem="PASSKEY_PIN_NO_KEY",
        fingerprint=secrets.token_hex(16),
        not_before=datetime.datetime.utcnow(),
        not_after=datetime.datetime.utcnow() + datetime.timedelta(days=3650),
    )
    db.session.add(uc)
    u.mfa_method  = "passkey"
    u.mfa_enabled = True
    db.session.commit()
    audit("OK", "DS", "PIN passkey registered", u.upn)
    return jsonify({"ok": True, "pin_set": True})


@app.route("/api/ds/users/<int:uid>/passkey/verify-pin", methods=["POST"])
def passkey_verify_pin(uid):
    """Verify a 4-digit PIN passkey for login."""
    u    = DSUser.query.get_or_404(uid)
    data = request.json or {}
    pin  = str(data.get("pin", "")).strip()
    if not pin:
        return jsonify({"ok": False, "verified": False, "error": "No PIN provided"}), 400
    rows = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
             .filter(UserCertificate.cert_pem.like("PASSKEY_PIN:%")).all()
    for row in rows:
        stored_hash = row.cert_pem.replace("PASSKEY_PIN:", "")
        try:
            if bcrypt.checkpw(pin.encode(), stored_hash.encode()):
                token = secrets.token_hex(32)
                u.cert_auth_token = token
                u.cert_auth_exp   = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
                db.session.commit()
                audit("OK", "DS", "PIN passkey verified", u.upn)
                return jsonify({"ok": True, "verified": True, "auth_token": token})
        except Exception:
            continue
    audit("WARN", "DS", "PIN passkey failed", u.upn)
    return jsonify({"ok": False, "verified": False, "error": "Incorrect PIN"})


@app.route("/api/ds/users/<int:uid>/mfa/status", methods=["GET"])
def ds_user_mfa_status(uid):
    """
    Report which MFA methods are actually configured for a user, so the UI can
    show a clear legend instead of relying on a single mfa_enabled flag. A user
    counts as having MFA configured if ANY of: TOTP secret, email method,
    a client certificate, a WebAuthn passkey, or a PIN passkey.
    """
    u = DSUser.query.get(uid)
    if not u:
        return jsonify({"error": "User not found"}), 404

    has_totp = bool(u.totp_secret)
    has_email = (u.mfa_method == "email" and bool(u.email))
    has_cert = (UserCertificate.query.filter_by(user_id=uid, revoked=False)
                .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))
                .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))
                .count() > 0)
    has_webauthn = (UserCertificate.query.filter_by(user_id=uid, revoked=False)
                    .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))
                    .count() > 0)
    has_pin = (UserCertificate.query.filter_by(user_id=uid, revoked=False)
               .filter(UserCertificate.cert_pem.like("PASSKEY_PIN:%"))
               .count() > 0)
    has_sms  = bool(u.sms_enrolled)
    has_push = bool(u.push_enrolled)

    methods = []
    if has_totp:     methods.append("Authenticator (TOTP)")
    if has_email:    methods.append("Email OTP")
    if has_cert:     methods.append("Certificate (CBA)")
    if has_webauthn: methods.append("Passkey (WebAuthn)")
    if has_pin:      methods.append("PIN passkey")
    if has_sms:      methods.append("SMS / Voice OTP")
    if has_push:     methods.append("Push Notification")

    configured = len(methods) > 0

    # Self-heal the mfa_enabled flag: if a method exists but the flag is off
    # (e.g. legacy data), turn it on; if the flag is on but nothing is
    # configured, the UI will show the "no method configured yet" legend.
    if configured and not u.mfa_enabled:
        u.mfa_enabled = True
        db.session.commit()

    return jsonify({
        "mfa_enabled":     u.mfa_enabled,
        "configured":      configured,
        "methods":         methods,
        "has_totp":        has_totp,
        "has_email":       has_email,
        "has_cert":        has_cert,
        "has_webauthn":    has_webauthn,
        "has_pin":         has_pin,
        "has_sms":         has_sms,
        "has_push":        has_push,
        "primary_method":  u.mfa_method,
    })


@app.route("/api/ds/users/<int:uid>/passkey/info", methods=["GET"])
def passkey_info(uid):
    """Return what passkey types are registered for a user."""
    DSUser.query.get_or_404(uid)
    webauthn = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
                 .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%")).count()
    pin = UserCertificate.query.filter_by(user_id=uid, revoked=False)\
            .filter(UserCertificate.cert_pem.like("PASSKEY_PIN:%")).count()
    return jsonify({
        "has_webauthn": webauthn > 0,
        "has_pin":      pin > 0,
        "any":          (webauthn + pin) > 0,
    })


@app.route("/api/fs/mfa", methods=["GET"])
def fs_mfa_list():
    return jsonify([{
        "id": m.id, "method": m.method, "label": m.label,
        "icon": m.icon, "enabled": m.enabled,
    } for m in MFAPolicy.query.all()])


@app.route("/api/fs/mfa/<int:mid>/toggle", methods=["POST"])
def fs_mfa_toggle(mid):
    m = MFAPolicy.query.get_or_404(mid)
    m.enabled = not m.enabled
    db.session.commit()
    audit("OK", "FS", f"MFA {m.method} {'enabled' if m.enabled else 'disabled'}", "")
    return jsonify({"ok": True, "enabled": m.enabled})


# ── MFA setup & verify ──

@app.route("/api/ds/users/<int:uid>/mfa/setup-totp", methods=["POST"])
def ds_user_mfa_setup_totp(uid):
    """
    Generate a new TOTP secret and return the QR code as an inline SVG.
    IMPORTANT: The secret is committed to the DB immediately so rescanning
    the QR code always reflects the latest secret in the database.
    """
    u = DSUser.query.get_or_404(uid)
    # Generate and immediately commit the secret BEFORE generating the QR
    # so the secret in the QR matches what's stored in the DB.
    u.totp_secret = pyotp.random_base32()
    u.mfa_method  = "totp"
    db.session.commit()  # commit first, THEN build the URI/QR

    uri = pyotp.totp.TOTP(u.totp_secret).provisioning_uri(
        name=u.upn, issuer_name="IDP-Playground"
    )

    # Generate QR code as SVG string
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory, box_size=6)
    svg_buf = io.BytesIO()
    img.save(svg_buf)
    svg_str = svg_buf.getvalue().decode("utf-8")

    audit("OK", "DS", "TOTP secret generated", u.upn)
    return jsonify({
        "ok":         True,
        "totp_secret": u.totp_secret,
        "otpauth_uri": uri,
        "qr_svg":      svg_str,
    })


@app.route("/api/ds/users/<int:uid>/mfa/totp-debug", methods=["GET"])
def ds_user_mfa_totp_debug(uid):
    """
    DEV ONLY — return the current expected TOTP code for a user.
    Use this to verify the secret is correct if authentication keeps failing.
    Remove in production.
    """
    u = DSUser.query.get_or_404(uid)
    if not u.totp_secret:
        return jsonify({"error": "No TOTP secret configured"}), 400
    totp = pyotp.TOTP(u.totp_secret)
    now_code = totp.now()
    import time as _time
    remaining = 30 - (int(_time.time()) % 30)
    return jsonify({
        "upn":         u.upn,
        "totp_secret": u.totp_secret,
        "current_code": now_code,
        "seconds_remaining": remaining,
        "otpauth_uri": totp.provisioning_uri(name=u.upn, issuer_name="IDP-Playground"),
    })


@app.route("/api/ds/users/<int:uid>/mfa/verify-totp", methods=["POST"])
def ds_user_mfa_verify_totp(uid):
    """Verify a TOTP code for a user."""
    u = DSUser.query.get_or_404(uid)
    code = request.json.get("code", "").strip()
    if not code:
        return jsonify({"ok": False, "error": "Code required"}), 400
    if not u.totp_secret:
        return jsonify({"ok": False, "error": "TOTP not set up for this user"}), 400
    valid = u.verify_totp(code)
    if valid:
        u.mfa_enabled = True
        db.session.commit()
        audit("OK", "DS", "TOTP verified & MFA enabled", u.upn)
    else:
        audit("WARN", "DS", "TOTP verification failed", u.upn)
    return jsonify({"ok": valid, "error": "" if valid else "Invalid or expired code"})


@app.route("/api/ds/users/<int:uid>/mfa/send-email-otp", methods=["POST"])
def ds_user_mfa_send_email_otp(uid):
    """Generate and send an email OTP to the user's email address."""
    u = DSUser.query.get_or_404(uid)
    if not u.email:
        return jsonify({"ok": False, "error": "User has no email address"}), 400

    code = u.generate_email_otp()
    db.session.commit()

    ok, msg = send_email_otp(u.email, u.display_name or u.upn, code)
    audit("OK" if ok else "WARN", "DS",
          "Email OTP sent" if ok else "Email OTP (console fallback)",
          f"{u.upn} → {u.email}")
    return jsonify({
        "ok": True,  # Always OK — code is on console if SMTP not configured
        "email": u.email,
        "smtp_sent": ok,
        "message": msg,
        # Only include code in response when SMTP is NOT configured (dev mode)
        "dev_code": code if not ok else None,
    })


@app.route("/api/ds/users/<int:uid>/mfa/verify-email-otp", methods=["POST"])
def ds_user_mfa_verify_email_otp(uid):
    """Verify the emailed OTP code."""
    u = DSUser.query.get_or_404(uid)
    code = request.json.get("code", "").strip()
    if not code:
        return jsonify({"ok": False, "error": "Code required"}), 400
    valid = u.verify_email_otp(code)
    if valid:
        u.mfa_enabled = True
        u.mfa_method  = "email"
        db.session.commit()
        audit("OK", "DS", "Email OTP verified & MFA enabled", u.upn)
    else:
        audit("WARN", "DS", "Email OTP verification failed", u.upn)
    return jsonify({"ok": valid, "error": "" if valid else "Invalid or expired code"})


@app.route("/api/ds/users/<int:uid>/mfa/disable", methods=["POST"])
def ds_user_mfa_disable(uid):
    """Disable MFA for a user."""
    u = DSUser.query.get_or_404(uid)
    u.mfa_enabled    = False
    u.totp_secret    = None
    u.email_otp_code = None
    u.email_otp_exp  = None
    db.session.commit()
    audit("WARN", "DS", "MFA disabled", u.upn)
    return jsonify({"ok": True})


@app.route("/api/ds/users/<int:uid>/mfa/check", methods=["POST"])
def ds_user_mfa_check(uid):
    """
    Called by external clients (testclient.py) to:
      - Step 1 (no code): determine if MFA is required, auto-send email OTP
      - Step 2 (with code): verify the submitted code

    Accepts optional JSON body:
      { "code": "123456",   -- omit on step 1
        "app_id": 3 }       -- if provided, also checks FSApplication.require_mfa
    """
    u = DSUser.query.get(uid)
    if not u:
        return jsonify({"required": False, "verified": False,
                        "error": "User not found"}), 404
    body = request.json or {}
    code = body.get("code","").strip()

    # Check app-level MFA requirement
    app_id = body.get("app_id")
    app_requires_mfa = False
    if app_id:
        a = FSApplication.query.get(app_id)
        if a:
            app_requires_mfa = a.require_mfa or False

    mfa_needed = u.mfa_enabled or app_requires_mfa

    # If app requires MFA but user has none configured, error early
    if app_requires_mfa and not u.mfa_enabled:
        return jsonify({
            "required": True, "verified": False,
            "error": "App requires MFA but this user has no MFA method configured"
        }), 400

    if not mfa_needed:
        return jsonify({"required": False, "verified": True})

    if not code:
        # Step 1 — inform client what method, auto-send email OTP if needed
        result = {"required": True, "method": u.mfa_method,
                  "verified": False, "email": u.email or ""}
        if u.mfa_method in ("email", "sms", "push"):
            otp = u.generate_email_otp()
            db.session.commit()
            if u.mfa_method == "email" and u.email:
                ok, msg = send_email_otp(u.email, u.display_name or u.upn, otp)
            else:
                ok, msg = False, "Demo delivery — code shown on screen"
            result["smtp_sent"] = ok
            result["dev_code"]  = otp if not ok else None
            result["message"]   = msg
            audit("OK", "DS", f"{u.mfa_method.upper()} OTP generated via check endpoint", u.upn)
        return jsonify(result)

    # Step 2 — verify submitted code
    if u.mfa_method == "totp":
        ok = u.verify_totp(code)
    elif u.mfa_method in ("email", "sms", "push"):
        ok = u.verify_email_otp(code)
        if ok:
            db.session.commit()
    else:
        ok = False

    audit("OK" if ok else "WARN", "DS",
          "MFA verified" if ok else "MFA failed", u.upn)
    return jsonify({"required": True, "method": u.mfa_method, "verified": ok})


@app.route("/api/ds/users/<int:uid>/mfa/enable-sms", methods=["POST"])
def ds_user_enable_sms(uid):
    """Enrol the user in SMS / Voice OTP (demo — codes are shown on screen)."""
    u = DSUser.query.get_or_404(uid)
    phone = (request.json or {}).get("phone", "").strip()
    if phone:
        u.phone = phone
    u.sms_enrolled = True
    u.mfa_method   = "sms"
    u.mfa_enabled  = True
    db.session.commit()
    audit("OK", "DS", "SMS / Voice OTP enrolled", f"{u.upn} ({u.phone or 'no number'})")
    return jsonify({"ok": True, "phone": u.phone or ""})


@app.route("/api/ds/users/<int:uid>/mfa/enable-push", methods=["POST"])
def ds_user_enable_push(uid):
    """Enrol the user in Push Notification (demo — approval shown on screen)."""
    u = DSUser.query.get_or_404(uid)
    u.push_enrolled = True
    u.mfa_method    = "push"
    u.mfa_enabled   = True
    db.session.commit()
    audit("OK", "DS", "Push Notification enrolled", u.upn)
    return jsonify({"ok": True})


# ── Discovery endpoints ──

@app.route("/.well-known/openid-configuration")
def oidc_discovery():
    issuer = app.config["IDPPLAYGROUND_ISSUER"]
    return jsonify({
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth2/authorize",
        "token_endpoint": f"{issuer}/oauth2/token",
        "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "response_types_supported": ["code","token","id_token"],
        "scopes_supported": ["openid","profile","email","groups","offline_access"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "grant_types_supported": ["authorization_code","client_credentials","refresh_token"],
    })


@app.route("/.well-known/jwks.json")
def jwks():
    keys = []
    for k in SigningKey.query.filter_by(active=True).all():
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(k.public_pem.encode(), backend=default_backend())
        pub_numbers = pub.public_key().public_numbers() if hasattr(pub,"public_key") else pub.public_numbers()
        def int_to_b64(n):
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()
        keys.append({
            "kty": "RSA", "use": "sig", "alg": k.algorithm, "kid": k.kid,
            "n": int_to_b64(pub_numbers.n),
            "e": int_to_b64(pub_numbers.e),
        })
    return jsonify({"keys": keys})


# ── Audit ──

@app.route("/api/settings/smtp", methods=["GET"])
def settings_smtp_get():
    return jsonify({
        "host":     app.config["SMTP_HOST"],
        "port":     app.config["SMTP_PORT"],
        "user":     app.config["SMTP_USER"],
        "from":     app.config["SMTP_FROM"],
        "configured": bool(app.config["SMTP_USER"] and app.config["SMTP_PASSWORD"]),
    })


@app.route("/api/settings/smtp", methods=["POST"])
def settings_smtp_post():
    data = request.json
    app.config["SMTP_HOST"]     = data.get("host",     app.config["SMTP_HOST"])
    app.config["SMTP_PORT"]     = int(data.get("port", app.config["SMTP_PORT"]))
    app.config["SMTP_USER"]     = data.get("user",     app.config["SMTP_USER"])
    app.config["SMTP_PASSWORD"] = data.get("password", app.config["SMTP_PASSWORD"])
    app.config["SMTP_FROM"]     = data.get("from",     app.config["SMTP_FROM"])
    audit("OK", "SYSTEM", "SMTP settings updated", data.get("user",""))
    return jsonify({"ok": True})


@app.route("/api/settings/smtp/test", methods=["POST"])
def settings_smtp_test():
    data = request.json
    to = data.get("to","")
    if not to:
        return jsonify({"ok": False, "error": "Recipient required"})
    ok, msg = send_email_otp(to, "Test User", "123456")
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/audit")
def audit_list():
    module = request.args.get("module")
    q = AuditLog.query
    if module:
        q = q.filter_by(module=module)
    logs = q.order_by(AuditLog.id.desc()).limit(200).all()
    return jsonify([l.to_dict() for l in logs])


# ──────────────────────────────────────────────────────────
#  Protocol Endpoints — SAML 2.0 / WS-Fed / OAuth2 authorize
# ──────────────────────────────────────────────────────────

import xml.etree.ElementTree as ET
from urllib.parse import urlencode as _urlencode, parse_qs as _parse_qs

def _login_page_html(protocol: str, callback_url: str, extra: dict = None):
    """Render a minimal login form that posts to /proto-auth."""
    color = {"SAML":"#a78bfa","WS-Fed":"#fb923c","OAuth":"#34d399"}.get(protocol,"#38b6ff")
    extra_fields = "".join(
        f'<input type="hidden" name="{k}" value="{v}">'
        for k, v in (extra or {}).items()
    )
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>IDP-Playground -- Sign In ({protocol})</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root{{--bg:#05080d;--bg2:#090e16;--b2:1px solid #1f3349;--text:#d4e4f5;--muted:#4a6685;--p:{color};}}
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
.box{{background:var(--bg2);border:var(--b2);border-radius:14px;padding:32px;width:100%;max-width:380px;}}
.top{{text-align:center;margin-bottom:24px;}}
.hex{{width:44px;height:44px;background:var(--p);clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);display:flex;align-items:center;justify-content:center;font-size:20px;margin:0 auto 10px;}}
.t{{font-size:18px;font-weight:900;color:#fff;}} .s{{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:2px;margin-top:3px;}}
.fg{{margin-bottom:13px;}} .fl{{display:block;font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.5px;margin-bottom:5px;}}
.fi{{width:100%;background:var(--bg);border:var(--b2);border-radius:8px;padding:10px 13px;color:var(--text);font-family:'Outfit',sans-serif;font-size:13px;outline:none;}}
.fi:focus{{border-color:var(--p);}}
.btn{{width:100%;padding:11px;border-radius:9px;font-family:'Outfit',sans-serif;font-weight:700;font-size:14px;cursor:pointer;border:none;background:var(--p);color:#000;transition:all .18s;}}
.hint{{background:rgba(232,255,71,.04);border:1px solid rgba(232,255,71,.12);border-radius:7px;padding:10px 13px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);line-height:1.8;margin-top:14px;}}
.hint strong{{color:#e8ff47;}} .badge{{display:inline-flex;padding:3px 10px;border-radius:20px;font-family:'IBM Plex Mono',monospace;font-size:9px;border:1px solid;margin-bottom:14px;}}
</style></head><body><div class="box">
<div class="top"><div class="hex">🔐</div><div class="t">IDP-Playground</div><div class="s">SIGN IN TO CONTINUE</div></div>
<div style="text-align:center"><span class="badge" style="color:var(--p);border-color:var(--p)">{protocol} Authentication</span></div>
<form method="POST" action="/proto-auth">
  {extra_fields}
  <input type="hidden" name="protocol" value="{protocol}">
  <input type="hidden" name="callback_url" value="{callback_url}">
  <div class="fg"><label class="fl">UPN / EMAIL</label><input class="fi" name="upn" placeholder="user@corp.idp-playground.local" required autocomplete="username"></div>
  <div class="fg"><label class="fl">PASSWORD</label><input class="fi" name="password" type="password" placeholder="••••••••" required></div>
  <div id="imp-row" style="display:none">
    <div class="fg"><label class="fl">IMPERSONATE USER (UPN or email)</label>
      <input class="fi" name="impersonate" id="imp-input" placeholder="target.user@corp.idp-playground.local" autocomplete="off"></div>
    <div style="font-size:10px;color:var(--muted);font-family:'IBM Plex Mono',monospace;line-height:1.7;margin-bottom:12px">
      Sign in with your <strong style="color:#e8ff47">admin</strong> credentials above, then the token
      is issued as the target user with an actor (act) claim recording who impersonated.
    </div>
  </div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;font-size:11px;color:var(--muted);cursor:pointer" onclick="toggleImp()">
    <input type="checkbox" id="imp-chk" style="cursor:pointer" onclick="event.stopPropagation();toggleImp()">
    <label for="imp-chk" style="cursor:pointer">Sign on behalf of another user (admin only)</label>
  </div>
  <button class="btn" type="submit">Sign In</button>
</form>
<script>
function toggleImp(){{
  var c=document.getElementById('imp-chk'),r=document.getElementById('imp-row');
  if(event && event.target!==c){{c.checked=!c.checked;}}
  r.style.display=c.checked?'block':'none';
  if(!c.checked){{document.getElementById('imp-input').value='';}}
}}
</script>
<div class="hint"><strong>Demo accounts:</strong><br>
administrator@corp.idp-playground.local / <strong>Admin@IDP-Playground1</strong><br>
john.smith@corp.idp-playground.local / <strong>Welcome@1</strong></div>
</div></body></html>"""


@app.route("/proto-auth", methods=["POST"])
def proto_auth():
    """
    Shared credential handler for SAML / WS-Fed / OAuth2 login forms.
    Enforces:
      1. Password verification
      2. Per-user MFA  (user.mfa_enabled)
      3. Per-app  MFA  (FSApplication.require_mfa)
    When MFA is needed the user is shown an MFA challenge page.
    Only after both factors pass is the protocol token issued.
    """
    upn          = request.form.get("upn","").strip()
    password     = request.form.get("password","").strip()
    protocol     = request.form.get("protocol","OIDC")
    callback_url = request.form.get("callback_url","")

    # Collect all extra form params to pass through the MFA step
    extra_params = {k: v for k, v in request.form.items()
                    if k not in ("upn","password")}

    def _back(msg):
        """Re-show login form with error message."""
        page = _login_page_html(protocol, callback_url, extra_params)
        return page + f"<script>alert('{msg}')</script>"

    # ── 1. Find user ─────────────────────────────────────
    user = DSUser.query.filter(
        db.or_(DSUser.upn.ilike(upn), DSUser.email.ilike(upn))
    ).first()

    if not user:
        audit("WARN","FS",f"{protocol} login failed","User not found: "+upn)
        return _back("Invalid credentials")
    if not user.enabled:
        return _back("Account is disabled")
    if user.locked:
        return _back("Account is locked")

    # ── 2. Verify password ───────────────────────────────
    if not user.check_password(password):
        audit("WARN","FS",f"{protocol} login failed","Bad password: "+upn)
        return _back("Invalid credentials")

    # ── 2b. SSO Impersonation ────────────────────────────
    # An admin may sign on behalf of another user. The admin authenticates with
    # their own password (and MFA/cert/passkey), then the token is issued as the
    # target user with an actor (act) claim recording the impersonator.
    impersonate = request.form.get("impersonate","").strip()
    if impersonate:
        admin_groups = {g.name for g in user.groups}
        is_admin = (user.sam_account == "administrator"
                    or "Domain Admins" in admin_groups
                    or "Administrators" in admin_groups)
        if not is_admin:
            audit("WARN","FS",f"{protocol} impersonation denied",
                  f"{user.upn} is not an admin")
            return _back("Only administrators may sign on behalf of another user")
        target = DSUser.query.filter(
            db.or_(DSUser.upn.ilike(impersonate), DSUser.email.ilike(impersonate))
        ).first()
        if not target:
            return _back(f"Impersonation target not found: {impersonate}")
        if not target.enabled:
            return _back("Impersonation target account is disabled")
        # Carry actor + target through the (admin's) secondary auth round-trip.
        extra_params["_impersonator_id"]   = str(user.id)
        extra_params["_impersonate_target"] = str(target.id)
        audit("OK","FS",f"{protocol} impersonation start",
              f"{user.upn} -> {target.upn}")

    # ── 3. Resolve app record & auth options ─────────────
    app_rec = FSApplication.query.filter_by(protocol=protocol).first()
    if not app_rec:
        app_rec = FSApplication.query.first()

    app_requires_mfa = app_rec.require_mfa if app_rec else False
    allow_auth       = bool(app_rec.allow_authenticator) if app_rec else False
    allow_email      = bool(app_rec.allow_email)         if app_rec else False
    allow_sms        = bool(app_rec.allow_sms)           if app_rec else False
    allow_push       = bool(app_rec.allow_push)          if app_rec else False
    allow_cba        = bool(app_rec.allow_cba)           if app_rec else False
    allow_passkey    = bool(app_rec.allow_passkey)       if app_rec else False

    # ── App-authoritative MFA policy ─────────────────────────────
    # The APPLICATION decides whether MFA is required and which second factors
    # are accepted. If the app does not require MFA, login is password-only. If
    # it requires MFA, only methods enabled ON THIS APP and enrolled by the user
    # are offered. Authenticator / Email / SMS / Push are all 6-digit code
    # methods; Certificate (CBA) and Passkey (FIDO2/WebAuthn) are their own tabs.
    if not app_requires_mfa:
        challenge_needed = False
        user_has_otp = allow_cba = allow_passkey = False
    else:
        user_has_cert = (UserCertificate.query.filter_by(user_id=user.id, revoked=False)
                         .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))
                         .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))
                         .count() > 0) or (user.mfa_enabled and user.mfa_method == "cert")
        user_has_passkey = (UserCertificate.query.filter_by(user_id=user.id, revoked=False)
                            .filter(db.or_(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"),
                                           UserCertificate.cert_pem.like("PASSKEY_PIN:%")))
                            .count() > 0) or (user.mfa_enabled and user.mfa_method == "passkey")
        # A user's code-based method is allowed only if the app enables that
        # specific channel (Authenticator/Email/SMS/Push).
        _code_flag = {"totp": allow_auth, "email": allow_email,
                      "sms": allow_sms, "push": allow_push}
        user_code_method = user.mfa_method if (user.mfa_enabled and user.mfa_method in _code_flag) else None
        show_otp     = bool(user_code_method) and _code_flag.get(user_code_method, False)
        show_cert    = allow_cba     and user_has_cert
        show_passkey = allow_passkey and user_has_passkey
        any_app_method = allow_auth or allow_email or allow_sms or allow_push or allow_cba or allow_passkey
        if not any_app_method:
            return _back("This application requires MFA but no authentication method "
                         "is enabled for it. Enable one under Applications → App MFA "
                         "Auth methods.")
        if not (show_otp or show_cert or show_passkey):
            return _back("This application requires MFA but your account has none of "
                         "the methods enabled for this app. Contact your administrator.")
        challenge_needed = True
        # Downstream rendering keys off these three flags
        user_has_otp  = show_otp
        allow_cba     = show_cert
        allow_passkey = show_passkey

    # ── 4. Secondary auth challenge: OTP / Certificate / Passkey ──────────
    if challenge_needed:
        dev_code = ""
        if user_has_otp and user.mfa_method in ("email", "sms", "push"):
            otp = user.generate_email_otp()
            db.session.commit()
            if user.mfa_method == "email" and user.email:
                smtp_ok, _ = send_email_otp(
                    user.email, user.display_name or user.upn, otp)
                dev_code = otp if not smtp_ok else ""
            else:
                dev_code = otp  # SMS / Push simulated — show the code on screen

        color = {"SAML":"#a78bfa","WS-Fed":"#fb923c","OAuth":"#34d399"}.get(protocol,"#38b6ff")
        extra_inputs = "".join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in extra_params.items())
        hidden_common = (extra_inputs +
            f'<input type="hidden" name="protocol" value="{protocol}">' +
            f'<input type="hidden" name="callback_url" value="{callback_url}">' +
            f'<input type="hidden" name="user_id" value="{user.id}">' +
            f'<input type="hidden" name="app_id" value="{app_rec.id if app_rec else ""}">')

        default_tab = "otp" if user_has_otp else ("cert" if allow_cba else "passkey")

        # Tab buttons
        tabs_html = ""
        if user_has_otp:
            lbl = {"totp":"Authenticator","email":"Email Code","sms":"SMS Code","push":"Push Approve"}.get(user.mfa_method, "Code")
            tabs_html += (f'<div class="tab{" on" if default_tab=="otp" else ""}" '
                          f'onclick="show(\'otp\',this)">{lbl}</div>')
        if allow_cba:
            tabs_html += (f'<div class="tab{" on" if default_tab=="cert" else ""}" '
                          f'onclick="show(\'cert\',this)">Certificate</div>')
        if allow_passkey:
            tabs_html += (f'<div class="tab{" on" if default_tab=="passkey" else ""}" '
                          f'onclick="show(\'passkey\',this)">Passkey</div>')

        # OTP pane
        otp_pane = ""
        if user_has_otp:
            _dest = {"email": (user.email or "your email"),
                     "sms": ("SMS to " + (user.phone or "your phone")),
                     "push": "the push notification on your device"}.get(user.mfa_method, "your device")
            hint = ("Enter the 6-digit code from your <strong>authenticator app</strong>"
                    if user.mfa_method == "totp"
                    else ("A 6-digit code was sent via <strong>" + _dest + "</strong>"
                          if not dev_code else "Code generated (demo mode — shown below)"))
            dev_box = ((
                '<div style="background:rgba(232,255,71,.08);border:1px solid rgba(232,255,71,.25);'
                'border-radius:8px;padding:14px;font-family:monospace;font-size:13px;'
                'color:#e8ff47;text-align:center;margin-bottom:14px">DEV MODE — SMTP not configured<br>'
                f'<span style="font-size:28px;letter-spacing:8px;font-weight:900">{dev_code}</span></div>'
            ) if dev_code else "")
            resend = ((
                '<form method="POST" action="/proto-auth-mfa-resend">'
                '<button class="btn ghost" type="submit">Resend Code</button>'
                + hidden_common + '</form>'
            ) if user.mfa_method in ("email", "sms", "push") else "")
            otp_pane = (
                f'<div class="pane{" on" if default_tab=="otp" else ""}" id="pane-otp">'
                f'<div class="info">{hint}</div>{dev_box}'
                f'<form method="POST" action="/proto-auth-mfa">{hidden_common}'
                f'<input type="hidden" name="mfa_method" value="{user.mfa_method}">'
                '<input class="code-input" name="mfa_code" type="text" inputmode="numeric" '
                'pattern="[0-9]*" maxlength="6" placeholder="------" autocomplete="one-time-code">'
                '<button class="btn" type="submit">Verify and Continue</button></form>'
                f'{resend}</div>')

        # Certificate pane (server-side fingerprint extraction)
        cert_pane = ""
        if allow_cba:
            cert_pane = (
                f'<div class="pane{" on" if default_tab=="cert" else ""}" id="pane-cert">'
                '<div class="info">Upload your <strong>IDP-Playground client certificate</strong> '
                '(.cer / .pem / .crt). Get it from IDP-Playground &rarr; IDP-DS &rarr; Users '
                '&rarr; MFA &rarr; Certificate tab.</div>'
                f'<form method="POST" action="/proto-auth-cert" enctype="multipart/form-data">{hidden_common}'
                '<label class="drop" for="cfile">'
                '<input type="file" id="cfile" name="cert_file" accept=".cer,.pem,.crt" '
                'onchange="document.getElementById(\'cname\').textContent=this.files[0]?this.files[0].name:\'\';'
                'document.getElementById(\'cbtn\').disabled=!this.files[0];">'
                '<div style="font-size:26px;margin-bottom:5px">&#128196;</div>'
                '<div style="font-weight:700;font-size:13px">Click to select certificate</div>'
                '<div style="font-size:11px;color:var(--muted)">.cer .pem .crt</div></label>'
                '<div id="cname" style="font-family:monospace;font-size:11px;color:#34d399;'
                'text-align:center;margin-bottom:10px"></div>'
                '<button class="btn green" type="submit" id="cbtn" disabled>'
                'Verify Certificate and Continue</button></form></div>')

        # Passkey pane (WebAuthn in browser, credential ID posted back)
        pk_pane = ""
        if allow_passkey:
            pk_pane = (
                f'<div class="pane{" on" if default_tab=="passkey" else ""}" id="pane-passkey">'
                '<div class="info">Sign in with your <strong>Passkey</strong> '
                '(Face ID, Touch ID, Windows Hello or security key).</div>'
                '<div id="pkmsg" style="display:none;font-family:monospace;font-size:11px;'
                'padding:9px 12px;border-radius:7px;margin-bottom:10px"></div>'
                f'<button class="btn orange" id="pkbtn" onclick="goPasskey({user.id})">'
                'Sign In with Passkey</button>'
                f'<form method="POST" action="/proto-auth-passkey" id="pkform" style="display:none">{hidden_common}'
                '<input type="hidden" name="credential_id" id="pkcred"></form>'
                '<div style="display:flex;align-items:center;gap:8px;margin:16px 0 12px">'
                '<div style="flex:1;height:1px;background:#1f3349"></div>'
                '<span style="font-size:10px;color:#4a6685;font-family:monospace">OR USE YOUR PIN</span>'
                '<div style="flex:1;height:1px;background:#1f3349"></div></div>'
                f'<form method="POST" action="/proto-auth-passkey-pin">{hidden_common}'
                '<input class="code-input" name="pin" type="text" inputmode="numeric" '
                'pattern="[0-9]*" maxlength="4" placeholder="PIN" autocomplete="off" '
                'style="letter-spacing:12px;font-size:22px">'
                '<button class="btn orange" type="submit">Sign In with PIN</button></form></div>')

        style = STYLE_TMPL.replace("%COLOR%", color)
        icon  = {"otp":"&#128274;","cert":"&#129706;","passkey":"&#128273;"}[default_tab]

        return ("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
            "<title>IDP-Playground — Verify Identity</title>"
            "<link href=\"https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Outfit:wght@400;700;800&display=swap\" rel=\"stylesheet\">"
            + style +
            "</head><body><div class=\"box\"><div class=\"top\">"
            f"<div class=\"icon\">{icon}</div>"
            "<div class=\"t\">Verify Your Identity</div>"
            f"<div class=\"s\">{protocol} &middot; SECONDARY AUTHENTICATION</div>"
            f"<div class=\"user-chip\">{user.display_name or upn}</div></div>"
            f"<div class=\"tabs\">{tabs_html}</div>"
            f"{otp_pane}{cert_pane}{pk_pane}"
            "<div class=\"back\"><a href=\"javascript:history.back()\">Cancel</a></div></div>"
            "<script>"
            "function show(p,el){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));"
            "document.querySelectorAll('.pane').forEach(x=>x.classList.remove('on'));"
            "el.classList.add('on');var pn=document.getElementById('pane-'+p);if(pn)pn.classList.add('on');}"
            "function b64ToAb(b){var p=b.replace(/-/g,'+').replace(/_/g,'/');while(p.length%4)p+='=';"
            "var s=atob(p),u=new Uint8Array(s.length);for(var i=0;i<s.length;i++)u[i]=s.charCodeAt(i);return u.buffer;}"
            "async function goPasskey(uid){var b=document.getElementById('pkbtn'),m=document.getElementById('pkmsg');"
            "b.disabled=true;m.style.display='block';m.style.cssText+=';background:rgba(52,211,153,.06);"
            "border:1px solid rgba(52,211,153,.2);color:#34d399;';m.textContent='Requesting passkey options...';"
            "try{var r=await fetch('/api/ds/users/'+uid+'/passkey/auth-options',"
            "{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});"
            "var o=await r.json();if(o.error)throw new Error(o.error);"
            "o.challenge=b64ToAb(o.challenge);"
            "if(o.allowCredentials)o.allowCredentials=o.allowCredentials.map(function(c){return{type:c.type,id:b64ToAb(c.id)};});"
            "m.textContent='Waiting for your authenticator...';"
            "var cred=await navigator.credentials.get({publicKey:o});"
            "document.getElementById('pkcred').value=cred.id;"
            "document.getElementById('pkform').submit();}"
            "catch(e){m.style.cssText+=';background:rgba(248,113,113,.06);border:1px solid rgba(248,113,113,.2);color:#f87171;';"
            "m.textContent='Passkey error: '+e.message;b.disabled=false;}}"
            "</script></body></html>")

    # ── 5. No secondary auth — issue token and dispatch ──
    return _proto_issue_and_dispatch(user, app_rec, protocol, extra_params)


@app.route("/proto-auth-mfa-resend", methods=["POST"])
def proto_auth_mfa_resend():
    """Resend email OTP for SAML/WS-Fed/OAuth2 login."""
    uid = request.form.get("user_id","")
    user = DSUser.query.get(uid)
    if user and user.mfa_method == "email" and user.email:
        otp = user.generate_email_otp()
        db.session.commit()
        send_email_otp(user.email, user.display_name or user.upn, otp)
    # Rebuild MFA page by re-posting to proto-auth
    return redirect(request.referrer or "/")


@app.route("/proto-auth-mfa", methods=["POST"])
def proto_auth_mfa():
    """
    Receive and verify the MFA code submitted by SAML/WS-Fed/OAuth2 login.
    On success, issue the protocol token and dispatch.
    """
    uid      = request.form.get("user_id","")
    app_id   = request.form.get("app_id","")
    method   = request.form.get("mfa_method","totp")
    code     = request.form.get("mfa_code","").strip()
    protocol = request.form.get("protocol","OIDC")

    user    = DSUser.query.get(uid)
    app_rec = FSApplication.query.get(app_id) if app_id else None

    if not user:
        return "Session expired — please start over", 400

    # Collect extra params to pass back on failure
    extra_params = {k: v for k, v in request.form.items()
                    if k not in ("mfa_code","user_id","app_id","mfa_method","protocol","callback_url")}

    def _mfa_error(msg):
        color = {"SAML":"#a78bfa","WS-Fed":"#fb923c","OAuth":"#34d399"}.get(protocol,"#38b6ff")
        extra_inputs = "".join(
            f'<input type="hidden" name="{k}" value="{v}">'
            for k, v in request.form.items() if k != "mfa_code"
        )
        return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>IDP-Playground — MFA Error</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;700;800&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{font-family:'Outfit',sans-serif;background:#05080d;color:#d4e4f5;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}}
.box{{background:#090e16;border:1px solid #1f3349;border-radius:14px;padding:32px;
  width:100%;max-width:380px;text-align:center;}}
.err{{background:rgba(248,113,113,.08);border:1px solid rgba(248,113,113,.2);border-radius:7px;
  padding:12px;font-size:13px;color:#f87171;margin-bottom:20px;}}
.btn{{width:100%;padding:11px;border-radius:9px;font-family:'Outfit',sans-serif;font-weight:700;
  font-size:14px;cursor:pointer;border:none;background:{color};color:#000;}}
</style></head>
<body><div class="box">
<div style="font-size:40px;margin-bottom:14px">⚠️</div>
<div class="err">{msg}</div>
<form method="POST" action="/proto-auth-mfa">
  {extra_inputs}
  <input type="text" name="mfa_code" inputmode="numeric" maxlength="6" autofocus
   placeholder="------"
   style="width:100%;background:#05080d;border:1px solid #1f3349;border-radius:8px;
   padding:14px;color:#d4e4f5;font-size:26px;letter-spacing:10px;text-align:center;
   outline:none;margin-bottom:14px;font-family:monospace;">
  <button class="btn" type="submit">Try Again</button>
</form>
</div></body></html>"""

    if not code:
        return _mfa_error("Please enter your verification code")

    # Verify the code
    verified = False
    if method == "totp":
        verified = user.verify_totp(code)
    elif method == "email":
        verified = user.verify_email_otp(code)
        if verified:
            db.session.commit()

    if not verified:
        audit("WARN","FS",f"{protocol} MFA failed",user.upn)
        return _mfa_error("Invalid or expired code — please try again")

    audit("OK","FS",f"{protocol} MFA verified",user.upn)

    # MFA passed — issue token and dispatch
    return _proto_issue_and_dispatch(user, app_rec, protocol, extra_params)


STYLE_TMPL = """<style>
:root{--bg:#05080d;--bg2:#090e16;--bg3:#0e1620;--b2:1px solid #1f3349;--text:#d4e4f5;--muted:#4a6685;--p:%COLOR%;}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'Outfit',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;
  display:flex;align-items:center;justify-content:center;padding:20px;}
.box{background:var(--bg2);border:var(--b2);border-radius:14px;padding:30px;
  width:100%;max-width:440px;box-shadow:0 0 50px rgba(0,0,0,.5);}
.top{text-align:center;margin-bottom:18px;}
.icon{font-size:38px;margin-bottom:8px;}
.t{font-size:18px;font-weight:900;color:#fff;}
.s{font-family:'IBM Plex Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:2px;margin-top:3px;}
.user-chip{display:inline-flex;padding:4px 12px;border-radius:20px;background:rgba(56,182,255,.08);
  border:var(--b2);font-family:'IBM Plex Mono',monospace;font-size:10px;color:#38b6ff;margin-top:8px;}
.tabs{display:flex;border:var(--b2);border-radius:9px;overflow:hidden;margin-bottom:16px;}
.tab{flex:1;padding:9px 4px;font-weight:700;font-size:12px;cursor:pointer;background:var(--bg3);
  color:var(--muted);text-align:center;transition:all .18s;}
.tab.on{background:var(--p);color:#000;}
.tab:not(:last-child){border-right:var(--b2);}
.pane{display:none;}.pane.on{display:block;}
.info{background:rgba(167,139,250,.06);border:1px solid rgba(167,139,250,.2);border-radius:8px;
  padding:11px 14px;font-size:12px;color:var(--muted);line-height:1.7;margin-bottom:14px;}
.code-input{width:100%;background:var(--bg);border:var(--b2);border-radius:8px;padding:14px;
  color:var(--text);font-family:'IBM Plex Mono',monospace;font-size:26px;letter-spacing:10px;
  text-align:center;outline:none;margin-bottom:14px;}
.code-input:focus{border-color:var(--p);}
.btn{width:100%;padding:11px;border-radius:9px;font-weight:700;font-size:14px;cursor:pointer;
  border:none;background:var(--p);color:#000;transition:all .18s;margin-bottom:8px;font-family:'Outfit',sans-serif;}
.btn:disabled{opacity:.4;cursor:not-allowed;}
.btn.ghost{background:transparent;color:var(--muted);border:var(--b2);}
.btn.green{background:rgba(52,211,153,.18);color:#34d399;border:1px solid rgba(52,211,153,.35);}
.btn.orange{background:rgba(251,146,60,.18);color:#fb923c;border:1px solid rgba(251,146,60,.35);}
.drop{display:block;width:100%;box-sizing:border-box;border:1px dashed #1f3349;border-radius:9px;padding:20px 14px;text-align:center;
  cursor:pointer;margin-bottom:10px;transition:all .18s;}
.drop:hover{border-color:#34d399;background:rgba(52,211,153,.04);}
.drop input{display:none;}
.back{text-align:center;margin-top:10px;font-size:12px;color:var(--muted);}
.back a{color:#38b6ff;text-decoration:none;}
</style>"""


@app.route("/proto-auth-cert", methods=["POST"])
def proto_auth_cert():
    """
    Certificate-Based Auth for SAML / WS-Fed / OAuth2 flows.
    Receives the uploaded certificate, extracts the SHA-256 fingerprint
    server-side, verifies it against the user's issued certificate,
    then issues the protocol token.
    """
    uid      = request.form.get("user_id","")
    app_id   = request.form.get("app_id","")
    protocol = request.form.get("protocol","OIDC")
    user     = DSUser.query.get(uid)
    app_rec  = FSApplication.query.get(app_id) if app_id else None
    if not user:
        return "Session expired — please start over", 400

    extra_params = {k: v for k, v in request.form.items()
                    if k not in ("user_id","app_id","protocol","callback_url")}

    cert_file = request.files.get("cert_file")
    if not cert_file or not (cert_file.filename or "").strip():
        return "No certificate file uploaded — go back and try again", 400
    cert_bytes = cert_file.read()
    if not cert_bytes:
        return "Certificate file is empty — go back and try again", 400
    fingerprint, perr = _extract_cert_fingerprint(cert_bytes)
    if not fingerprint:
        return f"Invalid certificate file: {perr}", 400

    uc = UserCertificate.query.filter_by(user_id=user.id, revoked=False)\
           .filter(~UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%"))\
           .filter(~UserCertificate.cert_pem.like("PASSKEY_PIN:%"))\
           .order_by(UserCertificate.id.desc()).first()
    if not uc or uc.fingerprint.strip().lower() != fingerprint.strip().lower():
        audit("WARN","FS",f"{protocol} CBA failed",user.upn)
        return "Certificate not recognized or revoked — go back and try again", 401

    audit("OK","FS",f"{protocol} CBA verified",user.upn)
    return _proto_issue_and_dispatch(user, app_rec, protocol, extra_params)


@app.route("/proto-auth-passkey", methods=["POST"])
def proto_auth_passkey():
    """
    Passkey (WebAuthn) auth for SAML / WS-Fed / OAuth2 flows.
    The browser completed navigator.credentials.get(); the credential ID
    is verified against the user's registered passkeys.
    """
    uid      = request.form.get("user_id","")
    app_id   = request.form.get("app_id","")
    protocol = request.form.get("protocol","OIDC")
    cred_id  = request.form.get("credential_id","").strip()
    user     = DSUser.query.get(uid)
    app_rec  = FSApplication.query.get(app_id) if app_id else None
    if not user:
        return "Session expired — please start over", 400

    extra_params = {k: v for k, v in request.form.items()
                    if k not in ("user_id","app_id","protocol","callback_url","credential_id")}

    passkeys = UserCertificate.query.filter_by(user_id=user.id, revoked=False)\
                 .filter(UserCertificate.cert_pem.like("PASSKEY_CRED_ID:%")).all()
    if not cred_id or not any(
            pk.cert_pem.replace("PASSKEY_CRED_ID:","") == cred_id for pk in passkeys):
        audit("WARN","FS",f"{protocol} passkey failed",user.upn)
        return "Passkey not recognized — register it in IDP-Playground first", 401

    audit("OK","FS",f"{protocol} passkey verified",user.upn)
    return _proto_issue_and_dispatch(user, app_rec, protocol, extra_params)


@app.route("/proto-auth-passkey-pin", methods=["POST"])
def proto_auth_passkey_pin():
    """
    PIN passkey auth for SAML / WS-Fed / OAuth2 flows.
    Verifies a 4-digit PIN against the user's registered PIN passkey.
    """
    uid      = request.form.get("user_id","")
    app_id   = request.form.get("app_id","")
    protocol = request.form.get("protocol","OIDC")
    pin      = request.form.get("pin","").strip()
    user     = DSUser.query.get(uid)
    app_rec  = FSApplication.query.get(app_id) if app_id else None
    if not user:
        return "Session expired — please start over", 400

    extra_params = {k: v for k, v in request.form.items()
                    if k not in ("user_id","app_id","protocol","callback_url","pin")}

    rows = UserCertificate.query.filter_by(user_id=user.id, revoked=False)\
             .filter(UserCertificate.cert_pem.like("PASSKEY_PIN:%")).all()
    ok = False
    for row in rows:
        stored = row.cert_pem.replace("PASSKEY_PIN:", "")
        try:
            if pin and bcrypt.checkpw(pin.encode(), stored.encode()):
                ok = True
                break
        except Exception:
            continue
    if not ok:
        audit("WARN","FS",f"{protocol} PIN passkey failed",user.upn)
        return "Incorrect PIN — go back and try again", 401

    audit("OK","FS",f"{protocol} PIN passkey verified",user.upn)
    return _proto_issue_and_dispatch(user, app_rec, protocol, extra_params)


def _proto_issue_and_dispatch(user, app_rec, protocol: str, extra_params: dict):
    """Issue a token and dispatch to the correct protocol handler."""
    # ── Impersonation swap ───────────────────────────────
    # If the authenticated user is an admin impersonating someone, switch the
    # token subject to the target and record the admin as the actor (RFC 8693).
    act_claim = None
    imp_id    = extra_params.pop("_impersonator_id", None)
    tgt_id    = extra_params.pop("_impersonate_target", None)
    if imp_id and tgt_id:
        impersonator = DSUser.query.get(imp_id)
        target       = DSUser.query.get(tgt_id)
        if impersonator and target:
            act_claim = {"sub": impersonator.upn,
                         "name": impersonator.display_name or impersonator.upn}
            audit("OK","FS",f"{protocol} impersonation token",
                  f"{impersonator.upn} acting as {target.upn}")
            user = target   # issue everything below as the target user

    groups = [g.name for g in user.groups]

    claims = {
        "name":       user.display_name or "",
        "email":      user.email or "",
        "department": user.department or "",
        "groups":     groups,
        "given_name": user.given_name or "",
        "surname":    user.surname or "",
        "amr":        ["pwd","otp"] if user.mfa_enabled else ["pwd"],
    }
    if act_claim:
        claims["act"] = act_claim

    try:
        raw_token, exp = issue_jwt(user.upn, app_rec, claims,
            app_rec.token_lifetime if app_rec else 3600)
    except Exception as e:
        return f"Token issuance error: {e}", 500

    rec = IssuedToken(
        app_id=app_rec.id if app_rec else None,
        subject=user.upn, scopes="openid profile email groups",
        extra_claims=json.dumps({"groups": groups, **({"act": act_claim} if act_claim else {})}),
        expires_at=exp, raw_token=raw_token,
    )
    db.session.add(rec)
    user.last_logon = datetime.datetime.utcnow()
    db.session.commit()
    audit("OK","FS",f"{protocol} auth complete",user.upn)

    if protocol == "SAML":
        return _dispatch_saml(user, raw_token, groups,
                              extra_params.get("acs_url",""),
                              extra_params.get("relay_state",""))
    elif protocol == "WS-Fed":
        return _dispatch_wsfed(raw_token,
                               extra_params.get("wreply",""),
                               extra_params.get("wctx",""))
    else:
        state = extra_params.get("state","")
        ru    = extra_params.get("redirect_uri", extra_params.get("callback_url",""))
        sep   = "&" if "?" in ru else "?"
        return redirect(f"{ru}{sep}code={raw_token}&state={state}")


def _dispatch_saml(user, raw_token: str, groups: list, acs_url: str, relay_state: str):
    """Build a minimal SAMLResponse and auto-POST it to the ACS URL."""
    now     = datetime.datetime.utcnow()
    exp     = now + datetime.timedelta(hours=1)
    fmt     = "%Y-%m-%dT%H:%M:%SZ"
    resp_id = "_" + secrets.token_hex(16)
    stmt_id = "_" + secrets.token_hex(16)

    groups_xml = "".join(
        f'<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:type="xs:string">{g}</saml:AttributeValue>' for g in groups
    )

    saml_resp = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{resp_id}" Version="2.0" IssueInstant="{now.strftime(fmt)}"
  Destination="{acs_url}">
  <saml:Issuer>https://idp-playground.local/saml/metadata</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema"
    ID="{stmt_id}" Version="2.0" IssueInstant="{now.strftime(fmt)}">
    <saml:Issuer>https://idp-playground.local/saml/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{user.upn}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="{exp.strftime(fmt)}" Recipient="{acs_url}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{now.strftime(fmt)}" NotOnOrAfter="{exp.strftime(fmt)}">
      <saml:AudienceRestriction><saml:Audience>{acs_url}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="name"><saml:AttributeValue>{user.display_name or ''}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="email"><saml:AttributeValue>{user.email or ''}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="department"><saml:AttributeValue>{user.department or ''}</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups">{groups_xml}</saml:Attribute>
    </saml:AttributeStatement>
    <saml:AuthnStatement AuthnInstant="{now.strftime(fmt)}">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>"""

    b64_resp = base64.b64encode(saml_resp.encode("utf-8")).decode()

    # Auto-submit form back to ACS
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{acs_url}">
  <input type="hidden" name="SAMLResponse" value="{b64_resp}">
  <input type="hidden" name="RelayState" value="{relay_state}">
  <noscript><button type="submit">Continue</button></noscript>
</form>
<p style="font-family:monospace;color:#aaa;padding:20px">Redirecting via SAML POST binding...</p>
</body></html>"""


def _dispatch_wsfed(raw_token: str, wreply: str, wctx: str):
    """POST the JWT as wresult back to the RP reply URL."""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{wreply}">
  <input type="hidden" name="wa" value="wsignin1.0">
  <input type="hidden" name="wresult" value="{raw_token}">
  <input type="hidden" name="wctx" value="{wctx}">
  <noscript><button type="submit">Continue</button></noscript>
</form>
<p style="font-family:monospace;color:#aaa;padding:20px">Redirecting via WS-Federation POST...</p>
</body></html>"""


@app.route("/favicon.ico")
def favicon():
    """Return a minimal favicon to avoid 404 log noise."""
    # 1x1 transparent PNG as base64
    import binascii
    ico = binascii.unhexlify(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c6260000000020001e221bc330000000049454e44ae426082"
    )
    from flask import Response
    return Response(ico, mimetype="image/png")


@app.route("/saml/sso", methods=["GET", "POST"])
def saml_sso():
    """SAML SSO endpoint — accepts AuthnRequest (HTTP-Redirect or POST binding),
    parses the ACS URL, and shows the IDP-Playground login form."""
    saml_req   = request.values.get("SAMLRequest","")
    relay      = request.values.get("RelayState","")
    acs_url    = ""

    if saml_req:
        # HTTP-Redirect binding: base64 + DEFLATE. HTTP-POST binding: base64 only.
        for _decoder in ("redirect", "post"):
            try:
                padded     = saml_req + "=" * ((4 - len(saml_req) % 4) % 4)
                raw        = base64.b64decode(padded)
                if _decoder == "redirect":
                    import zlib as _zlib
                    xml_bytes = _zlib.decompress(raw, -15)
                else:
                    xml_bytes = raw
                root      = ET.fromstring(xml_bytes)
                acs_url   = root.get("AssertionConsumerServiceURL","")
                if acs_url:
                    break
            except Exception:
                continue

    if not acs_url:
        # Fallback: find registered SAML app's ACS URL
        saml_app = FSApplication.query.filter_by(protocol="SAML").first()
        if saml_app:
            acs_url = saml_app.saml_acs_url or ""
            if not acs_url:
                uris    = json.loads(saml_app.redirect_uris or "[]")
                acs_url = uris[0] if uris else ""

    return _login_page_html("SAML", acs_url, {
        "acs_url":     acs_url,
        "relay_state": relay,
    })


@app.route("/wsfed")
def wsfed_endpoint():
    """WS-Federation passive requestor endpoint."""
    wa      = request.args.get("wa","")
    wtrealm = request.args.get("wtrealm","")
    wreply  = request.args.get("wreply","")
    wctx    = request.args.get("wctx","")

    if wa == "wsignout1.0":
        return "Signed out", 200

    return _login_page_html("WS-Fed", wreply, {
        "wreply": wreply,
        "wctx":   wctx,
    })


@app.route("/oauth2/authorize")
def oauth2_authorize():
    """OAuth2 / OIDC authorization endpoint."""
    client_id     = request.args.get("client_id","")
    redirect_uri  = request.args.get("redirect_uri","")
    state         = request.args.get("state","")
    scope         = request.args.get("scope","")
    code_challenge = request.args.get("code_challenge","")

    return _login_page_html("OAuth", redirect_uri, {
        "redirect_uri":          redirect_uri,
        "state":                 state,
        "scope":                 scope,
        "code_challenge":        code_challenge,
    })


# ──────────────────────────────────────────────────────────
#  Multi-App Process Manager
#  Manages all four demo test clients from the IDP-Playground UI
# ──────────────────────────────────────────────────────────
import subprocess, threading, sys, atexit, signal

# Registry of all manageable demo apps
_DEMO_APPS = {
    "oidc": {
        "name":   "OIDC Test Client",
        "script": os.path.join(BASE_DIR, "test_apps", "oidc_client", "testclient_oidc.py"),
        "port":   5000,
        "color":  "#38b6ff",
        "icon":   "🧪",
    },
    "saml": {
        "name":   "SAML 2.0 Demo SP",
        "script": os.path.join(BASE_DIR, "test_apps", "saml_client",  "testclient_saml.py"),
        "port":   5001,
        "color":  "#a78bfa",
        "icon":   "📄",
    },
    "oauth2": {
        "name":   "OAuth2 + PKCE Demo",
        "script": os.path.join(BASE_DIR, "test_apps", "oauth2_client","testclient_oauth2.py"),
        "port":   5002,
        "color":  "#34d399",
        "icon":   "⚡",
    },
    "wsfed": {
        "name":   "WS-Federation Demo App",
        "script": os.path.join(BASE_DIR, "test_apps", "wsfed_client", "testclient_wsfed.py"),
        "port":   5003,
        "color":  "#fb923c",
        "icon":   "🏢",
    },
}

# Runtime state per app
_procs: dict = {}   # key -> Popen | None
_logs:  dict = {k: [] for k in _DEMO_APPS}
_lock   = threading.Lock()


def _stream(key: str, proc: subprocess.Popen):
    for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        with _lock:
            _logs[key].append(line)
            if len(_logs[key]) > 200:
                _logs[key].pop(0)


def _clean_env():
    env = os.environ.copy()
    for v in ("WERKZEUG_SERVER_FD","WERKZEUG_RUN_MAIN","SERVER_NAME"):
        env.pop(v, None)
    return env


def _launch(key: str):
    cfg    = _DEMO_APPS[key]
    script = cfg["script"]
    if not os.path.exists(script):
        return False, f"Script not found: {script}"
    with _lock:
        _logs[key] = []
    kwargs = dict(
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=os.path.dirname(script), env=_clean_env(),
    )
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        kwargs["close_fds"] = True
    proc = subprocess.Popen([sys.executable, script], **kwargs)
    _procs[key] = proc
    t = threading.Thread(target=_stream, args=(key, proc), daemon=True)
    t.start()
    return True, proc.pid


def _stop(key: str):
    proc = _procs.get(key)
    if not proc or proc.poll() is not None:
        return False, "Not running"
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    _procs[key] = None
    return True, "stopped"


def _stop_all_demos():
    """Terminate every running demo child process. Registered on shutdown so the
    demo apps do not linger as orphaned python processes after IDP-Playground exits."""
    for _k in list(_procs.keys()):
        try:
            _p = _procs.get(_k)
            if _p and _p.poll() is None:
                _p.terminate()
                try:
                    _p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    _p.kill()
        except Exception:
            pass


atexit.register(_stop_all_demos)


def _demo_signal_handler(signum, frame):
    _stop_all_demos()
    raise SystemExit(0)


for _sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
    try:
        signal.signal(getattr(signal, _sig_name), _demo_signal_handler)
    except (AttributeError, ValueError):
        pass


@app.route("/api/testapp/status")
def testapp_status():
    """Status of OIDC client (backward-compat)."""
    return _demo_status("oidc")


@app.route("/api/testapp/start", methods=["POST"])
def testapp_start():
    return _demo_start("oidc")


@app.route("/api/testapp/stop", methods=["POST"])
def testapp_stop():
    return _demo_stop("oidc")


@app.route("/api/testapp/logs")
def testapp_logs():
    with _lock:
        return jsonify({"logs": list(_logs.get("oidc",[]))})


def _demo_status(key: str):
    cfg     = _DEMO_APPS.get(key, {})
    proc    = _procs.get(key)
    running = proc is not None and proc.poll() is None
    with _lock:
        logs = list(_logs.get(key, [])[-40:])
    return jsonify({
        "key":     key,
        "name":    cfg.get("name",""),
        "running": running,
        "pid":     proc.pid if running else None,
        "port":    cfg.get("port"),
        "url":     f"http://localhost:{cfg.get('port',5000)}",
        "logs":    logs,
        "script":  cfg.get("script",""),
        "exists":  os.path.exists(cfg.get("script","")),
        "color":   cfg.get("color","#38b6ff"),
        "icon":    cfg.get("icon","🔐"),
    })


def _demo_start(key: str):
    proc = _procs.get(key)
    if proc and proc.poll() is None:
        return jsonify({"ok": False, "error": "Already running"})
    ok, result = _launch(key)
    if ok:
        audit("OK", "SYSTEM", f"{_DEMO_APPS[key]['name']} started", f"pid={result}")
        return jsonify({"ok": True, "pid": result})
    return jsonify({"ok": False, "error": result})


def _demo_stop(key: str):
    ok, msg = _stop(key)
    if ok:
        audit("WARN", "SYSTEM", f"{_DEMO_APPS[key]['name']} stopped", "")
    return jsonify({"ok": ok, "error": "" if ok else msg})


@app.route("/api/demos/status")
def demos_status_all():
    return jsonify({k: json.loads(_demo_status(k).get_data()) for k in _DEMO_APPS})


@app.route("/api/demos/<key>/status")
def demo_status_one(key):
    if key not in _DEMO_APPS:
        return jsonify({"error": "Unknown demo"}), 404
    return _demo_status(key)


@app.route("/api/demos/<key>/start", methods=["POST"])
def demo_start_one(key):
    if key not in _DEMO_APPS:
        return jsonify({"error": "Unknown demo"}), 404
    return _demo_start(key)


@app.route("/api/demos/<key>/stop", methods=["POST"])
def demo_stop_one(key):
    if key not in _DEMO_APPS:
        return jsonify({"error": "Unknown demo"}), 404
    return _demo_stop(key)


@app.route("/api/demos/<key>/logs")
def demo_logs_one(key):
    if key not in _DEMO_APPS:
        return jsonify({"error": "Unknown demo"}), 404
    with _lock:
        return jsonify({"logs": list(_logs.get(key, []))})


# ──────────────────────────────────────────────────────────
#  DB init & run
# ──────────────────────────────────────────────────────────

with app.app_context():
    # ── Auto-migrate: add new columns to existing DBs ──
    import sqlite3 as _sq
    _db_path = os.path.join(BASE_DIR, "instance", "idp_playground.db")
    if os.path.exists(_db_path):
        _conn = _sq.connect(_db_path)
        _cur  = _conn.cursor()
        _migrations = [
            # DS users — MFA
            ("ds_users", "totp_secret",     "TEXT"),
            ("ds_users", "email_otp_code",  "TEXT"),
            ("ds_users", "email_otp_exp",   "DATETIME"),
            ("ds_users", "cert_auth_token", "TEXT"),
            ("ds_users", "cert_auth_exp",   "DATETIME"),
            # FSApplication — protocol-specific fields
            ("fs_applications", "logout_uris",            "TEXT DEFAULT '[]'"),
            ("fs_applications", "app_id_uri",             "TEXT"),
            ("fs_applications", "front_channel_logout",   "TEXT"),
            ("fs_applications", "grant_types",            "TEXT DEFAULT '[\"authorization_code\"]'"),
            ("fs_applications", "response_types",         "TEXT DEFAULT '[\"code\"]'"),
            ("fs_applications", "pkce_required",          "INTEGER DEFAULT 1"),
            ("fs_applications", "allowed_audiences",      "TEXT DEFAULT '[]'"),
            ("fs_applications", "client_type",            "TEXT DEFAULT 'confidential'"),
            ("fs_applications", "platform_type",          "TEXT DEFAULT 'web'"),
            ("fs_applications", "refresh_lifetime",       "INTEGER DEFAULT 2592000"),
            ("fs_applications", "saml_entity_id",         "TEXT"),
            ("fs_applications", "saml_acs_url",           "TEXT"),
            ("fs_applications", "saml_slo_url",           "TEXT"),
            ("fs_applications", "saml_name_id_format",    "TEXT"),
            ("fs_applications", "saml_name_id_value",     "TEXT DEFAULT 'user.email'"),
            ("fs_applications", "saml_sign_response",     "INTEGER DEFAULT 1"),
            ("fs_applications", "saml_sign_assertion",    "INTEGER DEFAULT 1"),
            ("fs_applications", "saml_encrypt_assertion", "INTEGER DEFAULT 0"),
            ("fs_applications", "saml_signature_algorithm","TEXT"),
            ("fs_applications", "saml_digest_algorithm",  "TEXT"),
            ("fs_applications", "saml_sp_metadata",       "TEXT"),
            ("fs_applications", "wsfed_realm",            "TEXT"),
            ("fs_applications", "wsfed_reply_url",        "TEXT"),
            ("fs_applications", "wsfed_token_type",       "TEXT"),
            ("fs_applications", "custom_claims",          "TEXT DEFAULT '[]'"),
            ("fs_applications", "group_claims",           "TEXT DEFAULT 'security'"),
            ("fs_applications", "include_standard_claims","INTEGER DEFAULT 1"),
            ("fs_applications", "sp_metadata_xml",        "TEXT"),
            ("fs_applications", "sso_login_url",          "TEXT"),
            ("fs_applications", "sso_logout_url",         "TEXT"),
            ("fs_applications", "allow_cba",              "INTEGER DEFAULT 0"),
            ("fs_applications", "allow_passkey",          "INTEGER DEFAULT 0"),
            ("fs_applications", "allow_authenticator",    "INTEGER DEFAULT 0"),
            ("fs_applications", "allow_email",            "INTEGER DEFAULT 0"),
            ("fs_applications", "allow_push",             "INTEGER DEFAULT 0"),
            ("fs_applications", "allow_sms",              "INTEGER DEFAULT 0"),
            ("ds_users",        "sms_enrolled",           "INTEGER DEFAULT 0"),
            ("ds_users",        "push_enrolled",          "INTEGER DEFAULT 0"),
        ]
        for _tbl, _col, _typ in _migrations:
            _cur.execute(f"PRAGMA table_info({_tbl})")
            _existing = [row[1] for row in _cur.fetchall()]
            if _col not in _existing:
                _conn.execute(f"ALTER TABLE {_tbl} ADD COLUMN {_col} {_typ}")
                print(f"[IDP-Playground] Migrated: {_tbl}.{_col}")
        _conn.commit()
        _conn.close()
    db.create_all()
    seed_database()

    # ── Startup cleanup ───────────────────────────────────────────────────
    now = datetime.datetime.utcnow()

    # 1. Revoke expired tokens that are still marked valid
    expired_count = IssuedToken.query.filter(
        IssuedToken.revoked == False,
        IssuedToken.expires_at < now
    ).update({"revoked": True})
    if expired_count:
        db.session.commit()
        print(f"[IDP-Playground] Auto-revoked {expired_count} expired token(s)")

    # 2. Remove legacy Docs Chat app
    _stale = FSApplication.query.filter(FSApplication.name.ilike('%docs%chat%')).all()
    for _a in _stale:
        db.session.delete(_a)
    if _stale:
        db.session.commit()
        print(f"[IDP-Playground] Removed {len(_stale)} legacy Docs Chat app(s)")

    # 2b. Remove the legacy duplicate WS-Fed demo app. The demo was renamed from
    # "WS-Fed Demo RP" to "WS-Fed Demo App"; older databases (or a mismatched
    # test client) can end up with both, so drop the old name and de-duplicate.
    _wsdupe = FSApplication.query.filter(FSApplication.name == "WS-Fed Demo RP").all()
    for _a in _wsdupe:
        db.session.delete(_a)
    if _wsdupe:
        db.session.commit()
        print(f"[IDP-Playground] Removed {len(_wsdupe)} legacy 'WS-Fed Demo RP' app(s)")
    _wsall = (FSApplication.query.filter(FSApplication.protocol == "WS-Fed")
              .order_by(FSApplication.id.asc()).all())
    for _a in _wsall[1:]:
        db.session.delete(_a)
    if len(_wsall) > 1:
        db.session.commit()
        print(f"[IDP-Playground] De-duplicated WS-Fed demo apps (removed {len(_wsall) - 1})")

    # 3. Auto-generate CA if none exists (so CBA is ready out of the box)
    if not CertificateAuthority.query.first():
        print("[IDP-Playground] No Root CA found — generating one automatically...")
        with app.test_request_context():
            try:
                from cryptography import x509 as _x509
                from cryptography.x509.oid import NameOID as _NameOID
                from cryptography.hazmat.primitives import hashes as _hashes
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
                priv_key = _rsa.generate_private_key(
                    public_exponent=65537, key_size=4096, backend=default_backend())
                subject = issuer = _x509.Name([
                    _x509.NameAttribute(_NameOID.COMMON_NAME, "IDP-Playground Root CA"),
                    _x509.NameAttribute(_NameOID.ORGANIZATION_NAME, "IDP-Playground Identity Platform"),
                ])
                _now = datetime.datetime.utcnow()
                cert = (_x509.CertificateBuilder()
                    .subject_name(subject).issuer_name(issuer)
                    .public_key(priv_key.public_key())
                    .serial_number(_x509.random_serial_number())
                    .not_valid_before(_now)
                    .not_valid_after(_now + datetime.timedelta(days=3650))
                    .add_extension(_x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .sign(priv_key, _hashes.SHA256(), default_backend()))
                priv_pem = priv_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()).decode()
                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
                ca = CertificateAuthority(
                    common_name="IDP-Playground Root CA",
                    private_pem=priv_pem, cert_pem=cert_pem,
                    fingerprint=cert.fingerprint(_hashes.SHA256()).hex(),
                    serial=str(cert.serial_number),
                    not_before=_now,
                    not_after=_now + datetime.timedelta(days=3650),
                )
                db.session.add(ca)
                db.session.commit()
                print("[IDP-Playground] Root CA generated automatically")
            except Exception as _e:
                print(f"[IDP-Playground] Auto-CA generation failed: {_e}")

if __name__ == "__main__":
    print("=" * 55)
    print("  IDP-Playground Identity Platform")
    print("  http://localhost:8080")
    print("=" * 55)
    app.run(debug=True, host="0.0.0.0", port=8080, use_reloader=False)

