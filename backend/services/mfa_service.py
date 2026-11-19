"""
MFA service with TOTP and SSO (SAML/OIDC) support.
"""
from __future__ import annotations

import logging
import pyotp
import qrcode
import base64
import secrets
import hashlib
from io import BytesIO
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from uuid import UUID

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.user import User, UserMFA, UserSession
from models.workspace import Workspace, WorkspaceMember

logger = logging.getLogger(__name__)


class MFAService:
    """Multi-Factor Authentication service with TOTP and SSO support."""

    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret: str, email: str, issuer: str = None) -> str:
        """Get TOTP URI for QR code."""
        issuer = issuer or settings.MFA_ISSUER
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=email,
            issuer_name=issuer,
        )

    @staticmethod
    def generate_qr_code(uri: str) -> bytes:
        """Generate QR code as PNG bytes."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @staticmethod
    def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
        """Verify TOTP token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=valid_window)

    @classmethod
    async def setup_totp(cls, db: AsyncSession, user: User) -> Dict[str, Any]:
        """Set up TOTP for user. Returns secret and QR code."""
        # Check if MFA already exists
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        existing = result.scalars().first()

        if existing and existing.totp_secret:
            secret = existing.totp_secret
        else:
            secret = cls.generate_secret()
            if existing:
                existing.totp_secret = secret
                existing.updated_at = datetime.now(timezone.utc)
            else:
                # Explicitly create the UserMFA with recovery_codes as empty list
                # to avoid SQLAlchemy passing None for the array column
                mfa = UserMFA(
                    user_id=user.id,
                    totp_secret=secret,
                    recovery_codes=[],
                )
                db.add(mfa)
                # Don't flush here, let the commit handle it
                # The key is to ensure recovery_codes is explicitly set to []

        uri = cls.get_totp_uri(secret, user.email)
        qr_bytes = cls.generate_qr_code(uri)
        qr_b64 = base64.b64encode(qr_bytes).decode()

        await db.commit()

        return {
            "secret": secret,
            "qr_code": f"data:image/png;base64,{qr_b64}",
            "uri": uri,
        }

    @classmethod
    async def enable_totp(cls, db: AsyncSession, user: User, token: str) -> bool:
        """Enable TOTP after verifying token."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        if not mfa or not mfa.totp_secret:
            return False

        if not cls.verify_totp(mfa.totp_secret, token):
            return False

        mfa.totp_enabled = True
        mfa.totp_enabled_at = datetime.now(timezone.utc)
        mfa.updated_at = datetime.now(timezone.utc)
        await db.commit()
        return True

    @classmethod
    async def disable_totp(cls, db: AsyncSession, user: User) -> bool:
        """Disable TOTP."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        if not mfa:
            return False

        mfa.totp_enabled = False
        mfa.totp_secret = None
        mfa.updated_at = datetime.now(timezone.utc)
        await db.commit()
        return True

    @classmethod
    async def verify_totp_token(cls, db: AsyncSession, user: User, token: str) -> bool:
        """Verify TOTP token for user."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        if not mfa or not mfa.totp_enabled or not mfa.totp_secret:
            return False

        return cls.verify_totp(mfa.totp_secret, token)

    @classmethod
    async def generate_recovery_codes(cls, db: AsyncSession, user: User, count: int = 10) -> List[str]:
        """Generate recovery codes."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        if not mfa:
            mfa = UserMFA(user_id=user.id)
            db.add(mfa)

        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            # Format: XXXX-XXXX
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)

        # Hash codes for storage
        hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
        mfa.recovery_codes = hashed
        mfa.updated_at = datetime.now(timezone.utc)
        await db.commit()

        return codes

    @classmethod
    async def verify_recovery_code(cls, db: AsyncSession, user: User, code: str) -> bool:
        """Verify and consume a recovery code."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        if not mfa or not mfa.recovery_codes:
            return False

        code_upper = code.upper().replace("-", "")
        hashed = hashlib.sha256(code_upper.encode()).hexdigest()

        if hashed in mfa.recovery_codes:
            # Remove used code
            mfa.recovery_codes.remove(hashed)
            mfa.updated_at = datetime.now(timezone.utc)
            await db.commit()
            return True

        return False

    @classmethod
    async def get_mfa_status(cls, db: AsyncSession, user: User) -> Dict[str, Any]:
        """Get MFA status for user."""
        result = await db.execute(
            select(UserMFA).where(UserMFA.user_id == user.id)
        )
        mfa = result.scalars().first()

        def to_iso(dt):
            return dt.isoformat() if dt else None

        return {
            "totp_enabled": mfa.totp_enabled if mfa else False,
            "totp_enabled_at": to_iso(mfa.totp_enabled_at) if mfa else None,
            "recovery_codes_count": len(mfa.recovery_codes) if mfa and mfa.recovery_codes else 0,
            "last_used": to_iso(mfa.last_used) if mfa else None,
        }


class SSOService:
    """Single Sign-On service supporting SAML and OIDC."""

    @staticmethod
    def is_saml_configured() -> bool:
        return bool(
            settings.SAML_ENTITY_ID
            and settings.SAML_ACS_URL
            and settings.SAML_METADATA_URL
            and settings.SAML_X509_CERT
        )

    @staticmethod
    def is_oidc_configured() -> bool:
        return bool(
            settings.OIDC_CLIENT_ID
            and settings.OIDC_CLIENT_SECRET
            and settings.OIDC_DISCOVERY_URL
        )

    @classmethod
    def get_saml_metadata(cls) -> str:
        """Generate SAML metadata XML."""
        if not cls.is_saml_configured():
            return ""

        metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{settings.SAML_ENTITY_ID}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        AuthnRequestsSigned="false"
                        WantAssertionsSigned="true">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                      Location="{settings.SAML_ACS_URL}"
                                      index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""
        return metadata

    @classmethod
    def get_oidc_config(cls) -> Dict[str, Any]:
        """Get OIDC configuration."""
        return {
            "client_id": settings.OIDC_CLIENT_ID,
            "discovery_url": settings.OIDC_DISCOVERY_URL,
            "redirect_uri": f"{settings.APP_URL}/auth/oidc/callback",
            "scope": "openid email profile",
        }

    @classmethod
    async def find_or_create_user_from_saml(
        cls,
        db: AsyncSession,
        saml_attributes: Dict[str, str],
        workspace_id: Optional[UUID] = None,
    ) -> Optional[User]:
        """Find or create user from SAML attributes."""
        email = saml_attributes.get("email") or saml_attributes.get("Email")
        if not email:
            return None

        email = email.lower()
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()

        if not user:
            user = User(
                email=email,
                full_name=saml_attributes.get("displayName") or saml_attributes.get("cn"),
                is_verified=True,
                is_active=True,
            )
            db.add(user)
            await db.flush()

            # Add to workspace if specified
            if workspace_id:
                member = WorkspaceMember(
                    workspace_id=workspace_id,
                    user_id=user.id,
                    role="member",
                )
                db.add(member)

        # Update last login
        user.last_login = datetime.now(timezone.utc)
        await db.commit()
        return user

    @classmethod
    async def find_or_create_user_from_oidc(
        cls,
        db: AsyncSession,
        oidc_claims: Dict[str, Any],
        workspace_id: Optional[UUID] = None,
    ) -> Optional[User]:
        """Find or create user from OIDC claims."""
        email = oidc_claims.get("email")
        if not email:
            return None

        email = email.lower()
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()

        if not user:
            user = User(
                email=email,
                full_name=oidc_claims.get("name"),
                is_verified=oidc_claims.get("email_verified", False),
                is_active=True,
            )
            db.add(user)
            await db.flush()

            if workspace_id:
                member = WorkspaceMember(
                    workspace_id=workspace_id,
                    user_id=user.id,
                    role="member",
                )
                db.add(member)

        user.last_login = datetime.now(timezone.utc)
        await db.commit()
        return user