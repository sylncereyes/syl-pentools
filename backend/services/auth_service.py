from datetime import datetime, timezone, timedelta
from typing import Optional, List
from uuid import UUID
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from models.user import User, UserSession, APIKey, UserRole
from models.auth_token import PasswordResetToken, EmailVerificationToken, InviteToken
from models.workspace import Workspace, WorkspaceMember, PlanType
from core.auth import hash_password, verify_password, create_token_pair, decode_token
import secrets
import hashlib
import json


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_by_email(self, email: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.email == email.lower()))
        return result.scalars().first()

    async def get_user_by_id(self, user_id: UUID) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalars().first()

    async def create_user(
        self,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role: UserRole = UserRole.MEMBER,
    ) -> User:
        user = User(
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name=full_name,
            role=role,
            is_verified=False,
        )
        self.db.add(user)
        await self.db.flush()
        return user

    async def authenticate_user(self, email: str, password: str) -> Optional[User]:
        user = await self.get_user_by_email(email)
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        user.last_login = datetime.now(timezone.utc)
        await self.db.flush()
        return user

    async def create_user_session(
        self,
        user_id: UUID,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserSession:
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        session = UserSession(
            user_id=user_id,
            session_token=hashlib.sha256(session_token.encode()).hexdigest(),
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )
        self.db.add(session)
        await self.db.flush()
        return session

    async def validate_session(self, session_token: str) -> Optional[UserSession]:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        result = await self.db.execute(
            select(UserSession).where(
                UserSession.session_token == token_hash,
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
        return result.scalars().first()

    async def revoke_session(self, session_token: str) -> bool:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        result = await self.db.execute(select(UserSession).where(UserSession.session_token == token_hash))
        session = result.scalars().first()
        if session:
            await self.db.delete(session)
            return True
        return False

    async def revoke_all_sessions(self, user_id: UUID) -> int:
        result = await self.db.execute(delete(UserSession).where(UserSession.user_id == user_id))
        return result.rowcount

    async def create_password_reset_token(self, user_id: UUID, email: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> PasswordResetToken:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        reset_token = PasswordResetToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.db.add(reset_token)
        await self.db.flush()
        return reset_token

    async def validate_password_reset_token(self, token: str) -> Optional[PasswordResetToken]:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        result = await self.db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
                PasswordResetToken.used_at.is_(None),
            )
        )
        return result.scalars().first()

    async def use_password_reset_token(self, reset_token: PasswordResetToken, new_password: str) -> bool:
        reset_token.used_at = datetime.now(timezone.utc)
        user = await self.get_user_by_id(reset_token.user_id)
        if user:
            user.hashed_password = hash_password(new_password)
            await self.db.flush()
            return True
        return False

    async def create_email_verification_token(self, user_id: UUID, email: str) -> EmailVerificationToken:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        verification_token = EmailVerificationToken(
            user_id=user_id,
            token_hash=token_hash,
            email=email,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        self.db.add(verification_token)
        await self.db.flush()
        return verification_token

    async def verify_email_token(self, token: str) -> Optional[EmailVerificationToken]:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        result = await self.db.execute(
            select(EmailVerificationToken).where(
                EmailVerificationToken.token_hash == token_hash,
                EmailVerificationToken.expires_at > datetime.now(timezone.utc),
                EmailVerificationToken.verified_at.is_(None),
            )
        )
        return result.scalars().first()

    async def confirm_email(self, verification_token: EmailVerificationToken) -> bool:
        verification_token.verified_at = datetime.now(timezone.utc)
        user = await self.get_user_by_id(verification_token.user_id)
        if user:
            user.is_verified = True
            await self.db.flush()
            return True
        return False

    async def create_invite_token(
        self,
        workspace_id: UUID,
        email: str,
        role: str,
        invited_by: UUID,
    ) -> tuple[InviteToken, str]:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        invite = InviteToken(
            workspace_id=workspace_id,
            email=email.lower(),
            role=role,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            invited_by=invited_by,
        )
        self.db.add(invite)
        await self.db.flush()
        return invite, token

    async def validate_invite_token(self, token: str) -> Optional[InviteToken]:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        result = await self.db.execute(
            select(InviteToken).where(
                InviteToken.token_hash == token_hash,
                InviteToken.expires_at > datetime.now(timezone.utc),
                InviteToken.accepted_at.is_(None),
            )
        )
        return result.scalars().first()

    async def accept_invite(self, invite_token: InviteToken, user_id: UUID) -> WorkspaceMember:
        invite_token.accepted_at = datetime.now(timezone.utc)
        invite_token.accepted_by = user_id
        member = WorkspaceMember(
            workspace_id=invite_token.workspace_id,
            user_id=user_id,
            role=invite_token.role,
            invited_by=invite_token.invited_by,
        )
        self.db.add(member)
        await self.db.flush()
        return member

    async def get_user_workspaces(self, user_id: UUID) -> List[Workspace]:
        result = await self.db.execute(
            select(Workspace).join(WorkspaceMember).where(WorkspaceMember.user_id == user_id)
        )
        return result.scalars().all()

    async def get_workspace_members(self, workspace_id: UUID) -> List[WorkspaceMember]:
        result = await self.db.execute(select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id))
        return result.scalars().all()

    async def add_workspace_member(
        self,
        workspace_id: UUID,
        user_id: UUID,
        role: str,
        invited_by: Optional[UUID] = None,
    ) -> WorkspaceMember:
        member = WorkspaceMember(
            workspace_id=workspace_id,
            user_id=user_id,
            role=role,
            invited_by=invited_by,
        )
        self.db.add(member)
        await self.db.flush()
        return member

    async def update_member_role(self, workspace_id: UUID, user_id: UUID, role: str) -> Optional[WorkspaceMember]:
        result = await self.db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user_id
            )
        )
        member = result.scalars().first()
        if member:
            member.role = role
            await self.db.flush()
        return member

    async def remove_workspace_member(self, workspace_id: UUID, user_id: UUID) -> bool:
        result = await self.db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == user_id
            )
        )
        member = result.scalars().first()
        if member:
            await self.db.delete(member)
            return True
        return False

    async def create_workspace(self, name: str, slug: str, owner_id: UUID, plan: PlanType = PlanType.FREE) -> Workspace:
        workspace = Workspace(name=name, slug=slug, plan=plan)
        self.db.add(workspace)
        await self.db.flush()
        member = WorkspaceMember(workspace_id=workspace.id, user_id=owner_id, role="owner")
        self.db.add(member)
        await self.db.flush()
        return workspace

    async def create_api_key(self, user_id: UUID, name: str, scopes: List[str], expires_days: Optional[int] = None) -> tuple[APIKey, str]:
        key = f"pt_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        key_prefix = key[:8]
        expires_at = None
        if expires_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
        api_key = APIKey(
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=json.dumps(scopes or []),
            expires_at=expires_at,
        )
        self.db.add(api_key)
        await self.db.flush()
        return api_key, key

    async def validate_api_key(self, key: str) -> Optional[APIKey]:
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        result = await self.db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.revoked_at.is_(None),
            )
        )
        api_key = result.scalars().first()
        if api_key and (api_key.expires_at is None or api_key.expires_at > datetime.now(timezone.utc)):
            api_key.last_used = datetime.now(timezone.utc)
            await self.db.flush()
            return api_key
        return None

    async def revoke_api_key(self, user_id: UUID, key_id: UUID) -> bool:
        result = await self.db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user_id))
        api_key = result.scalars().first()
        if api_key:
            api_key.revoked_at = datetime.now(timezone.utc)
            await self.db.flush()
            return True
        return False