"""
Stripe billing service for subscription management.
"""
from __future__ import annotations

import logging
from typing import Optional, Dict, Any
from datetime import datetime, timezone
from uuid import UUID

import stripe
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.workspace import Workspace, PlanType
from models.user import User

logger = logging.getLogger(__name__)

# Initialize Stripe
if settings.STRIPE_SECRET_KEY:
    stripe.api_key = settings.STRIPE_SECRET_KEY
else:
    logger.warning("Stripe not configured - billing features disabled")


class BillingService:
    """Handle Stripe subscriptions and billing."""

    PLAN_PRICES = {
        PlanType.FREE: settings.STRIPE_PRICE_FREE,
        PlanType.NETSCAN: settings.STRIPE_PRICE_NETSCAN,
        PlanType.APPSCAN: settings.STRIPE_PRICE_APPSCAN,
        PlanType.EXPLOIT: settings.STRIPE_PRICE_EXPLOIT,
        PlanType.ENTERPRISE: settings.STRIPE_PRICE_ENTERPRISE,
    }

    PLAN_LIMITS = {
        PlanType.FREE: {
            "asset_limit": 100,
            "concurrent_scan_limit": 2,
            "scheduled_scan_limit": 10,
            "team_member_limit": 5,
            "ai_pentests_enabled": False,
            "branded_reports": False,
            "custom_integrations": False,
            "internal_scanning": False,
        },
        PlanType.NETSCAN: {
            "asset_limit": 1000,
            "concurrent_scan_limit": 5,
            "scheduled_scan_limit": 50,
            "team_member_limit": 20,
            "ai_pentests_enabled": True,
            "branded_reports": False,
            "custom_integrations": False,
            "internal_scanning": False,
        },
        PlanType.APPSCAN: {
            "asset_limit": 2000,
            "concurrent_scan_limit": 10,
            "scheduled_scan_limit": 100,
            "team_member_limit": 50,
            "ai_pentests_enabled": True,
            "branded_reports": True,
            "custom_integrations": True,
            "internal_scanning": True,
        },
        PlanType.EXPLOIT: {
            "asset_limit": 5000,
            "concurrent_scan_limit": 20,
            "scheduled_scan_limit": 200,
            "team_member_limit": 100,
            "ai_pentests_enabled": True,
            "branded_reports": True,
            "custom_integrations": True,
            "internal_scanning": True,
        },
        PlanType.ENTERPRISE: {
            "asset_limit": -1,  # unlimited
            "concurrent_scan_limit": 50,
            "scheduled_scan_limit": -1,
            "team_member_limit": -1,
            "ai_pentests_enabled": True,
            "branded_reports": True,
            "custom_integrations": True,
            "internal_scanning": True,
        },
    }

    @staticmethod
    def is_configured() -> bool:
        """Check if Stripe is configured."""
        return bool(settings.STRIPE_SECRET_KEY)

    @classmethod
    def get_plan_limits(cls, plan: PlanType) -> Dict[str, Any]:
        """Get limits for a plan."""
        return cls.PLAN_LIMITS.get(plan, cls.PLAN_LIMITS[PlanType.FREE])

    @classmethod
    async def create_customer(cls, db: AsyncSession, workspace: Workspace, user: User) -> Optional[str]:
        """Create Stripe customer for workspace."""
        if not cls.is_configured():
            return None

        try:
            customer = stripe.Customer.create(
                email=user.email,
                name=workspace.name,
                metadata={
                    "workspace_id": str(workspace.id),
                    "user_id": str(user.id),
                },
            )
            workspace.stripe_customer_id = customer.id
            await db.flush()
            return customer.id
        except Exception as e:
            logger.error(f"Failed to create Stripe customer: {e}")
            return None

    @classmethod
    async def create_checkout_session(
        cls,
        workspace: Workspace,
        plan: PlanType,
        success_url: str,
        cancel_url: str,
    ) -> Optional[str]:
        """Create Stripe checkout session for subscription."""
        if not cls.is_configured():
            return None

        price_id = cls.PLAN_PRICES.get(plan)
        if not price_id:
            logger.error(f"No price ID configured for plan {plan}")
            return None

        try:
            if not workspace.stripe_customer_id:
                logger.error("Workspace has no Stripe customer")
                return None

            session = stripe.checkout.Session.create(
                customer=workspace.stripe_customer_id,
                payment_method_types=["card"],
                line_items=[{
                    "price": price_id,
                    "quantity": 1,
                }],
                mode="subscription",
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={
                    "workspace_id": str(workspace.id),
                    "plan": plan.value,
                },
            )
            return session.url
        except Exception as e:
            logger.error(f"Failed to create checkout session: {e}")
            return None

    @classmethod
    async def create_portal_session(cls, workspace: Workspace, return_url: str) -> Optional[str]:
        """Create Stripe billing portal session."""
        if not cls.is_configured():
            return None

        if not workspace.stripe_customer_id:
            return None

        try:
            session = stripe.billing_portal.Session.create(
                customer=workspace.stripe_customer_id,
                return_url=return_url,
            )
            return session.url
        except Exception as e:
            logger.error(f"Failed to create portal session: {e}")
            return None

    @classmethod
    async def handle_webhook(cls, db: AsyncSession, payload: bytes, sig_header: str) -> bool:
        """Process Stripe webhook events."""
        if not cls.is_configured():
            return False

        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except Exception as e:
            logger.error(f"Webhook signature verification failed: {e}")
            return False

        event_type = event["type"]
        data = event["data"]["object"]

        if event_type == "customer.subscription.created":
            await cls._handle_subscription_created(db, data)
        elif event_type == "customer.subscription.updated":
            await cls._handle_subscription_updated(db, data)
        elif event_type == "customer.subscription.deleted":
            await cls._handle_subscription_deleted(db, data)
        elif event_type == "invoice.payment_failed":
            await cls._handle_payment_failed(db, data)
        elif event_type == "invoice.payment_succeeded":
            await cls._handle_payment_succeeded(db, data)

        return True

    @classmethod
    async def _handle_subscription_created(cls, db: AsyncSession, subscription: Dict) -> None:
        """Handle new subscription."""
        workspace_id = subscription.get("metadata", {}).get("workspace_id")
        plan_str = subscription.get("metadata", {}).get("plan")
        if not workspace_id or not plan_str:
            return

        try:
            plan = PlanType(plan_str)
        except ValueError:
            return

        workspace = await db.get(Workspace, UUID(workspace_id))
        if not workspace:
            return

        workspace.plan = plan
        workspace.stripe_subscription_id = subscription["id"]
        workspace.subscription_status = subscription["status"]
        if subscription.get("current_period_end"):
            workspace.subscription_current_period_end = datetime.fromtimestamp(
                subscription["current_period_end"], tz=timezone.utc
            )

        # Apply plan limits
        limits = cls.get_plan_limits(plan)
        for key, value in limits.items():
            if hasattr(workspace, key):
                setattr(workspace, key, value)

        await db.commit()
        logger.info(f"Subscription created for workspace {workspace_id}: {plan}")

    @classmethod
    async def _handle_subscription_updated(cls, db: AsyncSession, subscription: Dict) -> None:
        """Handle subscription update."""
        workspace_id = subscription.get("metadata", {}).get("workspace_id")
        if not workspace_id:
            return

        workspace = await db.get(Workspace, UUID(workspace_id))
        if not workspace:
            return

        workspace.subscription_status = subscription["status"]
        if subscription.get("current_period_end"):
            workspace.subscription_current_period_end = datetime.fromtimestamp(
                subscription["current_period_end"], tz=timezone.utc
            )

        # Check if plan changed
        plan_str = subscription.get("metadata", {}).get("plan")
        if plan_str:
            try:
                new_plan = PlanType(plan_str)
                if new_plan != workspace.plan:
                    workspace.plan = new_plan
                    limits = cls.get_plan_limits(new_plan)
                    for key, value in limits.items():
                        if hasattr(workspace, key):
                            setattr(workspace, key, value)
            except ValueError:
                pass

        await db.commit()
        logger.info(f"Subscription updated for workspace {workspace_id}")

    @classmethod
    async def _handle_subscription_deleted(cls, db: AsyncSession, subscription: Dict) -> None:
        """Handle subscription cancellation."""
        workspace_id = subscription.get("metadata", {}).get("workspace_id")
        if not workspace_id:
            return

        workspace = await db.get(Workspace, UUID(workspace_id))
        if not workspace:
            return

        # Revert to free plan
        workspace.plan = PlanType.FREE
        workspace.stripe_subscription_id = None
        workspace.subscription_status = "canceled"
        workspace.subscription_current_period_end = None

        # Apply free plan limits
        limits = cls.get_plan_limits(PlanType.FREE)
        for key, value in limits.items():
            if hasattr(workspace, key):
                setattr(workspace, key, value)

        await db.commit()
        logger.info(f"Subscription canceled for workspace {workspace_id}, reverted to free")

    @classmethod
    async def _handle_payment_failed(cls, db: AsyncSession, invoice: Dict) -> None:
        """Handle failed payment."""
        customer_id = invoice.get("customer")
        if not customer_id:
            return

        # Find workspace by customer ID
        result = await db.execute(
            select(Workspace).where(Workspace.stripe_customer_id == customer_id)
        )
        workspace = result.scalars().first()
        if not workspace:
            return

        workspace.subscription_status = "past_due"
        await db.commit()
        logger.warning(f"Payment failed for workspace {workspace.id}")

    @classmethod
    async def _handle_payment_succeeded(cls, db: AsyncSession, invoice: Dict) -> None:
        """Handle successful payment."""
        customer_id = invoice.get("customer")
        if not customer_id:
            return

        result = await db.execute(
            select(Workspace).where(Workspace.stripe_customer_id == customer_id)
        )
        workspace = result.scalars().first()
        if not workspace:
            return

        workspace.subscription_status = "active"
        await db.commit()
        logger.info(f"Payment succeeded for workspace {workspace.id}")

    @classmethod
    async def cancel_subscription(cls, workspace: Workspace) -> bool:
        """Cancel subscription at period end."""
        if not cls.is_configured() or not workspace.stripe_subscription_id:
            return False

        try:
            stripe.Subscription.modify(
                workspace.stripe_subscription_id,
                cancel_at_period_end=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to cancel subscription: {e}")
            return False

    @classmethod
    async def resume_subscription(cls, workspace: Workspace) -> bool:
        """Resume canceled subscription."""
        if not cls.is_configured() or not workspace.stripe_subscription_id:
            return False

        try:
            stripe.Subscription.modify(
                workspace.stripe_subscription_id,
                cancel_at_period_end=False,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to resume subscription: {e}")
            return False