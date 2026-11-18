from datetime import datetime, timezone, timedelta
from typing import Optional, List
from uuid import UUID
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from models.scan import Scan, ScanType, ScanIntensity, ScanStatus
from models.schedule import ScheduledScan, ScheduleFrequency, ScheduledScanStatus
from models.asset import Asset, AssetType, AssetRiskLevel
from services.scanner_tasks import run_scan_task
import croniter
import json
from core.celery_app import celery_app


class SchedulerService:
    def __init__(self, db: Session):
        self.db = db

    async def get_due_schedules(self, limit: int = 50) -> List[ScheduledScan]:
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(ScheduledScan).where(
                and_(
                    ScheduledScan.status == ScheduledScanStatus.ACTIVE,
                    ScheduledScan.next_run <= now,
                )
            ).limit(limit)
        )
        return result.scalars().all()

    def get_due_schedules_sync(self, limit: int = 50) -> List[ScheduledScan]:
        now = datetime.now(timezone.utc)
        stmt = select(ScheduledScan).where(
            and_(
                ScheduledScan.status == ScheduledScanStatus.ACTIVE,
                ScheduledScan.next_run <= now,
            )
        ).limit(limit)
        return list(self.db.scalars(stmt))

    def calculate_next_run(self, schedule: ScheduledScan, from_time: Optional[datetime] = None) -> datetime:
        base = from_time or datetime.now(timezone.utc)
        tz = schedule.timezone or "UTC"

        if schedule.frequency == ScheduleFrequency.CUSTOM and schedule.cron_expression:
            cron = croniter.croniter(schedule.cron_expression, base)
            return cron.get_next(datetime)

        if schedule.frequency == ScheduleFrequency.DAILY:
            next_run = base.replace(hour=int(schedule.start_time[:2]), minute=int(schedule.start_time[3:]), second=0, microsecond=0)
            if next_run <= base:
                next_run += timedelta(days=1)
            return next_run

        if schedule.frequency == ScheduleFrequency.WEEKLY:
            next_run = base.replace(hour=int(schedule.start_time[:2]), minute=int(schedule.start_time[3:]), second=0, microsecond=0)
            days_ahead = (base.weekday() + 7) % 7
            next_run += timedelta(days=days_ahead if next_run > base else days_ahead + 7)
            return next_run

        if schedule.frequency == ScheduleFrequency.MONTHLY:
            next_run = base.replace(day=1, hour=int(schedule.start_time[:2]), minute=int(schedule.start_time[3:]), second=0, microsecond=0)
            while next_run <= base:
                if next_run.month == 12:
                    next_run = next_run.replace(year=next_run.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=next_run.month + 1)
            return next_run

        return base + timedelta(days=1)

    async def create_scan_from_schedule(self, schedule: ScheduledScan) -> Scan:
        target = schedule.target
        asset_id = None

        if schedule.asset_ids:
            asset_id = UUID(schedule.asset_ids[0])
        else:
            result = await self.db.execute(
                select(Asset).where(
                    Asset.workspace_id == schedule.workspace_id,
                    Asset.target == target,
                    Asset.deleted_at.is_(None)
                )
            )
            asset = result.scalars().first()
            if asset:
                asset_id = asset.id

        scan = Scan(
            workspace_id=schedule.workspace_id,
            asset_id=asset_id,
            scheduled_scan_id=schedule.id,
            name=schedule.name,
            type=ScanType(schedule.scan_type),
            target=target,
            intensity=ScanIntensity(schedule.intensity),
            is_authenticated=schedule.is_authenticated,
            auth_config=schedule.auth_config or {},
            scanner_config=schedule.scanner_config or {},
            status=ScanStatus.PENDING,
            progress=0.0,
        )
        self.db.add(scan)
        await self.db.flush()

        if schedule.asset_ids:
            assets = await self.db.execute(
                select(Asset).where(Asset.id.in_(schedule.asset_ids))
            )
            scan.assets = assets.scalars().all()

        return scan

    def create_scan_from_schedule_sync(self, schedule: ScheduledScan) -> Scan:
        target = schedule.target
        asset_id = None

        if schedule.asset_ids:
            asset_id = UUID(schedule.asset_ids[0])
        else:
            asset = self.db.query(Asset).filter(
                Asset.workspace_id == schedule.workspace_id,
                Asset.target == target,
                Asset.deleted_at.is_(None)
            ).first()
            if asset:
                asset_id = asset.id

        scan = Scan(
            workspace_id=schedule.workspace_id,
            asset_id=asset_id,
            scheduled_scan_id=schedule.id,
            name=schedule.name,
            type=ScanType(schedule.scan_type),
            target=target,
            intensity=ScanIntensity(schedule.intensity),
            is_authenticated=schedule.is_authenticated,
            auth_config=schedule.auth_config or {},
            scanner_config=schedule.scanner_config or {},
            status=ScanStatus.PENDING,
            progress=0.0,
        )
        self.db.add(scan)
        self.db.flush()

        if schedule.asset_ids:
            assets = self.db.query(Asset).filter(Asset.id.in_(schedule.asset_ids)).all()
            scan.assets = assets

        return scan

    async def dispatch_scan(self, scan: Scan) -> None:
        async_result = run_scan_task.apply_async(
            args=[str(scan.id), {
                "target": scan.target,
                "scan_type": scan.type.value,
                "intensity": scan.intensity.value,
                "is_authenticated": scan.is_authenticated,
                "auth_config": scan.auth_config,
                "options": scan.scanner_config,
            }],
            queue="scanners",
        )
        scan.status = ScanStatus.QUEUED
        scan.celery_task_id = async_result.id
        await self.db.flush()

    def dispatch_scan_sync(self, scan: Scan) -> None:
        async_result = run_scan_task.apply_async(
            args=[str(scan.id), {
                "target": scan.target,
                "scan_type": scan.type.value,
                "intensity": scan.intensity.value,
                "is_authenticated": scan.is_authenticated,
                "auth_config": scan.auth_config,
                "options": scan.scanner_config,
            }],
            queue="scanners",
        )
        scan.status = ScanStatus.QUEUED
        scan.celery_task_id = async_result.id
        self.db.flush()

    async def process_due_schedules(self) -> int:
        schedules = await self.get_due_schedules()
        processed = 0

        for schedule in schedules:
            try:
                scan = await self.create_scan_from_schedule(schedule)
                await self.dispatch_scan(scan)

                schedule.last_run = datetime.now(timezone.utc)
                schedule.next_run = self.calculate_next_run(schedule, schedule.last_run)
                schedule.consecutive_failures = 0
                schedule.last_run_status = "success"
                schedule.last_run_error = None
                processed += 1
            except Exception as e:
                schedule.consecutive_failures += 1
                schedule.last_run_status = "failed"
                schedule.last_run_error = str(e)
                if schedule.consecutive_failures >= 3:
                    schedule.status = ScheduledScanStatus.ERROR

            await self.db.flush()

        await self.db.commit()
        return processed

    def process_due_schedules_sync(self) -> int:
        schedules = self.get_due_schedules_sync()
        processed = 0

        for schedule in schedules:
            try:
                scan = self.create_scan_from_schedule_sync(schedule)
                self.dispatch_scan_sync(scan)

                schedule.last_run = datetime.now(timezone.utc)
                schedule.next_run = self.calculate_next_run(schedule, schedule.last_run)
                schedule.consecutive_failures = 0
                schedule.last_run_status = "success"
                schedule.last_run_error = None
                processed += 1
            except Exception as e:
                schedule.consecutive_failures += 1
                schedule.last_run_status = "failed"
                schedule.last_run_error = str(e)
                if schedule.consecutive_failures >= 3:
                    schedule.status = ScheduledScanStatus.ERROR

            self.db.flush()

        self.db.commit()
        return processed


@celery_app.task(name="services.scheduler_service.run_scheduler_tick")
def run_scheduler_tick() -> int:
    from core.database import SyncSessionLocal
    db: Session = SyncSessionLocal()
    try:
        service = SchedulerService(db)
        return service.process_due_schedules_sync()
    finally:
        db.close()
