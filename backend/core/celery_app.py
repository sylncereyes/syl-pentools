from celery import Celery
from celery.schedules import crontab
from core.config import settings

celery_app = Celery(
    "syl_pentools",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "services.scanner_tasks",
        "services.scheduler_service",
        "services.robot_tasks",
    ],
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max
    task_soft_time_limit=3000,  # 50 min soft limit
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=100,
    result_expires=86400,  # 24 hours
    
    # Task routing
    task_routes={
        "services.scanner_tasks.*": {"queue": "scanners"},
        "services.scheduler_service.*": {"queue": "scheduler"},
        "services.robot_tasks.*": {"queue": "scanners"},
    },
    
    # Beat schedule
    beat_schedule={
        "scheduler-tick-every-minute": {
            "task": "services.scheduler_service.run_scheduler_tick",
            "schedule": crontab(minute="*"),  # Every minute
        },
    },
)

# Auto-discover tasks
celery_app.autodiscover_tasks()

@celery_app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f"Request: {self.request!r}")