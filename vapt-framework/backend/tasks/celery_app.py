"""
Celery application configuration.
"""

from celery import Celery
import os

celery_app = Celery(
    "vapt_framework",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
    include=["tasks.scan_task"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=os.getenv("MAX_SCAN_TIMEOUT", 300),
    task_soft_time_limit=os.getenv("MAX_SCAN_TIMEOUT", 300),
    worker_max_tasks_per_child=50,
    worker_prefetch_multiplier=1,
)