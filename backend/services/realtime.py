"""Real-time updates via Socket.io"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum

import socketio
from core.config import settings


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_LOG = "scan_log"
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    ASSET_CREATED = "asset_created"
    ASSET_UPDATED = "asset_updated"
    SCHEDULED_SCAN_TRIGGERED = "scheduled_scan_triggered"
    REPORT_GENERATED = "report_generated"
    NOTIFICATION = "notification"
    WORKSPACE_STATS = "workspace_stats"


@dataclass
class RealtimeEvent:
    """Real-time event structure"""
    event_type: EventType
    workspace_id: str
    data: dict
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    user_id: Optional[str] = None


# Socket.io server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=settings.CORS_ORIGINS if hasattr(settings, 'CORS_ORIGINS') else ["*"],
    logger=True,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25,
)

# Socket.io ASGI app
socket_app = socketio.ASGIApp(sio)


# Connection management
connected_clients: Dict[str, Set[str]] = {}  # workspace_id -> set of socket_ids
client_workspaces: Dict[str, str] = {}  # socket_id -> workspace_id
client_users: Dict[str, str] = {}  # socket_id -> user_id


@sio.event
async def connect(sid, environ, auth):
    """Handle client connection"""
    workspace_id = auth.get('workspace_id') if auth else None
    user_id = auth.get('user_id') if auth else None
    token = auth.get('token') if auth else None
    
    if not workspace_id:
        await sio.disconnect(sid)
        return False
    
    # Validate token (implement your auth validation)
    # if not validate_token(token, workspace_id, user_id):
    #     await sio.disconnect(sid)
    #     return False
    
    # Register client
    if workspace_id not in connected_clients:
        connected_clients[workspace_id] = set()
    connected_clients[workspace_id].add(sid)
    client_workspaces[sid] = workspace_id
    client_users[sid] = user_id
    
    # Join workspace room
    await sio.enter_room(sid, f"workspace:{workspace_id}")
    
    # Send connection confirmation
    await sio.emit('connected', {
        'workspace_id': workspace_id,
        'user_id': user_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }, room=sid)
    
    print(f"Client {sid} connected to workspace {workspace_id}")
    return True


@sio.event
async def disconnect(sid):
    """Handle client disconnection"""
    workspace_id = client_workspaces.get(sid)
    if workspace_id and workspace_id in connected_clients:
        connected_clients[workspace_id].discard(sid)
        if not connected_clients[workspace_id]:
            del connected_clients[workspace_id]
    
    if sid in client_workspaces:
        del client_workspaces[sid]
    if sid in client_users:
        del client_users[sid]
    
    print(f"Client {sid} disconnected")


@sio.event
async def subscribe(sid, data):
    """Subscribe to specific scan or asset updates"""
    scan_id = data.get('scan_id')
    asset_id = data.get('asset_id')
    
    if scan_id:
        await sio.enter_room(sid, f"scan:{scan_id}")
        return {'subscribed': f'scan:{scan_id}'}
    
    if asset_id:
        await sio.enter_room(sid, f"asset:{asset_id}")
        return {'subscribed': f'asset:{asset_id}'}
    
    return {'error': 'Invalid subscription'}


@sio.event
async def unsubscribe(sid, data):
    """Unsubscribe from scan or asset updates"""
    scan_id = data.get('scan_id')
    asset_id = data.get('asset_id')
    
    if scan_id:
        await sio.leave_room(sid, f"scan:{scan_id}")
        return {'unsubscribed': f'scan:{scan_id}'}
    
    if asset_id:
        await sio.leave_room(sid, f"asset:{asset_id}")
        return {'unsubscribed': f'asset:{asset_id}'}
    
    return {'error': 'Invalid unsubscription'}


@sio.event
async def ping(sid):
    """Heartbeat"""
    return {'pong': True, 'timestamp': datetime.now(timezone.utc).isoformat()}


# Event emission functions
async def emit_scan_started(workspace_id: str, scan_id: str, scan_data: dict):
    """Emit scan started event"""
    event = RealtimeEvent(
        event_type=EventType.SCAN_STARTED,
        workspace_id=workspace_id,
        data={'scan_id': scan_id, **scan_data},
    )
    await sio.emit('scan_started', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('scan_started', asdict(event), room=f"scan:{scan_id}")


async def emit_scan_progress(workspace_id: str, scan_id: str, progress: float, step: str, metadata: dict = None):
    """Emit scan progress update"""
    event = RealtimeEvent(
        event_type=EventType.SCAN_PROGRESS,
        workspace_id=workspace_id,
        data={
            'scan_id': scan_id,
            'progress': progress,
            'step': step,
            'metadata': metadata or {},
        },
    )
    await sio.emit('scan_progress', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('scan_progress', asdict(event), room=f"scan:{scan_id}")


async def emit_scan_completed(workspace_id: str, scan_id: str, result: dict):
    """Emit scan completed event"""
    event = RealtimeEvent(
        event_type=EventType.SCAN_COMPLETED,
        workspace_id=workspace_id,
        data={'scan_id': scan_id, **result},
    )
    await sio.emit('scan_completed', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('scan_completed', asdict(event), room=f"scan:{scan_id}")


async def emit_scan_failed(workspace_id: str, scan_id: str, error: str):
    """Emit scan failed event"""
    event = RealtimeEvent(
        event_type=EventType.SCAN_FAILED,
        workspace_id=workspace_id,
        data={'scan_id': scan_id, 'error': error},
    )
    await sio.emit('scan_failed', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('scan_failed', asdict(event), room=f"scan:{scan_id}")


async def emit_scan_log(workspace_id: str, scan_id: str, log_data: dict):
    """Emit scan log entry"""
    event = RealtimeEvent(
        event_type=EventType.SCAN_LOG,
        workspace_id=workspace_id,
        data={'scan_id': scan_id, **log_data},
    )
    await sio.emit('scan_log', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('scan_log', asdict(event), room=f"scan:{scan_id}")


async def emit_finding_created(workspace_id: str, finding_data: dict):
    """Emit new finding event"""
    event = RealtimeEvent(
        event_type=EventType.FINDING_CREATED,
        workspace_id=workspace_id,
        data=finding_data,
    )
    await sio.emit('finding_created', asdict(event), room=f"workspace:{workspace_id}")
    if finding_data.get('asset_id'):
        await sio.emit('finding_created', asdict(event), room=f"asset:{finding_data['asset_id']}")


async def emit_finding_updated(workspace_id: str, finding_id: str, changes: dict):
    """Emit finding updated event"""
    event = RealtimeEvent(
        event_type=EventType.FINDING_UPDATED,
        workspace_id=workspace_id,
        data={'finding_id': finding_id, **changes},
    )
    await sio.emit('finding_updated', asdict(event), room=f"workspace:{workspace_id}")


async def emit_asset_created(workspace_id: str, asset_data: dict):
    """Emit new asset event"""
    event = RealtimeEvent(
        event_type=EventType.ASSET_CREATED,
        workspace_id=workspace_id,
        data=asset_data,
    )
    await sio.emit('asset_created', asdict(event), room=f"workspace:{workspace_id}")


async def emit_asset_updated(workspace_id: str, asset_id: str, changes: dict):
    """Emit asset updated event"""
    event = RealtimeEvent(
        event_type=EventType.ASSET_UPDATED,
        workspace_id=workspace_id,
        data={'asset_id': asset_id, **changes},
    )
    await sio.emit('asset_updated', asdict(event), room=f"workspace:{workspace_id}")
    await sio.emit('asset_updated', asdict(event), room=f"asset:{asset_id}")


async def emit_scheduled_scan_triggered(workspace_id: str, scan_data: dict):
    """Emit scheduled scan triggered event"""
    event = RealtimeEvent(
        event_type=EventType.SCHEDULED_SCAN_TRIGGERED,
        workspace_id=workspace_id,
        data=scan_data,
    )
    await sio.emit('scheduled_scan_triggered', asdict(event), room=f"workspace:{workspace_id}")


async def emit_report_generated(workspace_id: str, report_data: dict):
    """Emit report generated event"""
    event = RealtimeEvent(
        event_type=EventType.REPORT_GENERATED,
        workspace_id=workspace_id,
        data=report_data,
    )
    await sio.emit('report_generated', asdict(event), room=f"workspace:{workspace_id}")


async def emit_notification(workspace_id: str, notification_data: dict):
    """Emit notification event"""
    event = RealtimeEvent(
        event_type=EventType.NOTIFICATION,
        workspace_id=workspace_id,
        data=notification_data,
    )
    await sio.emit('notification', asdict(event), room=f"workspace:{workspace_id}")


async def emit_workspace_stats(workspace_id: str, stats: dict):
    """Emit workspace stats update"""
    event = RealtimeEvent(
        event_type=EventType.WORKSPACE_STATS,
        workspace_id=workspace_id,
        data=stats,
    )
    await sio.emit('workspace_stats', asdict(event), room=f"workspace:{workspace_id}")


# Utility functions
def get_connected_clients(workspace_id: str) -> int:
    """Get number of connected clients for workspace"""
    return len(connected_clients.get(workspace_id, set()))


def is_workspace_connected(workspace_id: str) -> bool:
    """Check if workspace has connected clients"""
    return workspace_id in connected_clients and len(connected_clients[workspace_id]) > 0


async def broadcast_to_workspace(workspace_id: str, event: str, data: dict):
    """Broadcast event to all clients in workspace"""
    await sio.emit(event, data, room=f"workspace:{workspace_id}")


async def broadcast_to_scan(scan_id: str, event: str, data: dict):
    """Broadcast event to all clients subscribed to scan"""
    await sio.emit(event, data, room=f"scan:{scan_id}")


async def broadcast_to_asset(asset_id: str, event: str, data: dict):
    """Broadcast event to all clients subscribed to asset"""
    await sio.emit(event, data, room=f"asset:{asset_id}")


# Integration with scanner tasks
async def emit_scanner_event(scan_id: str, event_type: str, data: dict):
    """Emit event from scanner task"""
    from core.database import get_sync_db
    from models.scan import Scan
    
    db = next(get_sync_db())
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        
        workspace_id = str(scan.workspace_id)
        
        if event_type == 'started':
            await emit_scan_started(workspace_id, scan_id, data)
        elif event_type == 'progress':
            await emit_scan_progress(workspace_id, scan_id, data.get('progress', 0), data.get('step', ''), data.get('metadata'))
        elif event_type == 'completed':
            await emit_scan_completed(workspace_id, scan_id, data)
        elif event_type == 'failed':
            await emit_scan_failed(workspace_id, scan_id, data.get('error', 'Unknown error'))
        elif event_type == 'log':
            await emit_scan_log(workspace_id, scan_id, data)
    finally:
        db.close()


# Celery integration
def emit_celery_scan_event(scan_id: str, event_type: str, data: dict):
    """Emit event from Celery task (synchronous)"""
    # Create new event loop for async emission
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    asyncio.run(emit_scanner_event(scan_id, event_type, data))


# Integration with Celery task
def patch_scanner_task():
    """Patch the scanner task to emit real-time events"""
    from services.scanner_tasks import run_scan_task
    from core.database import get_sync_db
    from models.scan import Scan, ScanLog
    
    original_run = run_scan_task.run
    
    def patched_run(self, scan_id: str, scan_config: dict):
        # Emit started event
        emit_celery_scan_event(scan_id, 'started', scan_config)
        
        # Run original
        result = original_run(self, scan_id, scan_config)
        
        # Emit completion event based on result
        if result.get('status') == 'completed':
            emit_celery_scan_event(scan_id, 'completed', result)
        elif result.get('status') == 'failed':
            emit_celery_scan_event(scan_id, 'failed', {'error': result.get('error', 'Unknown error')})
        
        return result
    
    run_scan_task.run = patched_run


# Startup function
async def init_realtime():
    """Initialize real-time service"""
    # Patch scanner tasks
    patch_scanner_task()
    print("Real-time service initialized")