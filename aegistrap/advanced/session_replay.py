"""
AegisTrap Session Replay & Forensic Timeline Reconstruction
==============================================================
Records complete session timelines with precise timing for forensic
analysis, incident response, and attacker behavior replay.

Features:
- Full session recording with millisecond-precision timestamps
- Asciinema-compatible export (terminal replay format)
- Timeline reconstruction with enrichment annotations
- Session comparison for campaign analysis
- Export to JSON, CSV, and STIX bundle formats
- Searchable command history across all sessions
"""

import time
import json
import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("aegistrap.replay")



# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class TimelineEvent:
    """A single event in a session timeline."""
    timestamp: float = 0.0           # Unix timestamp with ms precision
    elapsed_ms: float = 0.0          # Milliseconds since session start
    event_type: str = ""             # input, output, auth, file_access, alert
    direction: str = ""              # attacker_to_honeypot, honeypot_to_attacker
    content: str = ""                # The actual data
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Enrichment annotations (added by other modules)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_indicators: List[str] = field(default_factory=list)
    profiler_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "t": self.elapsed_ms,
            "ts": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "type": self.event_type,
            "dir": self.direction,
            "content": self.content,
            "meta": self.metadata,
            "mitre": self.mitre_techniques,
            "threats": self.threat_indicators,
        }


@dataclass
class SessionRecording:
    """Complete recording of an attacker session."""
    session_id: str = ""
    attacker_ip: str = ""
    attacker_port: int = 0
    service: str = ""
    username: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    # Timeline of all events
    events: List[TimelineEvent] = field(default_factory=list)
    # Summary data
    total_commands: int = 0
    total_responses: int = 0
    # Enrichment summary
    mitre_summary: Dict[str, int] = field(default_factory=dict)
    profiler_summary: Dict[str, Any] = field(default_factory=dict)
    geo_data: Dict[str, Any] = field(default_factory=dict)
    fingerprint_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "service": self.service,
            "username": self.username,
            "start_time": datetime.fromtimestamp(
                self.start_time, tz=timezone.utc
            ).isoformat() if self.start_time else "",
            "end_time": datetime.fromtimestamp(
                self.end_time, tz=timezone.utc
            ).isoformat() if self.end_time else "",
            "duration_seconds": self.duration_seconds,
            "total_commands": self.total_commands,
            "total_responses": self.total_responses,
            "events_count": len(self.events),
            "mitre_summary": self.mitre_summary,
            "profiler_summary": self.profiler_summary,
            "geo_data": self.geo_data,
        }

    def to_asciinema_v2(self) -> str:
        """
        Export session as Asciinema v2 format for terminal replay.
        Can be played back with `asciinema play` or shared via asciinema.org.
        """
        header = json.dumps({
            "version": 2,
            "width": 120,
            "height": 40,
            "timestamp": int(self.start_time),
            "title": f"AegisTrap Session {self.session_id[:8]} - {self.attacker_ip}",
            "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
        })

        lines = [header]
        for event in self.events:
            elapsed_sec = event.elapsed_ms / 1000.0
            if event.direction == "honeypot_to_attacker":
                # Output event ('o' type in asciinema)
                content = event.content.replace("\\", "\\\\").replace('"', '\\"')
                content = content.replace("\n", "\\r\\n")
                lines.append(f'[{elapsed_sec:.6f}, "o", "{content}"]')
            elif event.direction == "attacker_to_honeypot":
                # Input event ('i' type)
                content = event.content.replace("\\", "\\\\").replace('"', '\\"')
                lines.append(f'[{elapsed_sec:.6f}, "i", "{content}\\r\\n"]')

        return "\n".join(lines)

    def to_json_export(self) -> str:
        """Export full session as structured JSON for SIEM/forensics."""
        export = self.to_dict()
        export["events"] = [e.to_dict() for e in self.events]
        return json.dumps(export, indent=2)

    def to_csv_export(self) -> str:
        """Export events as CSV for spreadsheet analysis."""
        lines = ["timestamp,elapsed_ms,type,direction,content,mitre_techniques"]
        for e in self.events:
            content_escaped = e.content.replace('"', '""')[:200]
            mitre = "|".join(e.mitre_techniques)
            lines.append(
                f'"{e.timestamp}",{e.elapsed_ms},"{e.event_type}",'
                f'"{e.direction}","{content_escaped}","{mitre}"'
            )
        return "\n".join(lines)



class SessionRecorder:
    """
    Records complete session timelines for forensic analysis and replay.
    Stores events with precise timing and enrichment annotations.
    """

    def __init__(self, max_recordings: int = 500):
        self._active_recordings: Dict[str, SessionRecording] = {}
        self._completed_recordings: List[SessionRecording] = []
        self._max_recordings = max_recordings
        self._lock = asyncio.Lock()

    def start_recording(
        self, session_id: str, attacker_ip: str,
        attacker_port: int, service: str, username: str = ""
    ) -> SessionRecording:
        """Begin recording a new session."""
        recording = SessionRecording(
            session_id=session_id,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            service=service,
            username=username,
            start_time=time.time(),
        )
        self._active_recordings[session_id] = recording

        # Record session start event
        self._add_event(session_id, TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=0.0,
            event_type="session_start",
            direction="system",
            content=f"Session started on {service} from {attacker_ip}:{attacker_port}",
        ))

        logger.debug(f"[Replay] Started recording session {session_id}")
        return recording

    def record_input(
        self, session_id: str, command: str,
        mitre_techniques: List[str] = None
    ) -> None:
        """Record an attacker input/command."""
        recording = self._active_recordings.get(session_id)
        if not recording:
            return

        event = TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="input",
            direction="attacker_to_honeypot",
            content=command,
            mitre_techniques=mitre_techniques or [],
        )
        self._add_event(session_id, event)
        recording.total_commands += 1

    def record_output(
        self, session_id: str, response: str
    ) -> None:
        """Record a honeypot response."""
        recording = self._active_recordings.get(session_id)
        if not recording:
            return

        event = TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="output",
            direction="honeypot_to_attacker",
            content=response,
        )
        self._add_event(session_id, event)
        recording.total_responses += 1

    def record_auth(
        self, session_id: str, username: str, password: str, success: bool
    ) -> None:
        """Record an authentication attempt."""
        recording = self._active_recordings.get(session_id)
        if not recording:
            return

        event = TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="auth",
            direction="attacker_to_honeypot",
            content=f"{username}:{password}",
            metadata={"success": success, "username": username},
        )
        self._add_event(session_id, event)

    def record_file_access(
        self, session_id: str, action: str, filepath: str
    ) -> None:
        """Record a file access event (read, write, upload)."""
        recording = self._active_recordings.get(session_id)
        if not recording:
            return

        event = TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="file_access",
            direction="attacker_to_honeypot",
            content=f"{action}: {filepath}",
            metadata={"action": action, "path": filepath},
        )
        self._add_event(session_id, event)

    def record_alert(
        self, session_id: str, alert_type: str, details: str
    ) -> None:
        """Record a security alert event in the timeline."""
        recording = self._active_recordings.get(session_id)
        if not recording:
            return

        event = TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="alert",
            direction="system",
            content=f"[{alert_type}] {details}",
            metadata={"alert_type": alert_type},
        )
        self._add_event(session_id, event)

    async def end_recording(
        self, session_id: str,
        profiler_summary: Dict = None,
        geo_data: Dict = None,
        fingerprint_data: Dict = None,
    ) -> Optional[SessionRecording]:
        """
        Finalize and archive a session recording.
        Returns the completed recording.
        """
        recording = self._active_recordings.pop(session_id, None)
        if not recording:
            return None

        recording.end_time = time.time()
        recording.duration_seconds = recording.end_time - recording.start_time

        # Attach enrichment summaries
        if profiler_summary:
            recording.profiler_summary = profiler_summary
        if geo_data:
            recording.geo_data = geo_data
        if fingerprint_data:
            recording.fingerprint_data = fingerprint_data

        # Build MITRE summary from events
        mitre_counts: Dict[str, int] = {}
        for event in recording.events:
            for tech in event.mitre_techniques:
                mitre_counts[tech] = mitre_counts.get(tech, 0) + 1
        recording.mitre_summary = mitre_counts

        # Add to completed recordings (with cap)
        async with self._lock:
            self._completed_recordings.append(recording)
            if len(self._completed_recordings) > self._max_recordings:
                self._completed_recordings = self._completed_recordings[-self._max_recordings:]

        # Record end event
        self._add_event_to_recording(recording, TimelineEvent(
            timestamp=time.time(),
            elapsed_ms=self._elapsed(recording),
            event_type="session_end",
            direction="system",
            content=f"Session ended. Duration: {recording.duration_seconds:.1f}s, "
                    f"Commands: {recording.total_commands}",
        ))

        logger.info(
            f"[Replay] Session {session_id} recorded: "
            f"{recording.total_commands} commands, "
            f"{recording.duration_seconds:.1f}s duration"
        )
        return recording

    def _add_event(self, session_id: str, event: TimelineEvent) -> None:
        """Add event to active recording."""
        recording = self._active_recordings.get(session_id)
        if recording:
            recording.events.append(event)

    def _add_event_to_recording(
        self, recording: SessionRecording, event: TimelineEvent
    ) -> None:
        """Add event directly to a recording object."""
        recording.events.append(event)

    def _elapsed(self, recording: SessionRecording) -> float:
        """Calculate elapsed milliseconds since recording start."""
        return (time.time() - recording.start_time) * 1000.0

    # =========================================================================
    # Query & Export Methods
    # =========================================================================

    def get_recording(self, session_id: str) -> Optional[SessionRecording]:
        """Get a recording by session ID (active or completed)."""
        if session_id in self._active_recordings:
            return self._active_recordings[session_id]
        for rec in self._completed_recordings:
            if rec.session_id == session_id:
                return rec
        return None

    def search_commands(self, query: str, limit: int = 50) -> List[Dict]:
        """Search all recorded commands across sessions."""
        results = []
        query_lower = query.lower()

        all_recordings = list(self._completed_recordings) + list(
            self._active_recordings.values()
        )

        for rec in all_recordings:
            for event in rec.events:
                if event.event_type == "input" and query_lower in event.content.lower():
                    results.append({
                        "session_id": rec.session_id,
                        "attacker_ip": rec.attacker_ip,
                        "service": rec.service,
                        "command": event.content,
                        "timestamp": event.timestamp,
                        "mitre": event.mitre_techniques,
                    })
                    if len(results) >= limit:
                        return results
        return results

    def get_recent_recordings(self, limit: int = 20) -> List[Dict]:
        """Get metadata for recent completed recordings."""
        return [
            rec.to_dict() for rec in self._completed_recordings[-limit:]
        ]

    def export_asciinema(self, session_id: str) -> Optional[str]:
        """Export a session as Asciinema v2 format."""
        recording = self.get_recording(session_id)
        if recording:
            return recording.to_asciinema_v2()
        return None

    def export_json(self, session_id: str) -> Optional[str]:
        """Export a session as full JSON."""
        recording = self.get_recording(session_id)
        if recording:
            return recording.to_json_export()
        return None

    def get_stats(self) -> Dict:
        """Return recording statistics."""
        return {
            "active_recordings": len(self._active_recordings),
            "completed_recordings": len(self._completed_recordings),
            "total_events_recorded": sum(
                len(r.events) for r in self._completed_recordings
            ) + sum(
                len(r.events) for r in self._active_recordings.values()
            ),
        }


# =============================================================================
# Module-level singleton
# =============================================================================
session_recorder = SessionRecorder()
