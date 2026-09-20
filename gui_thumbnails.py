"""Background thumbnail capture and audio-track probing."""
import os
import socket
import subprocess
import sys
from urllib.parse import quote

from PyQt6.QtCore import QThread, QRunnable, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QPixmap


def build_rtsp_url(ip, port, username=None, password=None):
    """rtsp://ip:port, or rtsp://user:pass@ip:port when credentials are known.
    Percent-encodes user/pass so special characters (':', '@', '/', ...) can't
    break the URL."""
    if username or password:
        return (f'rtsp://{quote(username or "", safe="")}:'
                f'{quote(password or "", safe="")}@{ip}:{port}')
    return f'rtsp://{ip}:{port}'


# ── Thumbnail generation ───────────────────────────────────────────────────────

def build_capture_cmd(mpv_path, url, thumb_file, timeout):
    """mpv command that decodes and saves a single video frame to thumb_file."""
    return [mpv_path, url,
            f'-o={thumb_file}', '--ovc=png', '--frames=1',
            '--really-quiet', '--no-terminal', f'--end={timeout}']


def capture_env():
    """Env with DISPLAY/WAYLAND_DISPLAY stripped on Linux so mpv can't open a window
    even if a display is already active (e.g. other MPV windows are open)."""
    if sys.platform == 'linux':
        env = os.environ.copy()
        env.pop('DISPLAY', None)
        env.pop('WAYLAND_DISPLAY', None)
        return env
    return None


def find_thumbnail_file(thumb_dir):
    candidate = os.path.join(thumb_dir, 'thumb.png')
    if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
        return candidate
    return None


class ThumbnailWorker(QThread):
    done = pyqtSignal(str, int, str)   # ip, port, thumb_file_path ('' = failed)

    def __init__(self, ip, port, mpv_path, thumb_dir, timeout,
                 username=None, password=None):
        super().__init__()
        self._ip = ip
        self._port = port
        self._mpv_path = mpv_path
        self._thumb_dir = thumb_dir
        self._timeout = timeout
        self._username = username
        self._password = password
        self._proc = None

    def abort(self):
        """Kill the MPV subprocess so run() exits immediately."""
        if self._proc:
            try:
                self._proc.kill()
            except Exception:
                pass

    def run(self):
        os.makedirs(self._thumb_dir, exist_ok=True)
        thumb = os.path.join(self._thumb_dir, 'thumb.png')
        url = build_rtsp_url(self._ip, self._port, self._username, self._password)
        cmd = build_capture_cmd(self._mpv_path, url, thumb, self._timeout)
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, env=capture_env())
            try:
                self._proc.wait(timeout=self._timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self.done.emit(self._ip, self._port, '')
                return
            thumb_file = find_thumbnail_file(self._thumb_dir)
            if thumb_file:
                self.done.emit(self._ip, self._port, thumb_file)
                return
        except Exception:
            pass
        finally:
            self._proc = None
        self.done.emit(self._ip, self._port, '')


class ThumbnailManager(QObject):
    thumbnail_ready = pyqtSignal(str, int, object)  # ip, port, QPixmap|None

    def __init__(self, temp_dir, get_max_workers, parent=None):
        super().__init__(parent)
        self._temp_dir = temp_dir
        self._get_max_workers = get_max_workers
        self._queue = []    # [(ip, port, mpv_path, timeout, username, password)]
        self._active = {}   # (ip, port) → ThumbnailWorker

    def add(self, ip, port, mpv_path, timeout, username=None, password=None):
        key = (ip, port)
        if key in self._active or any(q[0] == ip and q[1] == port
                                       for q in self._queue):
            return
        self._queue.append((ip, port, mpv_path, timeout, username, password))
        self._process_queue()

    def _process_queue(self):
        max_w = self._get_max_workers()
        while self._queue and len(self._active) < max_w:
            ip, port, mpv_path, timeout, username, password = self._queue.pop(0)
            thumb_dir = os.path.join(self._temp_dir, f'{ip}_{port}')
            w = ThumbnailWorker(ip, port, mpv_path, thumb_dir, timeout,
                               username=username, password=password)
            w.done.connect(self._worker_done)
            # Keep strong Python reference until after finished fires
            w.finished.connect(lambda worker=w: self._thumb_worker_finished(worker))
            self._active[(ip, port)] = w
            w.start()

    def _thumb_worker_finished(self, worker):
        """Called after the thread has fully stopped; safe to delete."""
        worker.deleteLater()

    @pyqtSlot(str, int, str)
    def _worker_done(self, ip, port, file_path):
        self._active.pop((ip, port), None)
        pixmap = None
        if file_path:
            px = QPixmap(file_path)
            pixmap = px if not px.isNull() else None
        self.thumbnail_ready.emit(ip, port, pixmap)
        self._process_queue()

    def stop(self):
        self._queue.clear()
        workers = list(self._active.values())
        self._active.clear()   # stop tracking; workers kept alive by local list
        for w in workers:
            w.abort()
        for w in workers:
            w.wait(2000)       # generous: abort() kills MPV so thread exits fast


# ── RTSP DESCRIBE probing: audio track detection, auth requirement ───────────

def _rtsp_describe(ip, port, timeout=3):
    """Send a raw RTSP DESCRIBE and return (status_code, body_bytes).
    status_code is the numeric RTSP response code (e.g. 200, 401, 404) parsed
    from the response's status line, or None if the request/response itself
    failed (timeout, connection refused, malformed response, ...)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = (f'DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n'
                   f'CSeq: 1\r\nAccept: application/sdp\r\n'
                   f'User-Agent: VulnCam/1.0\r\n\r\n')
            s.sendall(req.encode())
            data = b''
            while len(data) < 8192:
                try:
                    chunk = s.recv(2048)
                    if not chunk:
                        break
                    data += chunk
                    if b'\r\n\r\n' in data:
                        hdr_end = data.index(b'\r\n\r\n') + 4
                        cl = 0
                        for line in data[:hdr_end].decode('utf-8', errors='ignore').splitlines():
                            if line.lower().startswith('content-length:'):
                                cl = int(line.split(':', 1)[1].strip())
                                break
                        if cl == 0 or len(data) - hdr_end >= cl:
                            break
                except socket.timeout:
                    break
    except Exception:
        return None, b''
    status = None
    first_line = data.split(b'\r\n', 1)[0].decode('utf-8', errors='ignore')
    parts = first_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, data


def _probe_audio(ip, port, timeout=3):
    """RTSP DESCRIBE to detect audio track.
    Returns (audio_type, raw_text): audio_type is 'AV'/'V'/None on failure."""
    _status, data = _rtsp_describe(ip, port, timeout)
    if not data:
        return None, ''
    audio_type = 'AV' if b'm=audio' in data else 'V'
    return audio_type, data.decode('utf-8', errors='replace')


def probe_needs_auth(ip, port, timeout=3):
    """Returns (needs_auth, raw_text). needs_auth is True only for a 401/403
    response (credentials required) — distinct from a timeout/refused
    connection, which means it's just not there."""
    status, data = _rtsp_describe(ip, port, timeout)
    return status in (401, 403), data.decode('utf-8', errors='replace')


def _emit_probe_result(signals, *args):
    """Ignore a result that races with Qt/Python application teardown."""
    try:
        signals.done.emit(*args)
    except RuntimeError:
        pass


class AudioProbeTask(QRunnable):
    class Signals(QObject):
        done = pyqtSignal(str, int, str, str)   # ip, port, 'V'|'AV', raw_text

    def __init__(self, ip, port):
        super().__init__()
        self.signals = self.Signals()
        self._ip = ip
        self._port = port
        self.setAutoDelete(True)

    def run(self):
        audio_type, raw_text = _probe_audio(self._ip, self._port)
        _emit_probe_result(
            self.signals, self._ip, self._port, audio_type or 'V', raw_text)


class AuthProbeTask(QRunnable):
    class Signals(QObject):
        done = pyqtSignal(str, int, bool, str)   # ip, port, needs_auth, raw_text

    def __init__(self, ip, port):
        super().__init__()
        self.signals = self.Signals()
        self._ip = ip
        self._port = port
        self.setAutoDelete(True)

    def run(self):
        needs_auth, raw_text = probe_needs_auth(self._ip, self._port)
        _emit_probe_result(
            self.signals, self._ip, self._port, needs_auth, raw_text)

