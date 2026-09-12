"""Background thumbnail capture and audio-track probing."""
import os
import socket
import subprocess
import sys

from PyQt6.QtCore import QThread, QRunnable, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QPixmap

# ── Thumbnail generation ───────────────────────────────────────────────────────

class ThumbnailWorker(QThread):
    done = pyqtSignal(str, int, str)   # ip, port, thumb_file_path ('' = failed)

    def __init__(self, ip, port, mpv_path, thumb_dir, timeout):
        super().__init__()
        self._ip = ip
        self._port = port
        self._mpv_path = mpv_path
        self._thumb_dir = thumb_dir
        self._timeout = timeout
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
        cmd = [self._mpv_path, f'rtsp://{self._ip}:{self._port}',
               f'-o={thumb}', '--ovc=png', '--frames=1',
               '--really-quiet', '--no-terminal']
        # Strip display vars so MPV cannot open any window even if a
        # display is already active (e.g. other MPV windows are open)
        env = os.environ.copy()
        if sys.platform == 'linux':
            env.pop('DISPLAY', None)
            env.pop('WAYLAND_DISPLAY', None)
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL, env=env)
            try:
                self._proc.wait(timeout=self._timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self.done.emit(self._ip, self._port, '')
                return
            if os.path.isfile(thumb) and os.path.getsize(thumb) > 0:
                self.done.emit(self._ip, self._port, thumb)
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
        self._queue = []    # [(ip, port, mpv_path, timeout)]
        self._active = {}   # (ip, port) → ThumbnailWorker

    def add(self, ip, port, mpv_path, timeout):
        key = (ip, port)
        if key in self._active or any(q[0] == ip and q[1] == port
                                       for q in self._queue):
            return
        self._queue.append((ip, port, mpv_path, timeout))
        self._process_queue()

    def _process_queue(self):
        max_w = self._get_max_workers()
        while self._queue and len(self._active) < max_w:
            ip, port, mpv_path, timeout = self._queue.pop(0)
            thumb_dir = os.path.join(self._temp_dir, f'{ip}_{port}')
            w = ThumbnailWorker(ip, port, mpv_path, thumb_dir, timeout)
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


# ── Audio detection via RTSP DESCRIBE ─────────────────────────────────────────

def _probe_audio(ip, port, timeout=3):
    """RTSP DESCRIBE to detect audio track. Returns 'AV', 'V', or None on failure."""
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
        return 'AV' if b'm=audio' in data else 'V'
    except Exception:
        return None


class AudioProbeTask(QRunnable):
    class Signals(QObject):
        done = pyqtSignal(str, int, str)   # ip, port, 'V'|'AV'

    def __init__(self, ip, port):
        super().__init__()
        self.signals = self.Signals()
        self._ip = ip
        self._port = port
        self.setAutoDelete(True)

    def run(self):
        result = _probe_audio(self._ip, self._port)
        self.signals.done.emit(self._ip, self._port, result or 'V')

