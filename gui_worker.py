"""Background VulnCam worker: GUIVulnCam core logic + the QThread that runs it."""
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from random import sample, shuffle

import requests
import shodan
from PyQt6.QtCore import QThread, pyqtSignal

from vulncam import VulnCam, REQUIRED_SECTION, DEFAULT_TIMEOUT, RESULTS_PER_PAGE, MAX_PAGES
from gui_thumbnails import build_capture_cmd, capture_env, find_thumbnail_file
from gui_constants import RECORDINGS_DIR

_vulncam_logger = logging.getLogger('vulncam')


class GUIVulnCam(VulnCam):
    """VulnCam for GUI: no signal.signal setup, no sys.exit, status callbacks."""

    def __init__(self, config, args):
        self._init_state(config, args)
        self._known_pids      = set()
        self.probe             = getattr(args, 'probe', False)
        self.thumb_timeout     = getattr(args, 'thumb_timeout', DEFAULT_TIMEOUT)
        self.shodan_plan       = getattr(args, 'shodan_plan', '')
        self._log_dev_plan_limit = getattr(args, 'log_dev_plan_limit', '')
        self.thumb_base_dir    = None    # set by worker before run()
        self.on_stream_added       = None
        self.on_stream_status      = None
        self.on_window_opened      = None   # (pid, ip, port, record_path) → live MPV window appeared
        self.on_thumbnail_generated = None  # (ip, port, file_path) -> None
        self.should_skip_stream    = None
        self.on_stream_skipped     = None
        self.on_stats_update       = None
        self.get_max_processes     = None

    def _sigint_handler(self, _signum, _frame):
        self.signal_received = True
        self._kill_unfinished_processes()

    def _active_processes(self):
        if self.probe:
            # Silent mode: just count; _check_working handles cleanup
            return sum(1 for info in self.processes.values()
                       if info['process'].poll() is None)
        return super()._active_processes()

    def _on_process_removed(self, info):
        if not info['working'] and self.on_stream_status:
            self.on_stream_status(info['title'], 'failed')

    def _check_working(self):
        # Detect new PIDs in both modes
        for pid, info in list(self.processes.items()):
            if pid not in self._known_pids:
                self._known_pids.add(pid)
                if self.on_stream_added:
                    self.on_stream_added(info['title'])

        if self.probe:
            now = time.time()
            for pid in list(self.processes):
                info = self.processes[pid]
                ret = info['process'].poll()
                if ret is not None:
                    self.processes.pop(pid)
                    thumb_dir = info.get('thumb_dir', '')
                    # MPV may exit non-zero even when the frame was saved;
                    # check file existence rather than relying on exit code.
                    thumb_file = find_thumbnail_file(thumb_dir) if thumb_dir else None
                    _vulncam_logger.debug(
                        '%s thumbnail exit=%s file=%s', info['title'], ret,
                        thumb_file or 'none')
                    if thumb_file:
                        if self.on_stream_status:
                            self.on_stream_status(info['title'], 'working')
                        if self.on_thumbnail_generated:
                            self.on_thumbnail_generated(
                                info['ip'], info['port'], thumb_file)
                    else:
                        if self.on_stream_status:
                            self.on_stream_status(info['title'], 'failed')
                elif (now - info['launch_time']) > (self.thumb_timeout + 5):
                    try:
                        info['process'].kill()
                    except Exception:
                        pass
                    self.processes.pop(pid)
                    if self.on_stream_status:
                        self.on_stream_status(info['title'], 'failed')
            if self.on_stats_update:
                self.on_stats_update(len(self.processes), 0)
            return 0  # no visible windows in probe mode

        cnt_working = self._scan_window_status()
        if self.on_stats_update:
            self.on_stats_update(len(self.processes), cnt_working)
        return cnt_working

    def _on_stream_working(self, pid, info):
        if self.on_stream_status:
            self.on_stream_status(info['title'], 'working')
        if self.on_window_opened:
            self.on_window_opened(pid, info['ip'], info['port'], info.get('record_path') or '')

    def _on_stream_timeout(self, pid, info):
        if not info['working'] and self.on_stream_status:
            self.on_stream_status(info['title'], 'failed')

    @staticmethod
    def _shodan_geo(result):
        loc = result.get('location') or {}
        return (loc.get('country_name') or '-',
                loc.get('region_name')  or '-',
                loc.get('city')         or '-')

    def _query_pages_with_geo(self, query, pages):
        results = []
        try:
            total = self.api.count(query)['total']
            if total == 0:
                return 0, results
            total_pages = max(1, (total + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE)
            available = min(MAX_PAGES, total_pages)
            n = min(pages, available)
            if self.random_pages and self.shodan_plan == 'dev' and n > 1:
                _vulncam_logger.info(self._log_dev_plan_limit)
                n = 1
            if self.random_pages:
                page_list = sorted(sample(range(1, available + 1), n))
            else:
                page_list = list(range(1, n + 1))
            for next_page in page_list:
                _vulncam_logger.info('Fetching page %d...', next_page)
                try:
                    q = self.api.search(query, page=next_page)
                except shodan.APIError as e:
                    _vulncam_logger.warning('Page %d failed: %s', next_page, e)
                    continue
                count = len(q.get('matches', []))
                _vulncam_logger.info('Page %d: %d result(s)', next_page, count)
                for r in q['matches']:
                    ip = r['ip_str']
                    results.append((ip, r['port']))
                    self._geo_cache[ip] = self._shodan_geo(r)
            if self.random_pages:
                shuffle(results)
            return total, results
        except shodan.APIError as e:
            _vulncam_logger.error('Error: %s', e)
            return None, None

    def _query_all_with_geo(self, query):
        matches = []
        try:
            for r in self.api.search_cursor(query):
                ip = r['ip_str']
                matches.append((ip, r['port']))
                self._geo_cache[ip] = self._shodan_geo(r)
                if len(matches) % 100 == 0:
                    _vulncam_logger.info('Retrieved %d results so far...', len(matches))
        except shodan.APIError as e:
            _vulncam_logger.error('Error: %s', e)
        return matches

    def _batch_geo_lookup(self, ips):
        """Resolve geo for a list of IPs via ip-api.com/batch (100 per request)."""
        for i in range(0, len(ips), 100):
            try:
                r = requests.post(
                    'http://ip-api.com/batch',
                    json=[{'query': ip} for ip in ips[i:i + 100]],
                    timeout=10,
                )
                for item in r.json():
                    ip = item.get('query', '')
                    if ip and item.get('status') == 'success':
                        self._geo_cache[ip] = (
                            item.get('country', '-') or '-',
                            item.get('regionName', '-') or '-',
                            item.get('city', '-') or '-',
                        )
            except Exception:
                continue  # geo is optional

    def run(self, query, total_results, pages):
        info = self.api.info()
        _vulncam_logger.info('Credits: %d', info['query_credits'])
        _vulncam_logger.info('Launching query: %s', query)
        if total_results:
            total_count = self.api.count(query)['total']
            pages_needed = max(1, (total_count + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE)
            _vulncam_logger.info('Total results in Shodan: %d (%d pages, %d credits needed)',
                                 total_count, pages_needed, pages_needed)
            matches = self._query_all_with_geo(query)   # Shodan geo as fallback
            _vulncam_logger.info('%d results retrieved.', len(matches))
        else:
            total_matches, matches = self._query_pages_with_geo(query, pages)
            if total_matches is None:
                _vulncam_logger.error('Error. Exiting...')
                return
            _vulncam_logger.info('The query returns %d matches in Shodan.', total_matches)
            _vulncam_logger.info('Working with %d.', len(matches))
        if not matches:
            return
        # Upgrade geo with ip-api batch (better quality); Shodan data stays as fallback
        ips = [ip for ip, _port in matches]
        _vulncam_logger.info('Fetching geo data for %d IPs...', len(ips))
        self._batch_geo_lookup(ips)
        self._run_match_loop(matches)

    def run_matches(self, matches):
        # Batch geo lookup for IPs not already cached (e.g. loaded from JSON)
        uncached = [ip for ip, _port in matches if ip not in self._geo_cache]
        if uncached:
            _vulncam_logger.info('Fetching geo data for %d IPs...', len(uncached))
            self._batch_geo_lookup(uncached)
        self._run_match_loop(matches)

    def _run_match_loop(self, matches):
        mpv_path = self.config[REQUIRED_SECTION]['mpvfilepath']
        for idx, match in enumerate(matches):
            if self.signal_received:
                break
            if self.should_skip_stream and self.should_skip_stream(match[0], match[1]):
                if self.on_stream_skipped:
                    self.on_stream_skipped('%s:%d' % (match[0], match[1]))
                continue
            _max_p = self.get_max_processes() if self.get_max_processes else self.max_processes
            while not self.signal_received and self._active_processes() >= _max_p:
                self._check_working()
                _vulncam_logger.debug('Waiting for some process to finish...')
                time.sleep(1)
                _max_p = self.get_max_processes() if self.get_max_processes else self.max_processes
            if self.signal_received:
                break
            location = self._get_geo_info(match[0])
            title = '[%d] %s:%d (%s-%s-%s)' % tuple((idx + 1,) + match + location)
            _vulncam_logger.info(title)
            thumb_dir = None
            record_path = None
            if self.probe:
                thumb_dir = os.path.join(
                    self.thumb_base_dir or '', f'{match[0]}_{match[1]}')
                os.makedirs(thumb_dir, exist_ok=True)
                thumb_file_path = os.path.join(thumb_dir, 'thumb.png')
                cmd = build_capture_cmd(mpv_path, match[0], match[1],
                                        thumb_file_path, self.thumb_timeout)
            elif self.stream_record:
                # Absolute path: must match what VulnCamWindow._recording_folder()
                # computes (also absolute), since the GUI later opens these files
                # via QUrl.fromLocalFile(), which needs an absolute path.
                folder = os.path.abspath(
                    os.path.join(RECORDINGS_DIR, f'{match[0]}_{match[1]}'))
                os.makedirs(folder, exist_ok=True)
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                record_path = os.path.join(folder, f'{ts}.mkv')
                cmd = [mpv_path, f'--title={title}',
                       f'--stream-record={record_path}',
                       'rtsp://%s:%d' % match, '--mute=yes']
            else:
                cmd = [mpv_path, f'--title={title}',
                       'rtsp://%s:%d' % match, '--mute=yes']
            if not self.probe and sys.platform == 'linux':
                cmd.append('--gpu-context=x11egl')
            popen_env = capture_env() if self.probe else None
            mpv_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.STDOUT,
                                        env=popen_env)
            self.processes[mpv_proc.pid] = {
                'process': mpv_proc,
                'title': title,
                'launch_time': time.time(),
                'working': False,
                'ip': match[0],
                'port': match[1],
                'thumb_dir': thumb_dir,
                'record_path': record_path,
            }
            time.sleep(0.2)
            self._check_working()  # detect new PID immediately → on_stream_added

        if self.signal_received:
            return
        if not self.probe and self.leave_windows:
            while not self.signal_received and \
                    self._active_processes() > self._check_working():
                time.sleep(1)
        else:
            while not self.signal_received and self._active_processes() > 0:
                self._check_working()
                time.sleep(1)
            if not self.signal_received:
                self._check_working()  # final sweep: catch exits during last sleep


class _QtLogHandler(logging.Handler):
    def __init__(self, signal):
        super().__init__()
        self.signal = signal

    def emit(self, record):
        self.signal.emit(self.format(record))


class VulnCamWorker(QThread):
    log_message         = pyqtSignal(str)
    finished            = pyqtSignal()
    error               = pyqtSignal(str)
    stream_added        = pyqtSignal(str)
    stream_status       = pyqtSignal(str, str)
    stream_skipped      = pyqtSignal(str)
    stats_update        = pyqtSignal(int, int)
    thumbnail_generated = pyqtSignal(str, int, str)  # ip, port, file_path
    window_opened       = pyqtSignal(int, str, int, str)   # pid, ip, port, record_path ('' = none)

    def __init__(self, config, args, matches=None, skip_fn=None,
                 max_procs_ref=None, thumb_base_dir=None):
        super().__init__()
        self.config         = config
        self.args           = args
        self.matches        = matches
        self.skip_fn        = skip_fn
        self.max_procs_ref  = max_procs_ref
        self.thumb_base_dir = thumb_base_dir
        self.vulncam = None
        self._handler = None

    def run(self):
        self._handler = _QtLogHandler(self.log_message)
        self._handler.setFormatter(logging.Formatter('%(message)s'))
        _vulncam_logger.addHandler(self._handler)
        _vulncam_logger.setLevel(logging.DEBUG if self.args.verbose else logging.INFO)
        try:
            self.vulncam = GUIVulnCam(self.config, self.args)
            self.vulncam.on_stream_added        = self.stream_added.emit
            self.vulncam.on_stream_status       = self.stream_status.emit
            self.vulncam.should_skip_stream     = self.skip_fn
            self.vulncam.on_stream_skipped      = self.stream_skipped.emit
            self.vulncam.on_stats_update        = self.stats_update.emit
            self.vulncam.on_window_opened       = self.window_opened.emit
            self.vulncam.on_thumbnail_generated = self.thumbnail_generated.emit
            self.vulncam.thumb_base_dir         = self.thumb_base_dir
            if self.max_procs_ref:
                self.vulncam.get_max_processes = lambda: self.max_procs_ref[0]
            if self.matches is not None:
                self.vulncam.run_matches(self.matches)
            else:
                query = (self.args.query + ' ' + self.args.extend).strip()
                self.vulncam.run(query=query, total_results=self.args.total_results,
                                 pages=self.args.pages)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            _vulncam_logger.removeHandler(self._handler)
            self.finished.emit()

    def stop(self):
        if self.vulncam:
            self.vulncam._sigint_handler(None, None)


