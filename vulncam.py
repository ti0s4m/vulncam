import argparse
import configparser
from datetime import datetime
import logging
import psutil
import subprocess
import shodan
import time
import requests
import signal
import sys
from random import sample, shuffle

DEFAULT_CONFIG_FILE = 'config.ini'
DEFAULT_QUERY = 'RTSP has_screenshot:yes'
DEFAULT_PAGES = 1
RESULTS_PER_PAGE = 100
DEFAULT_MAX_PROCS = 16
DEFAULT_TIMEOUT = 15
MAX_PAGES = 100
GEO_TIMEOUT = 10
IP_API = 'http://ip-api.com/json/%s'
IP_GEO = 'https://api.ipgeolocation.io/ipgeo?apiKey=%s&ip=%s'
REQUIRED_SECTION = 'REQUIRED'
REQUIRED_PARAMS = ('shodanapikey', 'mpvfilepath')
OPTIONAL_SECTION = 'OPTIONAL'
OPTIONAL_PARAMS = ('ipgeoapikey',)
RC_SIGINT = 1
RC_WRONG_CONFIG = 2
LINUX_SOFTWARE = ['mpv', 'wmctrl']

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description='RTSP Stream manager using Shodan.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', '--config', type=str, help='Config file', default=DEFAULT_CONFIG_FILE)
    parser.add_argument('-q', '--query', type=str, help='Query to be launched in Shodan',
                        default=DEFAULT_QUERY)
    parser.add_argument('-x', '--extend', type=str,
                        help='Extend the default query with additional parameters', default='')
    parser.add_argument('-r', '--random-pages', help='Choose pages randomly instead of sequentially',
                        action='store_true')
    parser.add_argument('-p', '--pages', type=int,
                        help='Number of pages that will be retrieved from Shodan', default=DEFAULT_PAGES)
    parser.add_argument('-t', '--total-results', help='All results are requested from Shodan',
                        action='store_true')
    parser.add_argument('-s', '--stream-record', help='Records the streams in mkv files',
                        action='store_true')
    parser.add_argument('-m', '--max-processes', type=int, help='Max parallel processes',
                        default=DEFAULT_MAX_PROCS)
    parser.add_argument('-w', '--max-windows', type=int, help='Max parallel stream windows',
                        default=DEFAULT_MAX_PROCS)
    parser.add_argument('-l', '--leave-windows', help='Leave working stream windows when finish.',
                        action='store_true')
    parser.add_argument('-v', '--verbose', help='Verbose outputs', action='store_true')
    return parser.parse_args()


def check_config(config):
    """
    Checks that the config file contains all required parameters.
    :return: True if the config file has all required parameters.
    """
    if not config.has_section(REQUIRED_SECTION):
        return False
    required = dict(config.items(REQUIRED_SECTION))
    for r_param in REQUIRED_PARAMS:
        if r_param not in required:
            return False
    for section in config.sections():
        if section not in (REQUIRED_SECTION, OPTIONAL_SECTION):
            logger.warning('Config: Unknown section: %s', section)
        elif section == REQUIRED_SECTION:
            for (key, _) in config.items(section):
                if key not in REQUIRED_PARAMS:
                    logger.warning('Config: Unknown parameter in %s section: %s', section, key)
        else:
            for (key, _) in config.items(section):
                if key not in OPTIONAL_PARAMS:
                    logger.warning('Config: Unknown parameter in %s section: %s', section, key)
    return True


def check_linux_software():
    """
    Checks that all required software on Linux is installed.
    :return: True if everything is installed, False otherwise.
    """
    for software in LINUX_SOFTWARE:
        if subprocess.call(['which', software], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) != 0:
            logger.error('%s is not installed.', software)
            return False
    return True


def list_window_titles():
    """Return list of visible window titles, cross-platform (Linux/Windows)."""
    if sys.platform == 'linux':
        try:
            out = subprocess.run(['wmctrl', '-l'], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL).stdout.decode()
            return [' '.join(w.split()[3:]).replace('"', '')
                    for w in out.strip().splitlines() if w.split()]
        except Exception:
            return []
    if sys.platform == 'win32':
        import ctypes
        titles = []
        def _cb(hwnd, _):
            if ctypes.windll.user32.IsWindowVisible(hwnd):
                n = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                if n:
                    buf = ctypes.create_unicode_buffer(n + 1)
                    ctypes.windll.user32.GetWindowTextW(hwnd, buf, n + 1)
                    titles.append(buf.value.replace('"', ''))
            return True
        EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        ctypes.windll.user32.EnumWindows(EnumProc(_cb), 0)
        return titles
    return []


class VulnCam:
    def __init__(self, config, args):
        self.config        = config
        self.random_pages  = args.random_pages
        self.leave_windows = args.leave_windows
        self.max_processes = args.max_processes
        self.max_windows   = args.max_windows
        self.stream_record = args.stream_record

        self.processes       = {}
        self.signal_received = False
        self._geo_cache        = {}
        self._last_geo_request = 0.0

        self.api = shodan.Shodan(config[REQUIRED_SECTION]['shodanapikey'])
        signal.signal(signal.SIGINT, self._sigint_handler)

    def _sigint_handler(self, _signum, _frame):
        self.signal_received = True
        logger.info('\nKilling active processes...')
        for pid in list(self.processes):
            if not self.leave_windows or not self.processes[pid]['working']:
                self.processes[pid]['process'].kill()
                self.processes.pop(pid)
        sys.exit(RC_SIGINT)

    def _active_processes(self):
        """Checks active processes and removes zombies or dead entries from the process table."""
        cnt = 0
        for pid in list(self.processes):
            try:
                p = psutil.Process(pid)
                if p.status() == psutil.STATUS_ZOMBIE:
                    self.processes[pid]['process'].kill()
                    del self.processes[pid]
                else:
                    cnt += 1
            except psutil.NoSuchProcess:
                del self.processes[pid]
        return cnt

    def _get_current_windows(self):
        return list_window_titles()

    def _check_working(self):
        """
        Checks if RTSP streams are working by looking for their MPV window on screen.
        Kills processes that exceed the timeout without opening a window.
        :return: Number of working streams.
        """
        if sys.platform != 'linux':
            return 0
        current_windows = self._get_current_windows()
        now = time.time()
        cnt_working = 0
        for pid in list(self.processes):
            title = self.processes[pid]['title']
            if title in current_windows:
                if not self.processes[pid]['working']:
                    logger.debug('%s is working :)', title)
                self.processes[pid]['working'] = True
                cnt_working += 1
            elif (now - self.processes[pid]['launch_time']) >= DEFAULT_TIMEOUT:
                logger.debug('Killing %s as it is not working.', title)
                self.processes[pid]['process'].kill()
                self.processes.pop(pid)
        return cnt_working

    # ip-api.com free tier: 45 req/min → 1 req every ~1.4s
    _GEO_MIN_INTERVAL = 1.4

    def _get_geo_info(self, ip):
        """Retrieves country, region, and city for the given IP, with cache and rate limiting."""
        if ip in self._geo_cache:
            return self._geo_cache[ip]

        elapsed = time.time() - self._last_geo_request
        if elapsed < self._GEO_MIN_INTERVAL:
            time.sleep(self._GEO_MIN_INTERVAL - elapsed)

        try:
            r = requests.get(IP_API % ip, timeout=GEO_TIMEOUT)
            j = r.json()
        except Exception:
            j = {}
        # ip-api.com returns HTTP 200 with {"status":"fail"} for private/invalid IPs
        # or when rate-limited, so fall back to ipgeo whenever it has no usable data.
        if (not j or j.get('status') == 'fail') \
                and self.config.has_option(OPTIONAL_SECTION, 'ipgeoapikey'):
            try:
                r = requests.get(IP_GEO % (self.config[OPTIONAL_SECTION]['ipgeoapikey'], ip),
                                 timeout=GEO_TIMEOUT)
                j = r.json()
            except Exception:
                pass
        self._last_geo_request = time.time()
        country = region = city = '-'
        if 'country' in j:
            country = j['country']
        elif 'country_name' in j:
            country = j['country_name']
        if 'regionName' in j:
            region = j['regionName']
        elif 'state_prov' in j:
            region = j['state_prov']
        if 'city' in j:
            city = j['city']
        result = country, region, city
        self._geo_cache[ip] = result
        return result

    def _query_pages(self, query, pages):
        results = []
        try:
            total = self.api.count(query)['total']
            if total == 0:
                return 0, results
            total_pages = max(1, (total + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE)
            available = min(MAX_PAGES, total_pages)
            n = min(pages, available)
            if self.random_pages:
                page_list = sorted(sample(range(1, available + 1), n))
            else:
                page_list = list(range(1, n + 1))
            for next_page in page_list:
                q = self.api.search(query, page=next_page)
                for result in q['matches']:
                    results.append((result['ip_str'], result['port']))
            if self.random_pages:
                shuffle(results)
            return total, results
        except shodan.APIError as e:
            logger.error('Error: %s', e)
            return None, None

    def _query_all(self, query):
        matches = []
        try:
            for match in self.api.search_cursor(query):
                matches.append((match['ip_str'], match['port']))
        except shodan.APIError as e:
            logger.error('Error: %s', e)
        return matches

    def run(self, query, total_results, pages):
        info = self.api.info()
        logger.info('Credits: %d', info['query_credits'])
        logger.info('Launching query: %s', query)

        if total_results:
            matches = self._query_all(query)
            logger.info('%d results retrieved.', len(matches))
        else:
            total_matches, matches = self._query_pages(query, pages)
            if total_matches is None:
                logger.error('Error. Exiting...')
                return
            logger.info('The query returns %d matches in Shodan.', total_matches)
            logger.info('Working with %d.', len(matches))

        if not matches:
            return

        mpv_path = self.config[REQUIRED_SECTION]['mpvfilepath']

        for idx, match in enumerate(matches):
            if self.signal_received:
                break
            while not self.signal_received and self._active_processes() >= self.max_processes:
                self._check_working()
                logger.debug('Waiting for some process to finish...')
                time.sleep(1)
            if self.signal_received:
                break

            location = self._get_geo_info(match[0])
            title = '[%d] %s:%d (%s-%s-%s)' % tuple((idx + 1,) + match + location)
            logger.info(title)

            if self.stream_record:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                mkv_file = '%s_%d.mkv' % (ts, idx + 1)
                cmd = [mpv_path, '--title=%s' % title, '--stream-record=%s' % mkv_file,
                       'rtsp://%s:%d' % match, '--mute=yes']
            else:
                cmd = [mpv_path, '--title=%s' % title, 'rtsp://%s:%d' % match, '--mute=yes']
            if sys.platform == 'linux':
                cmd.append('--gpu-context=x11egl')

            mpv_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            self.processes[mpv_process.pid] = {
                'process': mpv_process,
                'title': title,
                'launch_time': time.time(),
                'working': False,
            }
            time.sleep(0.2)

            while not self.signal_received and self._check_working() >= self.max_windows:
                logger.debug('Max windows limit reached. Not launching more connections until a window is closed...')
                time.sleep(1)

        if self.signal_received:
            return
        if self.leave_windows:
            while self._active_processes() > self._check_working():
                time.sleep(1)
        else:
            while self._active_processes() > 0:
                self._check_working()
                time.sleep(1)
            self._check_working()  # final sweep: catch exits during last sleep


if __name__ == '__main__':
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(message)s',
    )
    config = configparser.ConfigParser()
    config.read(args.config)
    if not check_config(config):
        logger.error('Config: Required parameter is missing.')
        sys.exit(RC_WRONG_CONFIG)
    if sys.platform == 'linux' and not check_linux_software():
        sys.exit(1)
    query = (args.query + ' ' + args.extend).strip()
    vulncam = VulnCam(config, args)
    vulncam.run(query=query, total_results=args.total_results, pages=args.pages)
