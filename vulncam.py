import argparse
import configparser
import psutil
import subprocess
import shodan
import time
import requests
import signal
import sys
import ntpath
from random import shuffle

DEFAULT_CONFIG_FILE = 'config.ini'
DEFAULT_QUERY = 'RTSP has_screenshot:yes'
DEFAULT_PAGES = 1
RESULTS_PER_PAGE = 100
DEFAULT_MAX_PROCS = 10
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
MAX_WORKING = 5
LINUX_SOFTWARE = ['mpv', 'wmctrl']


def debug(msg):
    """
    Prints a message if verbose is enabled.
    """
    if verbose:
        print(msg)

def check_config():
    """
    It checks that the config file contains all required parameters and also prints unknown parameters or sections.
    :return: True if the config file has all required parameters.
    """
    required = dict(config.items(REQUIRED_SECTION))
    for r_param in REQUIRED_PARAMS:
        if r_param not in required:
            return False
    for section in config.sections():
        if section not in (REQUIRED_SECTION, OPTIONAL_SECTION):
            print('Config: Unknown section: %s' % section)
        elif section == REQUIRED_SECTION:
            for (key, val) in config.items(section):
                if key not in REQUIRED_PARAMS:
                    print('Config: Unknown parameter in %s section: %s' % (section, key))
        else:
            for (key, val) in config.items(section):
                if key not in OPTIONAL_PARAMS:
                    print('Config: Unknown parameter in %s section: %s' % (section, key))
    return True


def sigint_handler(signum, frame):
    """
    SIGINT handler. It kills all active processes and finish the program.
    :param signum: The signal number.
    :param frame: The signal frame.
    """
    global signal_received
    signal_received = True
    print('\nKilling active processes...')
    for pid in list(processes):
        if not leave_windows or not processes[pid]['working']:
            processes[pid]['process'].kill()
            processes.pop(pid)
    sys.exit(RC_SIGINT)


def query_shodan_pages(query, pages):
    """
    It launches the query to Shodan limited by number of pages and return the results.
    :param query: The Shodan query.
    :param pages: The number of pages to be retrieved.
    :return: Shodan results.
    """
    results = []
    try:
        q = api.count(query)
        total = q['total']
        if total < RESULTS_PER_PAGE:
            total_pages = 1
        elif total % RESULTS_PER_PAGE == 0:
            total_pages = total // RESULTS_PER_PAGE
        else:
            total_pages = (total // RESULTS_PER_PAGE) + 1
        page_list = list(range(1, min(MAX_PAGES, total_pages + 1)))
        if random_pages:
            shuffle(page_list)
        for p in range(min(pages, total_pages)):
            next_page = page_list.pop(0)
            q = api.search(query, page=next_page)
            for result in q['matches']:
                results.append((result['ip_str'], result['port']))
        return q['total'], results
    except shodan.APIError as e:
        print('Error: %s' % e)
        return None, None


def query_shodan_all(query):
    """
    It launches the query to Shodan NOT limited by number of pages and return the results.
    :param query: The Shodan query.
    :return: Shodan results.
    """
    matches = []
    try:
        for match in api.search_cursor(query):
            matches.append((match['ip_str'], match['port']))
    except shodan.APIError as e:
        print('Error: %s' % e)
    return matches


def path_leaf(path):
    """
    It extracts the file name from a path.
    :param path: The Path.
    :return: The Leaf.
    """
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)


def active_processes():
    """
    It checks active processes and kill the zombies.
    :return: The number of active processes.
    """
    cnt = 0
    process_name = path_leaf(config[REQUIRED_SECTION]['MPVFilePath'])
    for pid in psutil.pids():
        try:
            p = psutil.Process(pid)
            if p.name() == process_name:
                if p.status() == psutil.STATUS_ZOMBIE:
                    processes[pid]['process'].kill()
                    del processes[pid]
                else:
                    cnt += 1
        except:
            pass
    return cnt


def get_geo_info(match_ip):
    """
    It checks geographical information about a given IP.
    :return: Country, region and city
    """
    try:
        r = requests.get(IP_API % match_ip, timeout=GEO_TIMEOUT)
        j = r.json()
    except:
        try:
            j = {}
            if config.has_option(OPTIONAL_SECTION, 'IPGEOAPIKey'):
                r = requests.get(IP_GEO % (config[OPTIONAL_SECTION]['IPGEOAPIKey'], match_ip), timeout=GEO_TIMEOUT)
                j = r.json()
        except:
            j = {}
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
    return country, region, city

def get_current_windows():
    """
    List the current windows on the system.
    :return: List of titles of the windows running on the system.
    """
    current_windows = []
    result = subprocess.run(['wmctrl', '-l'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    windows = result.strip().split('\n')
    for window in windows:
        parts = window.split()
        current_windows.append(" ".join(parts[3:]).replace('"', ''))
    return current_windows


def check_working():
    """
    It checks if the RTSP stream is working by checking if the window of MPV is on the screen.
    It also kills processes that are not working after a timeout.
    :return: Number of RTSP streams working.
    """
    if sys.platform != 'linux':
        return 0
    current_windows = get_current_windows()
    now = time.time()
    cnt_working = 0
    for pid in list(processes):
        if processes[pid]['title'] in current_windows:
            if not processes[pid]['working']:
                debug(f'{processes[pid]['title']} is working :)')
            processes[pid]['working'] = True
            cnt_working += 1
        elif (now - processes[pid]['launch_time']) >= DEFAULT_TIMEOUT:
            debug(f'Killing {processes[pid]['title']} as it is not working.')
            processes[pid]['process'].kill()
            processes.pop(pid)
    return cnt_working

def check_linux_software():
    """
    It checks of all required software in linux is installed.
    :return: True if everything is installed False otherwise.
    """
    for software in LINUX_SOFTWARE:
        if subprocess.call(['which', software], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) != 0:
            print(f'{software} is not installed.')
            return False
    debug('All required software is present.')
    return True


if __name__ == '__main__':
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
    args = parser.parse_args()
    config = configparser.ConfigParser()
    config.read(args.config)
    if not check_config():
        print('Config: Required parameter is missing.')
        sys.exit(RC_WRONG_CONFIG)
    vulncam_query = args.query + ' ' + args.extend
    vulncam_query = vulncam_query.strip()
    random_pages = args.random_pages
    vulncam_query_pages = args.pages
    total_results = args.total_results
    stream_record = args.stream_record
    max_processes = args.max_processes
    max_windows = args.max_windows
    leave_windows = args.leave_windows
    verbose = args.verbose
    if sys.platform == 'linux':
        if not check_linux_software():
            sys.exit(1)
    processes = {}
    signal.signal(signal.SIGINT, sigint_handler)
    signal_received = False
    api = shodan.Shodan(config[REQUIRED_SECTION]['ShodanAPIKey'])
    info = api.info()
    print('Credits: %d' % info['query_credits'])
    print('Launching query: %s' % vulncam_query)
    if total_results:
        vulncam_matches = query_shodan_all(vulncam_query)
        print('%d results retrieved.' % len(vulncam_matches))
    else:
        total_matches, vulncam_matches = query_shodan_pages(vulncam_query, vulncam_query_pages)
        if total_matches is None:
            print('Error. Exiting...')
            exit()
        print('The query returns %d matches in Shodan.' % total_matches)
        print('Working with %d.' % len(vulncam_matches))
    if len(vulncam_matches) > 0:
        for idx, vulncam_match in enumerate(vulncam_matches):
            while signal_received or (active_processes() >= max_processes):
                check_working()
                debug('Waiting for some process to finish...')
                time.sleep(1)
                if signal_received:
                    sigint_handler(None, None)
            location = get_geo_info(vulncam_match[0])
            title = '[%d] %s:%d (%s-%s-%s)' % tuple(((idx + 1,) + vulncam_match + location))
            print(title)
            if stream_record:
                mkv_file = '%d.mkv' % (idx + 1)
                cmd = (config[REQUIRED_SECTION]['MPVFilePath'], '--title="%s"' % title, '--stream-record=%s' % mkv_file,
                       'rtsp://%s:%d' % vulncam_match, '--mute=yes', '--gpu-context=x11egl')
            else:
                cmd = (config[REQUIRED_SECTION]['MPVFilePath'], '--title="%s"' % title, 'rtsp://%s:%d' % vulncam_match,
                       '--mute=yes', '--gpu-context=x11egl')
            mpv_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            processes[mpv_process.pid] = {'process': mpv_process, 'title': title, 'launch_time': time.time(),
                                          'working': False}
            time.sleep(0.2)
            while check_working() >= max_windows:
                debug('Max windows limit reached. Not launching more connections until a window is closed...')
                time.sleep(1)
        if leave_windows:
            while active_processes() > check_working():
                time.sleep(1)
        else:
            while active_processes() > 0:
                check_working()
                time.sleep(1)

