# vulncam
## Script that searches for exposed cams using [Shodan](https://www.shodan.io) and directly connects to them using [MPV](https://mpv.io).
### In the config file you need to specify the Shodan API Key and the MPV path at least.
#### Quick Help:
```bazaar
usage: vulncam.py [-h] [-c CONFIG] [-q QUERY] [-x EXTEND] [-r] [-p PAGES] [-t] [-s] [-m MAX_PROCESSES] [-v]

RTSP Stream manager using Shodan.

options:
  -h, --help                                        show this help message and exit
  -c CONFIG, --config CONFIG                        Config file (default: config.ini)
  -q QUERY, --query QUERY                           Query to be launched in Shodan (default: RTSP has_screenshot:yes)
  -x EXTEND, --extend EXTEND                        Extend the default query with additional parameters (default: )
  -r, --random-pages                                Choose pages randomly instead of sequentially (default: False)
  -p PAGES, --pages PAGES                           Number of pages that will be retrieved from Shodan (default: 1)
  -t, --total-results                               All results are requested from Shodan (default: False)
  -s, --stream-record                               Records the streams in mkv files (default: False)
  -m MAX_PROCESSES, --max-processes MAX_PROCESSES   Max parallel processes (default: 10)
  -v, --verbose                                     Verbose outputs (default: False)

```
#### Config file:
````chef
[REQUIRED]
ShodanAPIKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXX
MPVFilePath = XXXX/XXXX/XXX
[OPTIONAL]
IPGEOAPIKey = XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
````
