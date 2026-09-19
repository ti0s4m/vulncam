#!/usr/bin/env python3
import os
import sys


def _force_xcb_under_wayland():
    """mpv's live-embed feature (--wid=<winId()>) requires a genuine X11 window
    id to reparent into. Under a native Wayland Qt platform plugin, winId()
    returns an opaque handle mpv can't embed, so it silently opens its own
    top-level window instead — with several streams that means the screen
    fills up with overlapping mpv windows and the main window becomes
    unreachable. Forcing Qt onto xcb (via XWayland, when available) keeps
    embedding working the same way it does under plain X11. Must run before
    PyQt6 is imported, since the platform plugin is selected at that point."""
    if sys.platform != 'linux':
        return
    current = os.environ.get('QT_QPA_PLATFORM', '')
    # Desktop environments commonly preset this to a fallback list such as
    # 'wayland;xcb', which still resolves to the (embed-breaking) wayland
    # plugin since it's tried first — only leave truly non-wayland choices
    # (e.g. a user explicitly forcing 'xcb' or 'offscreen' for testing) alone.
    if current and 'wayland' not in current:
        return
    if os.environ.get('WAYLAND_DISPLAY') and os.environ.get('DISPLAY'):
        os.environ['QT_QPA_PLATFORM'] = 'xcb'


_force_xcb_under_wayland()

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon, QPixmap

from gui_resources import APP_ICON_B64
from gui_main_window import VulnCamWindow


def _qt_message_handler(mode, context, message):
    """Forward Qt warnings/errors to stderr so they appear in the terminal."""
    levels = {0: 'Qt[Debug]', 1: 'Qt[Warning]', 2: 'Qt[Critical]',
              3: 'Qt[Fatal]', 4: 'Qt[Info]'}
    print(f'{levels.get(mode, "Qt[?]")}: {message}', file=sys.stderr)


def main():
    import base64
    import tempfile
    from PyQt6.QtCore import qInstallMessageHandler
    import traceback

    crash_log = os.path.join(tempfile.gettempdir(), 'vulncam_crash.log')

    def _excepthook(exc_type, exc_value, exc_tb):
        msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        print(msg, file=sys.stderr)
        try:
            with open(crash_log, 'a') as f:
                f.write(msg + '\n')
        except Exception:
            pass

    sys.excepthook = _excepthook
    qInstallMessageHandler(_qt_message_handler)

    app = QApplication(sys.argv)
    app.setApplicationName('VulnCam')
    app.setDesktopFileName('vulncam')
    pixmap = QPixmap()
    pixmap.loadFromData(base64.b64decode(APP_ICON_B64))
    icon = QIcon(pixmap)
    app.setWindowIcon(icon)
    window = VulnCamWindow()
    window.setWindowIcon(icon)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
