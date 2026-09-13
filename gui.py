#!/usr/bin/env python3
import sys

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
    import os
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
