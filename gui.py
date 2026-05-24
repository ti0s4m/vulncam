#!/usr/bin/env python3
import sys
import configparser
import logging
from argparse import Namespace

import shodan
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QPushButton, QSpinBox, QCheckBox,
    QPlainTextEdit, QFileDialog, QMessageBox, QSizePolicy,
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor

from vulncam import (
    VulnCam, check_config, check_linux_software,
    REQUIRED_SECTION, OPTIONAL_SECTION,
    DEFAULT_CONFIG_FILE, DEFAULT_QUERY, DEFAULT_MAX_PROCS, DEFAULT_PAGES,
)

_vulncam_logger = logging.getLogger('vulncam')


class GUIVulnCam(VulnCam):
    """VulnCam variant for GUI: no signal handler setup, no sys.exit on stop."""

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

    def _sigint_handler(self, _signum, _frame):
        self.signal_received = True
        for pid in list(self.processes):
            if not self.leave_windows or not self.processes[pid]['working']:
                self.processes[pid]['process'].kill()
                self.processes.pop(pid, None)


class _QtLogHandler(logging.Handler):
    def __init__(self, signal):
        super().__init__()
        self.signal = signal

    def emit(self, record):
        self.signal.emit(self.format(record))


class VulnCamWorker(QThread):
    log_message = pyqtSignal(str)
    finished    = pyqtSignal()
    error       = pyqtSignal(str)

    def __init__(self, config, args):
        super().__init__()
        self.config  = config
        self.args    = args
        self.vulncam = None
        self._handler = None

    def run(self):
        self._handler = _QtLogHandler(self.log_message)
        self._handler.setFormatter(logging.Formatter('%(message)s'))
        _vulncam_logger.addHandler(self._handler)
        _vulncam_logger.setLevel(logging.DEBUG if self.args.verbose else logging.INFO)
        try:
            self.vulncam = GUIVulnCam(self.config, self.args)
            query = (self.args.query + ' ' + self.args.extend).strip()
            self.vulncam.run(
                query=query,
                total_results=self.args.total_results,
                pages=self.args.pages,
            )
        except Exception as e:
            self.error.emit(str(e))
        finally:
            _vulncam_logger.removeHandler(self._handler)
            self.finished.emit()

    def stop(self):
        if self.vulncam:
            self.vulncam._sigint_handler(None, None)


class VulnCamWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self._setup_ui()
        self._load_config(DEFAULT_CONFIG_FILE)

    def _setup_ui(self):
        self.setWindowTitle('VulnCam')
        self.setMinimumWidth(640)
        self.resize(720, 640)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)

        # ── Config ────────────────────────────────────────────────────────────
        cfg_group = QGroupBox('Configuración')
        cfg_layout = QVBoxLayout(cfg_group)

        cfg_file_row = QHBoxLayout()
        cfg_file_row.addWidget(QLabel('Archivo config:'))
        self.config_path = QLineEdit(DEFAULT_CONFIG_FILE)
        cfg_file_row.addWidget(self.config_path)
        load_btn = QPushButton('Cargar')
        load_btn.clicked.connect(self._browse_config)
        cfg_file_row.addWidget(load_btn)
        cfg_layout.addLayout(cfg_file_row)

        shodan_row = QHBoxLayout()
        shodan_row.addWidget(QLabel('Shodan API Key:'))
        self.shodan_key = QLineEdit()
        self.shodan_key.setEchoMode(QLineEdit.EchoMode.Password)
        shodan_row.addWidget(self.shodan_key)
        cfg_layout.addLayout(shodan_row)

        mpv_row = QHBoxLayout()
        mpv_row.addWidget(QLabel('MPV Path:'))
        self.mpv_path = QLineEdit()
        mpv_row.addWidget(self.mpv_path)
        mpv_browse = QPushButton('Buscar...')
        mpv_browse.clicked.connect(self._browse_mpv)
        mpv_row.addWidget(mpv_browse)
        cfg_layout.addLayout(mpv_row)

        ipgeo_row = QHBoxLayout()
        ipgeo_row.addWidget(QLabel('IPGeo API Key (opcional):'))
        self.ipgeo_key = QLineEdit()
        self.ipgeo_key.setEchoMode(QLineEdit.EchoMode.Password)
        ipgeo_row.addWidget(self.ipgeo_key)
        cfg_layout.addLayout(ipgeo_row)

        root.addWidget(cfg_group)

        # ── Search ────────────────────────────────────────────────────────────
        search_group = QGroupBox('Búsqueda')
        search_layout = QVBoxLayout(search_group)

        q_row = QHBoxLayout()
        q_row.addWidget(QLabel('Query:'))
        self.query_field = QLineEdit(DEFAULT_QUERY)
        q_row.addWidget(self.query_field)
        search_layout.addLayout(q_row)

        ext_row = QHBoxLayout()
        ext_row.addWidget(QLabel('Extender:'))
        self.extend_field = QLineEdit()
        ext_row.addWidget(self.extend_field)
        search_layout.addLayout(ext_row)

        num_row = QHBoxLayout()
        num_row.addWidget(QLabel('Páginas:'))
        self.pages_spin = QSpinBox()
        self.pages_spin.setRange(1, 100)
        self.pages_spin.setValue(DEFAULT_PAGES)
        num_row.addWidget(self.pages_spin)
        num_row.addSpacing(16)
        num_row.addWidget(QLabel('Max procesos:'))
        self.max_proc_spin = QSpinBox()
        self.max_proc_spin.setRange(1, 50)
        self.max_proc_spin.setValue(DEFAULT_MAX_PROCS)
        num_row.addWidget(self.max_proc_spin)
        num_row.addSpacing(16)
        num_row.addWidget(QLabel('Max ventanas:'))
        self.max_win_spin = QSpinBox()
        self.max_win_spin.setRange(1, 50)
        self.max_win_spin.setValue(DEFAULT_MAX_PROCS)
        num_row.addWidget(self.max_win_spin)
        num_row.addStretch()
        search_layout.addLayout(num_row)

        check_row = QHBoxLayout()
        self.random_check  = QCheckBox('Páginas aleatorias')
        self.record_check  = QCheckBox('Grabar streams')
        self.leave_check   = QCheckBox('Dejar ventanas al terminar')
        self.allres_check  = QCheckBox('Todos los resultados')
        self.verbose_check = QCheckBox('Verbose')
        for w in (self.random_check, self.record_check, self.leave_check,
                  self.allres_check, self.verbose_check):
            check_row.addWidget(w)
        check_row.addStretch()
        self.allres_check.toggled.connect(lambda on: self.pages_spin.setEnabled(not on))
        search_layout.addLayout(check_row)

        root.addWidget(search_group)

        # ── Buttons ───────────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton('START')
        self.start_btn.setFixedHeight(36)
        self.stop_btn = QPushButton('STOP')
        self.stop_btn.setFixedHeight(36)
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._start)
        self.stop_btn.clicked.connect(self._stop)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        root.addLayout(btn_row)

        # ── Log ───────────────────────────────────────────────────────────────
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont('Monospace', 9))
        self.log_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        root.addWidget(self.log_view)

    # ── Config helpers ────────────────────────────────────────────────────────

    def _browse_config(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Seleccionar config', '', 'INI files (*.ini)')
        if path:
            self.config_path.setText(path)
            self._load_config(path)

    def _browse_mpv(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Seleccionar MPV', '')
        if path:
            self.mpv_path.setText(path)

    def _load_config(self, path):
        config = configparser.ConfigParser()
        config.read(path)
        if config.has_option(REQUIRED_SECTION, 'shodanapikey'):
            self.shodan_key.setText(config[REQUIRED_SECTION]['shodanapikey'])
        if config.has_option(REQUIRED_SECTION, 'mpvfilepath'):
            self.mpv_path.setText(config[REQUIRED_SECTION]['mpvfilepath'])
        if config.has_option(OPTIONAL_SECTION, 'ipgeoapikey'):
            self.ipgeo_key.setText(config[OPTIONAL_SECTION]['ipgeoapikey'])

    def _build_config(self):
        config = configparser.ConfigParser()
        config[REQUIRED_SECTION] = {
            'shodanapikey': self.shodan_key.text().strip(),
            'mpvfilepath':  self.mpv_path.text().strip(),
        }
        ipgeo = self.ipgeo_key.text().strip()
        if ipgeo:
            config[OPTIONAL_SECTION] = {'ipgeoapikey': ipgeo}
        return config

    # ── Run control ───────────────────────────────────────────────────────────

    def _start(self):
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, 'Error de configuración',
                                 'Faltan parámetros requeridos (Shodan API Key y MPV Path).')
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, 'Software no encontrado',
                                 'mpv o wmctrl no están instalados.')
            return

        cfg_path = self.config_path.text().strip() or DEFAULT_CONFIG_FILE
        with open(cfg_path, 'w') as f:
            config.write(f)

        args = Namespace(
            query         = self.query_field.text().strip() or DEFAULT_QUERY,
            extend        = self.extend_field.text().strip(),
            pages         = self.pages_spin.value(),
            max_processes = self.max_proc_spin.value(),
            max_windows   = self.max_win_spin.value(),
            random_pages  = self.random_check.isChecked(),
            stream_record = self.record_check.isChecked(),
            leave_windows = self.leave_check.isChecked(),
            total_results = self.allres_check.isChecked(),
            verbose       = self.verbose_check.isChecked(),
        )

        self.log_view.clear()
        self.worker = VulnCamWorker(config, args)
        self.worker.log_message.connect(self._append_log)
        self.worker.error.connect(lambda e: self._append_log(f'Error: {e}'))
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def _stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self._append_log('Deteniendo...')

    def _on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._append_log('── Finalizado ──')

    def _append_log(self, msg):
        self.log_view.appendPlainText(msg)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)


def main():
    app = QApplication(sys.argv)
    window = VulnCamWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
