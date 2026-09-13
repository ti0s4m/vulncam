"""VulnCam main window: configuration, search, streams list/mosaic, and MPV auto-detect."""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import configparser
from argparse import Namespace
from datetime import datetime

import psutil
import shodan
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QPushButton, QSpinBox, QCheckBox,
    QPlainTextEdit, QFileDialog, QMessageBox, QSizePolicy, QComboBox,
    QSplitter, QListWidget, QListWidgetItem,
    QRadioButton, QButtonGroup, QFrame, QMenu, QDialog, QDialogButtonBox,
)
from PyQt6.QtCore import (QThreadPool, Qt, QTimer, QEvent, QUrl, pyqtSlot)
from PyQt6.QtGui import QFont, QTextCursor, QPixmap, QDesktopServices

from vulncam import (
    check_config, check_linux_software, list_window_titles,
    REQUIRED_SECTION, OPTIONAL_SECTION,
    DEFAULT_CONFIG_FILE, DEFAULT_QUERY, DEFAULT_MAX_PROCS, DEFAULT_PAGES,
    DEFAULT_TIMEOUT,
)
from gui_i18n import TRANSLATIONS
from gui_constants import (
    COLOR_IDLE, COLOR_LAUNCHING, COLOR_WORKING, COLOR_FAILED, COLOR_SAVED,
    THUMB_SIZES, MAX_THUMB_RETRIES, RECORDINGS_DIR, DEFAULT_MAX_LIVE_EMBEDS,
)
from gui_mosaic import MosaicGrid
from gui_thumbnails import ThumbnailManager, AudioProbeTask, AuthProbeTask, build_rtsp_url
from gui_worker import VulnCamWorker


QUERY_PRESETS = [
    ('RTSP + screenshot',  'RTSP has_screenshot:yes'),
    ('Port 554 + screenshot',  'port:554 has_screenshot:yes'),
    ('Port 554 (RTSP)',    'port:554 RTSP')
]

_COUNTRY_CODES = [('', '—')] + sorted([
    ('AR', 'Argentina'), ('AU', 'Australia'), ('BR', 'Brazil'),
    ('CA', 'Canada'), ('CL', 'Chile'), ('CN', 'China'),
    ('CO', 'Colombia'), ('EG', 'Egypt'), ('ES', 'Spain'),
    ('FR', 'France'), ('DE', 'Germany'), ('GB', 'United Kingdom'),
    ('HK', 'Hong Kong'), ('IN', 'India'), ('ID', 'Indonesia'),
    ('IR', 'Iran'), ('IT', 'Italy'), ('JP', 'Japan'),
    ('KR', 'South Korea'), ('MY', 'Malaysia'), ('MX', 'Mexico'),
    ('NL', 'Netherlands'), ('PH', 'Philippines'), ('PL', 'Poland'),
    ('PT', 'Portugal'), ('RU', 'Russia'), ('SA', 'Saudi Arabia'),
    ('SG', 'Singapore'), ('ZA', 'South Africa'), ('TW', 'Taiwan'),
    ('TH', 'Thailand'), ('TR', 'Turkey'), ('UA', 'Ukraine'),
    ('US', 'United States'), ('VN', 'Vietnam'),
], key=lambda x: x[1])


def _detect_mpv():
    """Try to locate the MPV executable automatically. Returns path or None."""
    found = shutil.which('mpv')
    if found:
        return found
    if sys.platform == 'win32':
        candidates = [
            os.path.join(os.environ.get('PROGRAMFILES', r'C:\Program Files'), 'mpv', 'mpv.exe'),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', r'C:\Program Files (x86)'), 'mpv', 'mpv.exe'),
            os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Programs', 'mpv', 'mpv.exe'),
            os.path.expanduser(r'~\scoop\apps\mpv\current\mpv.exe'),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
    return None




class VulnCamWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._lang = 'en'
        self.worker = None
        self._shodan_info = None   # cached result of api.info(); refreshed on key change
        self._stream_items = {}    # (ip, port) → QListWidgetItem
        self._mosaic_cells = {}    # (ip, port) → MosaicCell
        self._audio_probes  = {}   # (ip, port) → AudioProbeTask.Signals
        self._auth_probes   = {}   # (ip, port) → AuthProbeTask.Signals
        self._worker_refs   = []   # keep-alive: holds Python refs to workers until finished
        self._live_mpv_pids = set()
        self._live_mpv_timer = QTimer(self)
        self._live_mpv_timer.setInterval(1000)
        self._live_mpv_timer.timeout.connect(self._poll_live_mpv)
        self._search_start_time = 0.0
        self._running_source = None   # 'shodan' | 'connect_all' | 'connect_selected'
        self._last_stats = (0, 0)
        self._reconnect_pids = set()
        self._stream_sessions = {}   # (ip, port) → {'pid', 'headless', 'record_path'}
        self._credentials = {}       # (ip, port) → (username, password); memory-only
        self._pending_credential_keys = set()   # awaiting confirmation from a connect attempt
        self._rtsp_info = {}         # (ip, port) → last raw RTSP DESCRIBE response
        self._temp_dir = tempfile.mkdtemp(prefix='vulncam_thumbs_')
        self._thumb_manager = ThumbnailManager(
            self._temp_dir, lambda: self.max_proc_spin.value(), self)
        self._thumb_manager.thumbnail_ready.connect(self._on_thumbnail_ready)
        self._setup_ui()
        self.config_combo.currentTextChanged.connect(self._on_config_selected)
        self._populate_ini_combo()

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(5000)
        for w in list(self._worker_refs):
            if w.isRunning():
                w.stop()
                w.wait(3000)
        self._worker_refs.clear()
        # Headless recordings and embedded live views have no independent window to
        # survive the app closing — the embedded case lives inside a widget that's
        # about to be destroyed — so leaving them running would orphan them
        # invisibly; a live-window session is left alone, same as any other mpv
        # window the user opened by double-click.
        for key, session in list(self._stream_sessions.items()):
            if session['headless'] or session.get('embedded'):
                try:
                    psutil.Process(session['pid']).kill()
                except Exception:
                    pass
                self._stream_sessions.pop(key, None)
        self._live_mpv_timer.stop()
        self._live_mpv_pids.clear()
        self._thumb_manager.stop()
        QThreadPool.globalInstance().waitForDone(4000)
        self._audio_probes.clear()
        self._auth_probes.clear()
        shutil.rmtree(self._temp_dir, ignore_errors=True)
        super().closeEvent(event)

    def _t(self, key):
        return TRANSLATIONS[self._lang][key]

    # ── UI construction ───────────────────────────────────────────────────────

    def _setup_ui(self):
        self.setMinimumWidth(900)
        QTimer.singleShot(0, self._fit_initial_size)
        QTimer.singleShot(0, self._autofill_mpv_if_empty)
        QTimer.singleShot(0, lambda: self._on_view_mode_changed(None, True))

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setSpacing(8)


        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left panel ────────────────────────────────────────────────────────
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 4, 0)
        ll.setSpacing(8)

        self._cfg_group = QGroupBox()
        cfg_layout = QVBoxLayout(self._cfg_group)

        cfg_toggle_row = QHBoxLayout()
        self._cfg_toggle_btn = QPushButton()
        self._cfg_toggle_btn.setCheckable(True)
        self._cfg_toggle_btn.setFlat(True)
        self._cfg_toggle_btn.setStyleSheet('font-weight: 600; text-align: left;')
        self._cfg_toggle_btn.toggled.connect(self._on_cfg_toggle)
        cfg_toggle_row.addWidget(self._cfg_toggle_btn)
        cfg_toggle_row.addStretch()
        cfg_layout.addLayout(cfg_toggle_row)

        self._cfg_body = QWidget()
        self._cfg_body.setVisible(False)   # collapsed by default — set once, rarely touched
        cfg_layout.addWidget(self._cfg_body)
        cfg_layout = QVBoxLayout(self._cfg_body)
        cfg_layout.setContentsMargins(0, 0, 0, 0)

        lang_row = QHBoxLayout()
        self._lang_label = QLabel()
        lang_row.addWidget(self._lang_label)
        self._lang_combo = QComboBox()
        self._lang_combo.addItem('English', 'en')
        self._lang_combo.addItem('Español', 'es')
        self._lang_combo.currentIndexChanged.connect(self._on_lang_changed)
        lang_row.addWidget(self._lang_combo)
        lang_row.addStretch()
        cfg_layout.addLayout(lang_row)

        cfg_file_row = QHBoxLayout()
        self._label_config_file = QLabel()
        cfg_file_row.addWidget(self._label_config_file)
        self.config_combo = QComboBox()
        self.config_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        cfg_file_row.addWidget(self.config_combo)
        self._browse_cfg_btn = QPushButton()
        self._browse_cfg_btn.clicked.connect(self._browse_config)
        cfg_file_row.addWidget(self._browse_cfg_btn)
        self._save_cfg_btn = QPushButton()
        self._save_cfg_btn.clicked.connect(self._save_config)
        cfg_file_row.addWidget(self._save_cfg_btn)
        cfg_layout.addLayout(cfg_file_row)

        shodan_row = QHBoxLayout()
        self._label_shodan = QLabel()
        shodan_row.addWidget(self._label_shodan)
        self.shodan_key = QLineEdit()
        self.shodan_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.shodan_key.editingFinished.connect(self._refresh_shodan_info)
        shodan_row.addWidget(self.shodan_key)
        self._shodan_info_btn = QPushButton()
        self._shodan_info_btn.clicked.connect(self._on_shodan_info_clicked)
        shodan_row.addWidget(self._shodan_info_btn)
        cfg_layout.addLayout(shodan_row)

        mpv_row = QHBoxLayout()
        self._label_mpv = QLabel()
        mpv_row.addWidget(self._label_mpv)
        self.mpv_path = QLineEdit()
        self.mpv_path.editingFinished.connect(self._check_mpv_path_field)
        mpv_row.addWidget(self.mpv_path)
        self._browse_mpv_btn = QPushButton()
        self._browse_mpv_btn.clicked.connect(self._browse_mpv)
        mpv_row.addWidget(self._browse_mpv_btn)
        self._detect_mpv_btn = QPushButton()
        self._detect_mpv_btn.clicked.connect(self._on_detect_mpv)
        mpv_row.addWidget(self._detect_mpv_btn)
        cfg_layout.addLayout(mpv_row)

        ipgeo_row = QHBoxLayout()
        self._label_ipgeo = QLabel()
        ipgeo_row.addWidget(self._label_ipgeo)
        self.ipgeo_key = QLineEdit()
        self.ipgeo_key.setEchoMode(QLineEdit.EchoMode.Password)
        ipgeo_row.addWidget(self.ipgeo_key)
        cfg_layout.addLayout(ipgeo_row)

        ll.addWidget(self._cfg_group)

        # ── Playback group (common to Shodan search and stream list) ─────────
        self._playback_group = QGroupBox()
        pb_layout = QVBoxLayout(self._playback_group)

        pb_num_row = QHBoxLayout()
        self._label_max_proc = QLabel()
        pb_num_row.addWidget(self._label_max_proc)
        self.max_proc_spin = QSpinBox()
        self.max_proc_spin.setRange(1, 50)
        self.max_proc_spin.setValue(DEFAULT_MAX_PROCS)
        pb_num_row.addWidget(self.max_proc_spin)
        pb_num_row.addSpacing(16)
        self._label_thumb_timeout = QLabel()
        pb_num_row.addWidget(self._label_thumb_timeout)
        self._thumb_timeout_spin = QSpinBox()
        self._thumb_timeout_spin.setRange(5, 60)
        self._thumb_timeout_spin.setValue(DEFAULT_TIMEOUT)
        pb_num_row.addWidget(self._thumb_timeout_spin)
        pb_num_row.addSpacing(16)
        self._label_max_live = QLabel()
        pb_num_row.addWidget(self._label_max_live)
        self.max_live_spin = QSpinBox()
        self.max_live_spin.setRange(1, 20)
        self.max_live_spin.setValue(DEFAULT_MAX_LIVE_EMBEDS)
        pb_num_row.addWidget(self.max_live_spin)
        pb_num_row.addStretch()
        self._stats_label = QLabel()
        pb_num_row.addWidget(self._stats_label)
        pb_layout.addLayout(pb_num_row)
        self.max_proc_spin.valueChanged.connect(lambda _: self._refresh_stats_label())


        # ── Shodan search group ───────────────────────────────────────────────
        self._search_group = QGroupBox()
        search_layout = QVBoxLayout(self._search_group)

        # Query row: label + presets combo + free-text field
        q_row = QHBoxLayout()
        self._label_query = QLabel()
        q_row.addWidget(self._label_query)
        self._preset_combo = QComboBox()
        self._preset_combo.addItem('', None)          # placeholder at index 0
        for name, qstr in QUERY_PRESETS:
            self._preset_combo.addItem(name, qstr)
        self._preset_combo.setFixedWidth(160)
        self._preset_combo.currentIndexChanged.connect(self._on_preset_selected)
        q_row.addWidget(self._preset_combo)
        self.query_field = QLineEdit(DEFAULT_QUERY)
        q_row.addWidget(self.query_field)
        search_layout.addLayout(q_row)

        # Filter builder toggle
        fb_toggle_row = QHBoxLayout()
        self._fb_toggle_btn = QPushButton()
        self._fb_toggle_btn.setCheckable(True)
        self._fb_toggle_btn.setFlat(True)
        self._fb_toggle_btn.toggled.connect(self._on_filter_toggle)
        fb_toggle_row.addWidget(self._fb_toggle_btn)
        fb_toggle_row.addStretch()
        search_layout.addLayout(fb_toggle_row)

        # Location filter panel (hidden by default)
        self._fb_widget = QWidget()
        self._fb_widget.setVisible(False)
        fb_layout = QHBoxLayout(self._fb_widget)
        fb_layout.setContentsMargins(0, 0, 0, 0)

        self._label_country = QLabel()
        fb_layout.addWidget(self._label_country)
        self._country_combo = QComboBox()
        for code, name in _COUNTRY_CODES:
            self._country_combo.addItem(name, code)
        self._country_combo.setFixedWidth(150)
        fb_layout.addWidget(self._country_combo)
        fb_layout.addSpacing(12)
        self._label_city = QLabel()
        fb_layout.addWidget(self._label_city)
        self._city_field = QLineEdit()
        fb_layout.addWidget(self._city_field)
        fb_layout.addSpacing(8)
        self._clear_filters_btn = QPushButton()
        self._clear_filters_btn.clicked.connect(self._clear_filters)
        fb_layout.addWidget(self._clear_filters_btn)

        search_layout.addWidget(self._fb_widget)

        # Connect filter fields → auto-update extend
        self._country_combo.currentIndexChanged.connect(self._build_extend_from_filters)
        self._city_field.textChanged.connect(self._build_extend_from_filters)

        ext_row = QHBoxLayout()
        self._label_extend = QLabel()
        ext_row.addWidget(self._label_extend)
        self.extend_field = QLineEdit()
        ext_row.addWidget(self.extend_field)
        search_layout.addLayout(ext_row)

        shodan_opt_row = QHBoxLayout()
        self._label_pages = QLabel()
        shodan_opt_row.addWidget(self._label_pages)
        self.pages_spin = QSpinBox()
        self.pages_spin.setRange(1, 100)
        self.pages_spin.setValue(DEFAULT_PAGES)
        shodan_opt_row.addWidget(self.pages_spin)
        shodan_opt_row.addSpacing(16)
        self.random_check  = QCheckBox()
        self.allres_check  = QCheckBox()
        self._dedup_check  = QCheckBox()
        self._dedup_check.setChecked(True)
        for w in (self.random_check, self.allres_check, self._dedup_check):
            shodan_opt_row.addWidget(w)
        shodan_opt_row.addStretch()
        self._credits_btn = QPushButton()
        self._credits_btn.clicked.connect(self._check_credits)
        shodan_opt_row.addWidget(self._credits_btn)
        self.allres_check.toggled.connect(lambda on: self.pages_spin.setEnabled(not on))
        search_layout.addLayout(shodan_opt_row)

        ll.addWidget(self._search_group)
        ll.addWidget(self._playback_group)

        btn_row = QHBoxLayout()
        self._restore_btn = QPushButton()
        self._restore_btn.clicked.connect(self._restore_defaults)
        btn_row.addWidget(self._restore_btn)
        btn_row.addStretch()
        self.start_btn = QPushButton()
        self.start_btn.setFixedHeight(36)
        self.stop_btn = QPushButton()
        self.stop_btn.setFixedHeight(36)
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self._start)
        self.stop_btn.clicked.connect(self._stop)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        ll.addLayout(btn_row)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont('Monospace', 9))
        self.log_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        ll.addWidget(self.log_view)

        # ── Right panel ───────────────────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(4, 0, 0, 0)

        self._streams_group = QWidget()
        sg_layout = QVBoxLayout(self._streams_group)
        sg_layout.setContentsMargins(0, 0, 0, 0)

        self._streams_title = QLabel()
        self._streams_title.setStyleSheet(
            'font-weight: 600; font-size: 13px; padding-bottom: 4px;'
            ' border-bottom: 1px solid palette(mid);')
        sg_layout.addWidget(self._streams_title)

        # View mode toggle (list / mosaic)
        view_row = QHBoxLayout()
        self._view_btn_group = QButtonGroup(self)
        self._mosaic_radio = QRadioButton()
        self._list_radio = QRadioButton()
        self._mosaic_radio.setChecked(True)
        self._view_btn_group.addButton(self._mosaic_radio)
        self._view_btn_group.addButton(self._list_radio)
        view_row.addWidget(self._mosaic_radio)
        view_row.addWidget(self._list_radio)
        self._thumb_size_combo = QComboBox()
        for key, w, h in THUMB_SIZES:
            self._thumb_size_combo.addItem('', (w, h))
        self._thumb_size_combo.setCurrentIndex(1)  # medium
        self._thumb_size_combo.setVisible(False)
        self._thumb_size_combo.currentIndexChanged.connect(self._on_thumb_size_changed)
        view_row.addWidget(self._thumb_size_combo)
        view_row.addSpacing(12)
        self._label_filter = QLabel()
        view_row.addWidget(self._label_filter)
        self._filter_combo = QComboBox()
        self._filter_combo.addItem('', 'all')
        self._filter_combo.addItem('', 'working')
        self._filter_combo.addItem('', 'working_av')
        self._filter_combo.addItem('', 'recording')
        self._filter_combo.addItem('', 'failed')
        self._filter_combo.addItem('', 'auth')
        self._filter_combo.addItem('', 'launching')
        self._filter_combo.setCurrentIndex(1)
        self._filter_combo.currentIndexChanged.connect(self._apply_filter)
        view_row.addWidget(self._filter_combo)
        view_row.addStretch()
        self._count_label = QLabel()
        view_row.addWidget(self._count_label)
        sg_layout.addLayout(view_row)
        self._view_btn_group.buttonToggled.connect(self._on_view_mode_changed)

        # Single action bar: connect/scan (primary) | separator | manage streams | discard option
        actions_row = QHBoxLayout()
        self._connect_btn = QPushButton()
        self._connect_btn.clicked.connect(self._on_connect_btn_clicked)
        self._connect_selected_btn = QPushButton()
        self._connect_selected_btn.clicked.connect(self._on_connect_selected_clicked)
        self._scan_btn = QPushButton()
        self._scan_btn.clicked.connect(self._on_scan_btn_clicked)
        self._scan_selected_btn = QPushButton()
        self._scan_selected_btn.clicked.connect(self._on_scan_selected_btn_clicked)
        for w in (self._connect_btn, self._connect_selected_btn,
                  self._scan_btn, self._scan_selected_btn):
            actions_row.addWidget(w)

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.VLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        actions_row.addWidget(sep1)

        self._clear_btn = QPushButton()
        self._clear_btn.clicked.connect(self._clear_streams)
        self._clear_failed_btn = QPushButton()
        self._clear_failed_btn.clicked.connect(self._clear_failed_streams)
        self._save_streams_btn = QPushButton()
        self._save_streams_btn.clicked.connect(self._save_streams)
        self._load_streams_btn = QPushButton()
        self._load_streams_btn.clicked.connect(self._load_streams)
        for w in (self._clear_btn, self._clear_failed_btn,
                  self._save_streams_btn, self._load_streams_btn):
            actions_row.addWidget(w)

        actions_row.addStretch()
        self._discard_check = QCheckBox()
        self._discard_check.setChecked(False)
        actions_row.addWidget(self._discard_check)
        sg_layout.addLayout(actions_row)

        self._streams_list = QListWidget()
        self._streams_list.setFont(QFont('Monospace', 8))
        self._streams_list.setWordWrap(True)
        self._streams_list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection)
        self._streams_list.itemDoubleClicked.connect(self._on_stream_double_clicked)
        self._streams_list.installEventFilter(self)
        self._streams_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._streams_list.customContextMenuRequested.connect(self._on_list_context_menu)
        self._streams_list.itemSelectionChanged.connect(self._refresh_connect_buttons)
        sg_layout.addWidget(self._streams_list)

        self._mosaic_grid = MosaicGrid()
        self._mosaic_grid.cell_double_clicked.connect(
            self._on_mosaic_cell_double_clicked)
        self._mosaic_grid.cell_context_menu_requested.connect(
            self._on_mosaic_context_menu)
        self._mosaic_grid.selection_changed.connect(self._refresh_connect_buttons)
        self._mosaic_grid.setVisible(False)
        self._mosaic_grid.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._mosaic_grid.installEventFilter(self)
        sg_layout.addWidget(self._mosaic_grid)

        rl.addWidget(self._streams_group)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([440, 660])
        root.addWidget(splitter)

        self._retranslate()

    def _retranslate(self):
        t = TRANSLATIONS[self._lang]
        self.setWindowTitle(t['window_title'])
        self._lang_label.setText(t['label_language'])
        arrow = '▾' if self._cfg_body.isVisible() else '▸'
        self._cfg_toggle_btn.setText(f'{arrow} {t["group_config"]}')
        self._label_config_file.setText(t['label_config_file'])
        self._browse_cfg_btn.setText(t['btn_browse'])
        self._save_cfg_btn.setText(t['btn_save_cfg'])
        self._label_shodan.setText(t['label_shodan_key'])
        self._shodan_info_btn.setText(t['btn_shodan_info'])
        self._label_mpv.setText(t['label_mpv_path'])
        self._browse_mpv_btn.setText(t['btn_browse'])
        self._detect_mpv_btn.setText(t['btn_detect_mpv'])
        self._label_ipgeo.setText(t['label_ipgeo_key'])
        self._playback_group.setTitle(t['group_playback'])
        self._label_max_proc.setText(t['label_max_proc'])
        self._label_thumb_timeout.setText(t['label_thumb_timeout'])
        self._label_max_live.setText(t['label_max_live'])
        self._dedup_check.setText(t['check_dedup'])
        self._search_group.setTitle(t['group_search'])
        self._label_query.setText(t['label_query'])
        self._preset_combo.setItemText(0, t['lbl_presets'])
        arrow = '▾' if self._fb_widget.isVisible() else '▸'
        self._fb_toggle_btn.setText(f'{arrow} {t["btn_adv_filters"]}')
        self._label_country.setText(t['label_country'])
        self._label_city.setText(t['label_city'])
        self._clear_filters_btn.setText(t['btn_clear_filters'])
        self._label_extend.setText(t['label_extend'])
        self._label_pages.setText(t['label_pages'])
        self.random_check.setText(t['check_random'])
        self.allres_check.setText(t['check_allres'])
        self._credits_btn.setText(t['btn_credits'])
        self._restore_btn.setText(t['btn_restore'])
        self.start_btn.setText(t['btn_start'])
        self.stop_btn.setText(t['btn_stop'])
        self._refresh_stats_label()
        self._streams_title.setText(t['group_streams'])
        self._label_filter.setText(t['label_filter'])
        self._filter_combo.setItemText(0, t['filter_all'])
        self._filter_combo.setItemText(1, t['filter_working'])
        self._filter_combo.setItemText(2, t['filter_working_av'])
        self._filter_combo.setItemText(3, t['filter_recording'])
        self._filter_combo.setItemText(4, t['filter_failed'])
        self._filter_combo.setItemText(5, t['filter_auth'])
        self._filter_combo.setItemText(6, t['filter_launching'])
        self._discard_check.setText(t['check_discard'])
        self._clear_btn.setText(t['btn_clear_streams'])
        self._clear_failed_btn.setText(t['btn_clear_failed'])
        self._save_streams_btn.setText(t['btn_save_streams'])
        self._load_streams_btn.setText(t['btn_load_streams'])
        self._connect_btn.setText(t['btn_connect_all'])
        self._connect_selected_btn.setText(t['btn_connect_selected'])
        self._scan_btn.setText(t['btn_scan'])
        self._scan_selected_btn.setText(t['btn_scan_selected'])
        self._list_radio.setText(t['btn_view_list'])
        self._mosaic_radio.setText(t['btn_view_mosaic'])
        for i, key in enumerate(('thumb_small', 'thumb_medium', 'thumb_large')):
            self._thumb_size_combo.setItemText(i, t[key])
        # Retranslate placeholder text in existing mosaic cells
        for cell in self._mosaic_cells.values():
            cell.retranslate(t['mosaic_connecting'], t['mosaic_no_signal'],
                             t['mosaic_waiting'], t['mosaic_working'])
        self._update_count()

    def _fit_initial_size(self):
        """Resize to fit content using actual font metrics, with a sensible minimum."""
        hint = self.sizeHint()
        self.resize(max(hint.width() + 80, 1100), max(hint.height() + 40, 700))

    def _on_lang_changed(self, _index):
        self._lang = self._lang_combo.currentData()
        self._retranslate()

    def _on_preset_selected(self, idx):
        if idx == 0:
            return
        self.query_field.setText(self._preset_combo.itemData(idx))
        self._preset_combo.blockSignals(True)
        self._preset_combo.setCurrentIndex(0)
        self._preset_combo.blockSignals(False)

    def _on_filter_toggle(self, checked):
        self._fb_widget.setVisible(checked)
        t = TRANSLATIONS[self._lang]
        arrow = '▾' if checked else '▸'
        self._fb_toggle_btn.setText(f'{arrow} {t["btn_adv_filters"]}')

    def _on_cfg_toggle(self, checked):
        self._cfg_body.setVisible(checked)
        t = TRANSLATIONS[self._lang]
        arrow = '▾' if checked else '▸'
        self._cfg_toggle_btn.setText(f'{arrow} {t["group_config"]}')

    def _build_extend_from_filters(self, _=None):
        parts = []
        country = self._country_combo.currentData()
        if country:
            parts.append(f'country:{country}')
        city = self._city_field.text().strip()
        if city:
            parts.append(f'city:"{city}"' if ' ' in city else f'city:{city}')
        self.extend_field.setText(' '.join(parts))

    def _clear_filters(self):
        self._country_combo.setCurrentIndex(0)
        self._city_field.clear()

    # ── Config helpers ────────────────────────────────────────────────────────

    def _populate_ini_combo(self):
        self.config_combo.clear()
        for path in sorted(glob.glob('*.ini')):
            self.config_combo.addItem(path)

    def _on_config_selected(self, path):
        if path:
            self._load_config(path)

    def _browse_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, self._t('dlg_select_config'), '', self._t('ini_filter'))
        if path:
            if self.config_combo.findText(path) == -1:
                self.config_combo.addItem(path)
            self.config_combo.setCurrentText(path)

    def _check_mpv_path_field(self):
        """Validate the MPV path field visually: green=OK, red=not found."""
        path = self.mpv_path.text().strip()
        if not path:
            self.mpv_path.setStyleSheet('')
            return
        valid = bool(os.path.isfile(path) or shutil.which(path))
        if valid:
            self.mpv_path.setStyleSheet('color: #20A050;')
        else:
            # Path not found — try auto-detect
            detected = _detect_mpv()
            if detected:
                self.mpv_path.setText(detected)
                self.mpv_path.setStyleSheet('color: #20A050;')
                self._append_log(self._t('log_mpv_detected').format(detected))
            else:
                self.mpv_path.setStyleSheet('color: #C03030;')

    def _browse_mpv(self):
        path, _ = QFileDialog.getOpenFileName(self, self._t('dlg_select_mpv'), '')
        if path:
            self.mpv_path.setText(path)
            self._check_mpv_path_field()

    def _on_detect_mpv(self):
        """Manual detect button: find MPV and fill the field, inform the user."""
        found = _detect_mpv()
        if found:
            self.mpv_path.setText(found)
            self._append_log(self._t('log_mpv_detected').format(found))
        else:
            self._append_log(self._t('log_mpv_not_found'))
            QMessageBox.warning(self, self._t('dlg_mpv_err_title'),
                                self._t('dlg_mpv_missing'))
        self._check_mpv_path_field()

    def _autofill_mpv_if_empty(self):
        """Silently fill MPV path on startup if the field is empty."""
        if not self.mpv_path.text().strip():
            found = _detect_mpv()
            if found:
                self.mpv_path.setText(found)
                self._append_log(self._t('log_mpv_detected').format(found))
        self._check_mpv_path_field()

    def _load_config(self, path):
        config = configparser.ConfigParser()
        config.read(path)
        if config.has_option(REQUIRED_SECTION, 'shodanapikey'):
            self.shodan_key.setText(config[REQUIRED_SECTION]['shodanapikey'])
            self._refresh_shodan_info()
        if config.has_option(REQUIRED_SECTION, 'mpvfilepath'):
            self.mpv_path.setText(config[REQUIRED_SECTION]['mpvfilepath'])
        if config.has_option(OPTIONAL_SECTION, 'ipgeoapikey'):
            self.ipgeo_key.setText(config[OPTIONAL_SECTION]['ipgeoapikey'])
        self._autofill_mpv_if_empty()   # fills if empty, then validates

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

    def _save_config(self):
        cfg_path = self.config_combo.currentText() or DEFAULT_CONFIG_FILE
        with open(cfg_path, 'w') as f:
            self._build_config().write(f)

    def _restore_defaults(self):
        self.shodan_key.clear()
        self.mpv_path.clear()
        self.mpv_path.setStyleSheet('')
        self.ipgeo_key.clear()
        self.query_field.setText(DEFAULT_QUERY)
        self._preset_combo.setCurrentIndex(0)
        self._clear_filters()
        self.extend_field.clear()
        self.pages_spin.setValue(DEFAULT_PAGES)
        self.max_proc_spin.setValue(DEFAULT_MAX_PROCS)
        self.random_check.setChecked(False)
        self.allres_check.setChecked(False)
        self._dedup_check.setChecked(True)
        self._thumb_timeout_spin.setValue(DEFAULT_TIMEOUT)
        self.max_live_spin.setValue(DEFAULT_MAX_LIVE_EMBEDS)
        self._discard_check.setChecked(False)
        self._filter_combo.setCurrentIndex(1)
        self._autofill_mpv_if_empty()

    def _ensure_mpv_path(self):
        """Returns True if MPV path is set (auto-detecting if empty). Shows error if not found."""
        if self.mpv_path.text().strip():
            return True
        found = _detect_mpv()
        if found:
            self.mpv_path.setText(found)
            self._append_log(self._t('log_mpv_detected').format(found))
            return True
        QMessageBox.critical(self, self._t('dlg_mpv_err_title'),
                             self._t('dlg_mpv_missing'))
        return False

    def _refresh_shodan_info(self):
        """Fetch and cache api.info(). Called on key change and config load."""
        key = self.shodan_key.text().strip()
        if not key:
            self._shodan_info = None
            return
        try:
            self._shodan_info = shodan.Shodan(key).info()
        except Exception:
            self._shodan_info = None

    def _on_shodan_info_clicked(self):
        self._refresh_shodan_info()
        if self._shodan_info is None:
            self._append_log(self._t('log_shodan_info_err').format('no API key or connection error'))
            return
        lines = [self._t('log_shodan_info_hdr')]
        for k, v in self._shodan_info.items():
            lines.append(f'  {k}: {v}')
        self._append_log('\n'.join(lines))

    def _check_credits(self):
        key = self.shodan_key.text().strip()
        if not key:
            QMessageBox.warning(self, self._t('dlg_credits_title'),
                                self._t('dlg_credits_err'))
            return
        try:
            info = shodan.Shodan(key).info()
            QMessageBox.information(
                self, self._t('dlg_credits_title'),
                self._t('dlg_credits_msg').format(
                    info.get('query_credits', '?'),
                    info.get('scan_credits', '?'),
                ),
            )
        except Exception as e:
            QMessageBox.critical(self, self._t('dlg_credits_title'), str(e))

    # ── Stream panel ──────────────────────────────────────────────────────────

    @staticmethod
    def _parse_ip_port(title):
        """Extract (ip, port) from a title like '[N] IP:PORT (geo)'."""
        try:
            ip_port = title.split('] ', 1)[1].split(' ')[0]
            ip, port_str = ip_port.rsplit(':', 1)
            return ip, int(port_str)
        except (IndexError, ValueError):
            return None, None

    def _on_stream_added(self, title):
        ip, port = self._parse_ip_port(title)
        key = (ip, port) if ip else None

        if key and key in self._stream_items:
            item = self._stream_items[key]
            item.setText('⬤ ' + title)
            item.setForeground(COLOR_LAUNCHING)
            item.setData(Qt.ItemDataRole.UserRole, (ip, port, title))
            item.setHidden(False)
        else:
            item = QListWidgetItem('⬤ ' + title)
            item.setForeground(COLOR_LAUNCHING)
            if key:
                item.setData(Qt.ItemDataRole.UserRole, (ip, port, title))
                self._stream_items[key] = item
            self._streams_list.addItem(item)

        # Mosaic: create cell if new stream
        if key and key not in self._mosaic_cells:
            t = TRANSLATIONS[self._lang]
            self._mosaic_grid.add_cell(ip, port, title,
                                       t['mosaic_connecting'], t['mosaic_no_signal'],
                                       t['mosaic_waiting'], t['mosaic_working'])
            self._mosaic_cells[key] = self._mosaic_grid.get_cell(ip, port)
            # Queue thumbnail only if no worker is running (avoid competing MPV processes)
            if self._running_source is None:
                self._queue_thumbnail(ip, port)
        elif key and key in self._mosaic_cells:
            regenerating = self._running_source in ('shodan', 'scan_all', 'scan_selected')
            if regenerating:
                self._mosaic_cells[key].reset(keep_thumbnail=False)
            else:
                # Live connection (connect_all / connect_selected): keep thumbnail
                # and current status — only clear the audio badge so it re-probes
                cell = self._mosaic_cells[key]
                cell.reset_retries()
                cell.set_audio_type(None)

        if key:
            self._refresh_stream_badge(key)
        self._apply_filter()
        if not item.isHidden():
            self._streams_list.scrollToItem(item)

    def _on_stream_status(self, title, status):
        ip, port = self._parse_ip_port(title)
        if ip is None:
            return
        key = (ip, port)
        if key in self._pending_credential_keys:
            self._pending_credential_keys.discard(key)
            if status == 'failed':
                # Credentials just tried didn't work — don't keep them "saved"
                # while silently failing on every future connection attempt.
                self._credentials.pop(key, None)
                self._append_log(self._t('log_credentials_failed').format(title))
            elif status == 'working':
                self._append_log(self._t('log_credentials_saved').format(title))
        item = self._stream_items.get(key)
        if item:
            if status == 'failed' and self._discard_check.isChecked():
                self._remove_stream(key, item)
                self._update_count()
                return
            item.setForeground(COLOR_WORKING if status == 'working' else COLOR_FAILED)
            self._apply_filter()
        cell = self._mosaic_cells.get((ip, port))
        if cell:
            # Status always reflects the latest outcome, even if a thumbnail from an
            # earlier successful probe is still shown (e.g. a live-connect attempt
            # made after the probe can still fail and must flip the cell back to
            # 'failed' — otherwise it stays gate-open for future connect attempts).
            cell.set_status(status)
            if status != 'failed':
                cell.set_auth_failed(False)   # stale AUTH tag until re-confirmed
            if not cell.has_thumbnail():
                if status == 'failed' and self._running_source is None:
                    # Worker reported failure → retry via ThumbnailManager
                    self._retry_or_fail_thumbnail(ip, port, cell)
                elif status == 'working' and self._running_source is None:
                    # Stream confirmed working with no active run (e.g. double-click) →
                    # now safe to capture thumbnail (no competing MPV window process)
                    self._queue_thumbnail(ip, port)
            self._refresh_stream_badge(key)
        if status == 'working':
            self._launch_audio_probe(ip, port)
        elif status == 'failed':
            self._launch_auth_probe(ip, port)
        self._refresh_connect_buttons()

    def _launch_audio_probe(self, ip, port):
        key = (ip, port)
        if key in self._audio_probes:
            return
        task = AudioProbeTask(ip, port)
        task.signals.done.connect(self._on_audio_probe_done)
        self._audio_probes[key] = task.signals   # keep Signals alive until done
        QThreadPool.globalInstance().start(task)

    def _launch_auth_probe(self, ip, port):
        key = (ip, port)
        if key in self._auth_probes:
            return
        task = AuthProbeTask(ip, port)
        task.signals.done.connect(self._on_auth_probe_done)
        self._auth_probes[key] = task.signals   # keep Signals alive until done
        QThreadPool.globalInstance().start(task)

    @pyqtSlot(str, int, bool, str)
    def _on_auth_probe_done(self, ip, port, needs_auth, raw_text):
        key = (ip, port)
        self._auth_probes.pop(key, None)
        self._rtsp_info[key] = raw_text
        cell = self._mosaic_cells.get(key)
        # Skip only if it's since been confirmed working — _retry_or_fail_thumbnail
        # briefly flips a thumbnail-less failure to 'launching' while it retries via
        # ThumbnailManager, and that transient state shouldn't drop this result;
        # _on_stream_status already clears the tag the moment 'working' lands.
        if cell and cell.status() != 'working':
            cell.set_auth_failed(needs_auth)
            self._refresh_stream_badge(key)
            if self._filter_combo.currentData() == 'auth':
                self._apply_filter()

    @pyqtSlot(str, int, str, str)
    def _on_audio_probe_done(self, ip, port, result, raw_text):
        key = (ip, port)
        self._audio_probes.pop(key, None)
        self._rtsp_info[key] = raw_text
        cell = self._mosaic_cells.get(key)
        if cell:
            cell.set_audio_type(result)
        self._refresh_stream_badge(key)
        if key in self._stream_items:
            self._apply_filter()

    def _on_stream_double_clicked(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        ip, port, title = data
        if self._stream_status((ip, port)) != 'working':
            self._append_log(self._t('log_not_verified').format(title))
            return
        self._connect_stream((ip, port), title)

    def _connect_stream(self, key, title, force_record=False):
        """Launch a direct MPV connection to (ip, port) — the mechanism behind both
        double-click and the context menu's Connect actions. Only records when
        force_record is explicitly True (the context menu's "Connect and start
        recording") — plain connect/double-click never records."""
        if key in self._stream_sessions:
            self._append_log(self._t('log_already_playing').format(title))
            return
        ip, port = key
        mpv_path = self.mpv_path.text().strip()
        if not mpv_path:
            QMessageBox.warning(self, self._t('dlg_mpv_err_title'),
                                self._t('dlg_mpv_no_path'))
            return
        record_path = self._new_recording_path(key) if force_record else None
        url = build_rtsp_url(ip, port, *self._credentials.get(key, (None, None)))
        cmd = [mpv_path, f'--title={title}']
        if record_path:
            cmd.append(f'--stream-record={record_path}')
        cmd += [url, '--mute=yes']
        if sys.platform == 'linux':
            cmd.append('--gpu-context=x11egl')
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT)
        except Exception as e:
            QMessageBox.critical(self, self._t('dlg_mpv_err_title'),
                                 self._t('dlg_mpv_err_msg').format(e))
            return
        # Only set orange (and log) once we know the process started
        item = self._stream_items.get(key)
        if item:
            item.setForeground(COLOR_LAUNCHING)
        self._append_log(self._t('log_reconnect').format(title))
        self._reconnect_pids.add(proc.pid)
        self._refresh_stats_label()
        self._watch_reconnect(title, ip, port, proc.pid, record_path=record_path)

    # ── Context menu (right-click on a stream, list or mosaic) ──────────────────

    def _context_menu_targets(self, key):
        """Keys a context menu invoked on `key` should act on: the whole current
        selection if `key` is part of a multi-selection, otherwise just `key`."""
        selected = self._selected_keys()
        if key in selected and len(selected) > 1:
            return selected
        return [key]

    def _on_list_context_menu(self, pos):
        item = self._streams_list.itemAt(pos)
        if not item:
            return
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        key = (data[0], data[1])
        if key not in self._selected_keys():
            self._streams_list.clearSelection()
            item.setSelected(True)
            self._streams_list.setCurrentItem(item)
        self._show_stream_context_menu(key, self._streams_list.viewport().mapToGlobal(pos))

    def _on_mosaic_context_menu(self, ip, port, global_pos):
        key = (ip, port)
        if key not in self._selected_keys():
            self._mosaic_grid.select_only(ip, port)
        self._show_stream_context_menu(key, global_pos)

    def _show_stream_context_menu(self, key, global_pos):
        # The SAVED badge isn't backed by a filesystem watcher, so it can go stale
        # if recordings are deleted from outside the app; revalidate it against
        # disk right when the user is looking (the submenu below already does the
        # same live check for its own contents).
        self._refresh_stream_badge(key)
        targets = self._context_menu_targets(key)
        connectable = [k for k in targets if self._can_connect(k)]
        playing = [k for k in targets
                  if k in self._stream_sessions and not self._stream_sessions[k]['headless']]
        recording = [k for k in targets
                    if k in self._stream_sessions and self._stream_sessions[k]['headless']]
        live_keys = [k for k, s in self._stream_sessions.items() if s.get('embedded')]

        menu = QMenu(self)
        act_connect = menu.addAction(self._t('ctx_connect'))
        act_connect.setEnabled(bool(connectable))
        act_record = menu.addAction(self._t('ctx_connect_record'))
        act_record.setEnabled(bool(connectable))
        act_live_view = menu.addAction(self._t('ctx_live_view'))
        act_live_view.setEnabled(self._mosaic_radio.isChecked() and bool(connectable)
                                 and len(live_keys) < self.max_live_spin.value())
        act_stop_playback = menu.addAction(self._t('ctx_stop_playback'))
        act_stop_playback.setEnabled(bool(playing))
        act_stop_all_live = menu.addAction(self._t('ctx_stop_all_live'))
        act_stop_all_live.setEnabled(bool(live_keys))
        menu.addSeparator()
        act_start_headless = menu.addAction(self._t('ctx_start_headless_record'))
        act_start_headless.setEnabled(bool(connectable))
        act_stop_record = menu.addAction(self._t('ctx_stop_record'))
        act_stop_record.setEnabled(bool(recording))
        menu.addSeparator()
        act_copy = menu.addAction(self._t('ctx_copy_rtsp'))
        act_copy_host = menu.addAction(self._t('ctx_copy_host'))

        # These two apply only to the single stream that was right-clicked, not the
        # whole multi-selection — entering credentials and viewing info are per-stream.
        menu.addSeparator()
        cell = self._mosaic_cells.get(key)
        act_credentials = menu.addAction(self._t('ctx_enter_credentials'))
        act_credentials.setEnabled(bool(cell and cell.is_auth_failed()))
        act_info = menu.addAction(self._t('ctx_info'))
        act_info.setEnabled(key in self._rtsp_info)

        # Recordings submenu: about the single stream that was right-clicked, not
        # the whole multi-selection — opening/browsing recordings isn't a bulk action.
        recording_actions = {}
        act_open_folder = None
        recordings = self._recordings_for(key)
        if recordings:
            menu.addSeparator()
            rec_menu = menu.addMenu(self._t('ctx_recordings_menu'))
            for path in recordings:
                try:
                    size = self._format_size(os.path.getsize(path))
                except OSError:
                    size = '?'
                label = f'{os.path.basename(path)} ({size})'
                recording_actions[rec_menu.addAction(label)] = path
            rec_menu.addSeparator()
            act_open_folder = rec_menu.addAction(self._t('ctx_open_recordings_folder'))

        menu.addSeparator()
        act_delete = menu.addAction(self._t('ctx_delete'))
        act_delete.setEnabled(self._running_source is None)

        chosen = menu.exec(global_pos)
        if chosen in recording_actions:
            QDesktopServices.openUrl(QUrl.fromLocalFile(recording_actions[chosen]))
        elif act_open_folder is not None and chosen is act_open_folder:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self._recording_folder(key)))
        elif chosen is act_connect:
            self._connect_targets(connectable)
        elif chosen is act_record:
            self._connect_targets(connectable, force_record=True)
        elif chosen is act_live_view:
            self._start_live_targets(connectable)
        elif chosen is act_stop_playback:
            self._stop_targets(playing)
        elif chosen is act_stop_all_live:
            self._stop_all_live_views()
        elif chosen is act_start_headless:
            self._start_headless_targets(connectable)
        elif chosen is act_stop_record:
            self._stop_targets(recording)
        elif chosen is act_copy:
            self._copy_rtsp_links(targets)
        elif chosen is act_copy_host:
            self._copy_hosts(targets)
        elif chosen is act_delete:
            self._delete_targets(targets)
        elif chosen is act_credentials:
            self._on_enter_credentials(key, self._target_title(key))
        elif chosen is act_info:
            self._show_info_dialog(self._target_title(key), self._rtsp_info.get(key, ''))

    def _prompt_credentials(self, title):
        """Modal dialog asking for username/password. Returns (user, pass) or
        None if the user cancels."""
        dlg = QDialog(self)
        dlg.setWindowTitle(self._t('dlg_credentials_title'))
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel(title))
        user_edit = QLineEdit()
        pass_edit = QLineEdit()
        pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form = QVBoxLayout()
        form.addWidget(QLabel(self._t('dlg_credentials_user')))
        form.addWidget(user_edit)
        form.addWidget(QLabel(self._t('dlg_credentials_pass')))
        form.addWidget(pass_edit)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            return user_edit.text(), pass_edit.text()
        return None

    def _on_enter_credentials(self, key, title):
        result = self._prompt_credentials(title)
        if result is None:
            return
        self._credentials[key] = result
        self._pending_credential_keys.add(key)
        self._connect_stream(key, title)

    def _show_info_dialog(self, title, text):
        dlg = QDialog(self)
        dlg.setWindowTitle(self._t('dlg_info_title').format(title))
        layout = QVBoxLayout(dlg)
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setFont(QFont('monospace'))
        view.setPlainText(text)
        layout.addWidget(view)
        buttons = QDialogButtonBox()
        copy_btn = buttons.addButton(self._t('btn_copy'), QDialogButtonBox.ButtonRole.ActionRole)
        close_btn = buttons.addButton(self._t('btn_close'), QDialogButtonBox.ButtonRole.RejectRole)
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(text))
        close_btn.clicked.connect(dlg.reject)
        layout.addWidget(buttons)
        dlg.resize(600, 400)
        dlg.exec()

    def _target_title(self, key):
        item = self._stream_items.get(key)
        data = item.data(Qt.ItemDataRole.UserRole) if item else None
        return data[2] if data else f'{key[0]}:{key[1]}'

    def _connect_targets(self, keys, force_record=False):
        for key in keys:
            self._connect_stream(key, self._target_title(key), force_record=force_record)

    def _start_headless_targets(self, keys):
        for key in keys:
            self._start_headless_recording(key, self._target_title(key))

    def _start_live_targets(self, keys):
        for key in keys:
            self._start_live_embed(key, self._target_title(key))

    def _start_headless_recording(self, key, title):
        """Record a stream to disk without opening any window (mpv --vo=null
        --force-window=no) — a separate mpv process from live playback, so it can
        be stopped independently without affecting a viewer watching the stream."""
        if key in self._stream_sessions:
            self._append_log(self._t('log_already_playing').format(title))
            return
        ip, port = key
        mpv_path = self.mpv_path.text().strip()
        if not mpv_path:
            QMessageBox.warning(self, self._t('dlg_mpv_err_title'),
                                self._t('dlg_mpv_no_path'))
            return
        record_path = self._new_recording_path(key)
        url = build_rtsp_url(ip, port, *self._credentials.get(key, (None, None)))
        cmd = [mpv_path, '--vo=null', '--force-window=no',
               '--really-quiet', '--no-terminal',
               f'--stream-record={record_path}', url]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT)
        except Exception as e:
            QMessageBox.critical(self, self._t('dlg_mpv_err_title'),
                                 self._t('dlg_mpv_err_msg').format(e))
            return
        self._mark_session(key, proc.pid, headless=True, record_path=record_path)
        self._append_log(self._t('log_recording_started').format(title))

    def _start_live_embed(self, key, title):
        """Play a stream live inside its own mosaic cell (mpv --wid) instead of a
        separate window. No window-appearance watch is needed here (unlike
        _connect_stream) — the session is marked immediately after Popen succeeds,
        same as _start_headless_recording; if mpv dies early (bad credentials,
        connection refused), _poll_live_mpv's existing dead-pid sweep notices within
        a second and reverts the cell to thumbnail mode via _end_session."""
        if key in self._stream_sessions:
            self._append_log(self._t('log_already_playing').format(title))
            return
        max_live = self.max_live_spin.value()
        active_live = sum(1 for s in self._stream_sessions.values() if s.get('embedded'))
        if active_live >= max_live:
            self._append_log(self._t('log_live_limit').format(max_live))
            return
        ip, port = key
        mpv_path = self.mpv_path.text().strip()
        if not mpv_path:
            QMessageBox.warning(self, self._t('dlg_mpv_err_title'),
                                self._t('dlg_mpv_no_path'))
            return
        cell = self._mosaic_cells.get(key)
        if not cell:
            return
        cell.set_live_mode(True)
        wid = int(cell.live_video_widget().winId())
        url = build_rtsp_url(ip, port, *self._credentials.get(key, (None, None)))
        # --input-cursor=no stops mpv from grabbing pointer input on its embedded
        # window at all, so clicks propagate to the cell instead of being swallowed
        # by mpv (needed for selecting/right-clicking a cell while it's live);
        # --input-vo-keyboard=no/--no-input-default-bindings do the same for the
        # keyboard, since this is meant to be a passive preview tile, not a player.
        # --vo=x11 (plain X11 blits, no GPU context) instead of the default GPU-
        # accelerated output: each embedded tile would otherwise open its own EGL
        # context, and several of those at once appear to contend for the GPU/
        # compositor badly enough to make the whole desktop feel unresponsive.
        cmd = [mpv_path, f'--wid={wid}', url, '--mute=yes', '--vo=x11',
               '--no-osc', '--osd-level=0', '--cursor-autohide=always',
               '--force-window=immediate', '--input-cursor=no',
               '--input-vo-keyboard=no', '--no-input-default-bindings']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.STDOUT)
        except Exception as e:
            cell.set_live_mode(False)
            QMessageBox.critical(self, self._t('dlg_mpv_err_title'),
                                 self._t('dlg_mpv_err_msg').format(e))
            return
        self._mark_session(key, proc.pid, embedded=True)
        self._append_log(self._t('log_live_started').format(title))

    def _stop_targets(self, keys):
        for key in keys:
            self._stop_session(key, self._target_title(key))

    def _stop_all_live_views(self):
        """Stop every embedded live view app-wide, regardless of selection —
        the escape hatch for when too many at once make the whole app sluggish."""
        keys = [k for k, s in self._stream_sessions.items() if s.get('embedded')]
        for key in keys:
            self._stop_session(key, self._target_title(key))

    def _copy_rtsp_links(self, keys):
        urls = [f'rtsp://{ip}:{port}' for ip, port in keys]
        QApplication.clipboard().setText('\n'.join(urls))
        self._append_log(self._t('log_rtsp_copied').format(', '.join(urls)))

    def _copy_hosts(self, keys):
        hosts = [ip for ip, _port in keys]
        QApplication.clipboard().setText('\n'.join(hosts))
        self._append_log(self._t('log_host_copied').format(', '.join(hosts)))

    def _delete_targets(self, keys):
        for key in keys:
            item = self._stream_items.get(key)
            if item:
                self._remove_stream(key, item)
        self._update_count()

    def _watch_reconnect(self, title, ip, port, pid, record_path=None):
        """Poll for the MPV window every second until it appears or timeout expires."""
        start = time.time()

        def _finish(status):
            if status == 'working':
                # Keep counting the pid in Proc (like the batch path does) until
                # _poll_live_mpv notices the process has actually exited.
                self._add_live_mpv_pid(pid)
                self._mark_session((ip, port), pid, record_path=record_path)
            else:
                self._reconnect_pids.discard(pid)
            self._refresh_stats_label()
            self._on_stream_status(title, status)

        def check():
            try:
                psutil.Process(pid)
            except psutil.NoSuchProcess:
                timer.stop()
                _finish('failed')
                return
            if title in list_window_titles():
                timer.stop()
                _finish('working')
            elif time.time() - start >= DEFAULT_TIMEOUT:
                timer.stop()
                try:
                    psutil.Process(pid).kill()
                except Exception:
                    pass
                _finish('failed')

        timer = QTimer(self)
        timer.timeout.connect(check)
        timer.start(1000)

    def _update_count(self):
        total   = self._streams_list.count()
        visible = sum(1 for i in range(total) if not self._streams_list.item(i).isHidden())
        self._count_label.setText(self._t('streams_count').format(visible, total))

    def _apply_filter(self, _index=None):
        fval = self._filter_combo.currentData()
        color_map = {
            'working':    COLOR_WORKING,
            'working_av': COLOR_WORKING,
            'failed':     COLOR_FAILED,
            'launching':  COLOR_LAUNCHING,
        }
        target = color_map.get(fval)
        for i in range(self._streams_list.count()):
            item = self._streams_list.item(i)
            data = item.data(Qt.ItemDataRole.UserRole)
            key = (data[0], data[1]) if data else None
            if fval == 'all':
                hidden = False
            elif fval == 'working_av':
                hidden = not (item.foreground().color() == COLOR_WORKING
                              and ' · AV' in item.text())
            elif fval == 'recording':
                session = self._stream_sessions.get(key) if key else None
                hidden = not (session and session['record_path'])
            elif fval == 'auth':
                cell = self._mosaic_cells.get(key) if key else None
                hidden = not (cell and cell.is_auth_failed())
            else:
                hidden = bool(target and item.foreground().color() != target)
            item.setHidden(hidden)
            if data:
                ip, port, _ = data
                self._mosaic_grid.set_cell_visible(ip, port, not hidden)
        self._update_count()
        self._refresh_connect_buttons()

    def _visible_items(self):
        """Returns list of (key, item) for currently visible stream items."""
        return [(k, v) for k, v in self._stream_items.items() if not v.isHidden()]

    def _remove_stream(self, key, item):
        """Remove a stream from list, mosaic and stream_items dict."""
        session = self._stream_sessions.get(key)
        if session and session.get('embedded'):
            # The mpv process renders into the cell's widget — kill it before
            # destroying that widget, or it's left holding an invalid window handle.
            try:
                psutil.Process(session['pid']).kill()
            except Exception:
                pass
            self._stream_sessions.pop(key, None)
        self._audio_probes.pop(key, None)
        self._auth_probes.pop(key, None)
        self._streams_list.takeItem(self._streams_list.row(item))
        del self._stream_items[key]
        if key in self._mosaic_cells:
            del self._mosaic_cells[key]
            self._mosaic_grid.remove_cell(*key)

    def _clear_streams(self):
        for key, item in self._visible_items():
            self._remove_stream(key, item)
        self._update_count()

    def _clear_failed_streams(self):
        for key, item in list(self._stream_items.items()):
            if item.foreground().color() == COLOR_FAILED:
                self._remove_stream(key, item)
        self._update_count()

    def _save_streams(self):
        path, _ = QFileDialog.getSaveFileName(
            self, self._t('dlg_save_streams'), '', self._t('json_filter'))
        if not path:
            return
        if not path.endswith('.json'):
            path += '.json'
        data = []
        for (ip, port), item in self._visible_items():
            # Use the canonical title (UserRole), not the display text — the latter
            # may carry appended badges (audio, play/record state) that must never
            # leak into the saved title (they'd get duplicated on reload).
            role_data = item.data(Qt.ItemDataRole.UserRole)
            title = role_data[2] if role_data else item.text()[2:]
            entry = {'ip': ip, 'port': port, 'title': title}
            cell = self._mosaic_cells.get((ip, port))
            if cell and cell.audio_type() is not None:
                entry['audio'] = cell.audio_type()
            else:
                text = item.text()
                for badge in (' · V', ' · AV'):
                    if badge in text:
                        entry['audio'] = badge.strip(' · ')
                        break
            data.append(entry)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def _load_streams(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self, self._t('dlg_load_streams'), '', self._t('json_filter'))
        if not paths:
            return
        added = skipped = 0
        errors = []
        audio_map = {}     # key → audio type, for applying badges after sync
        loaded_keys = []
        for path in paths:
            try:
                with open(path) as f:
                    data = json.load(f)
            except Exception:
                errors.append(path)
                continue
            for entry in data:
                ip    = entry.get('ip', '')
                port  = entry.get('port', 0)
                title = entry.get('title', f'{ip}:{port}')
                if not ip or not port:
                    continue
                key = (ip, int(port))
                if key in self._stream_items:
                    skipped += 1
                    continue
                audio = entry.get('audio')
                item = QListWidgetItem('⬤ ' + title)
                item.setForeground(COLOR_IDLE)
                item.setData(Qt.ItemDataRole.UserRole, (ip, int(port), title))
                self._stream_items[key] = item
                self._streams_list.addItem(item)
                if audio:
                    audio_map[key] = audio
                loaded_keys.append(key)
                added += 1
        if errors:
            QMessageBox.warning(self, self._t('dlg_load_err_title'),
                                self._t('dlg_load_err').format('\n'.join(errors)))
        self._sync_mosaic_cells()
        for key, audio in audio_map.items():
            cell = self._mosaic_cells.get(key)
            if cell:
                cell.set_audio_type(audio)
        for key in loaded_keys:
            self._refresh_stream_badge(key)   # picks up audio + any SAVED recordings
        self._filter_combo.setCurrentIndex(0)  # reset to All so loaded streams are visible
        self._apply_filter()
        self._append_log(self._t('log_load_summary').format(added, skipped, len(paths)))

    def _prepare_run(self):
        """Validate MPV path, config and required software for a run.
        Returns the built config, or None if validation failed (error already shown)."""
        if not self._ensure_mpv_path():
            return None
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return None
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return None
        return config

    def _make_args(self, **overrides):
        """Build the Namespace of run arguments, applying per-action overrides."""
        base = dict(
            random_pages  = False,
            leave_windows = False,
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            stream_record = False,
            probe           = False,
            thumb_timeout   = self._thumb_timeout_spin.value(),
            verbose         = False,
        )
        base.update(overrides)
        return Namespace(**base)

    def _queue_thumbnail(self, ip, port):
        """Queue a thumbnail capture for (ip, port) if an MPV path is set."""
        mpv = self.mpv_path.text().strip()
        if mpv:
            username, password = self._credentials.get((ip, port), (None, None))
            self._thumb_manager.add(ip, port, mpv, self._thumb_timeout_spin.value(),
                                     username=username, password=password)

    def _stream_status(self, key):
        """Single source of truth for a stream's probe status ('working'/'failed'/... or
        None if it doesn't have a mosaic cell yet)."""
        cell = self._mosaic_cells.get(key)
        return cell.status() if cell else None

    def _can_connect(self, key):
        """Whether a NEW connection may be started for this stream: verified working,
        and not already playing/recording (that's what "Stop playback" is for)."""
        return self._stream_status(key) == 'working' and key not in self._stream_sessions

    def _refresh_connect_buttons(self):
        """Keep Connect all/selected enabled exactly when the context menu's Connect
        would be: at least one target can actually be connected to right now.
        Never runs while a worker is active — _set_running owns button state then."""
        if self._running_source is not None:
            return
        visible_keys = [k for k, _ in self._visible_items()]
        self._connect_btn.setEnabled(any(self._can_connect(k) for k in visible_keys))
        self._connect_selected_btn.setEnabled(
            any(self._can_connect(k) for k in self._selected_keys()))

    # ── Recording file layout: recordings/<ip>_<port>/<timestamp>.mkv ───────────

    def _recording_folder(self, key):
        # Absolute path: QDesktopServices/QUrl.fromLocalFile() need one to build a
        # valid file:// URI — a relative one produces a malformed URI that gio/
        # xdg-open reject ("Operation not supported").
        ip, port = key
        folder = os.path.abspath(os.path.join(RECORDINGS_DIR, f'{ip}_{port}'))
        os.makedirs(folder, exist_ok=True)
        return folder

    def _new_recording_path(self, key):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(self._recording_folder(key), f'{ts}.mkv')

    def _recordings_for(self, key):
        """Existing recordings for this stream, most recent first."""
        folder = os.path.abspath(os.path.join(RECORDINGS_DIR, f'{key[0]}_{key[1]}'))
        if not os.path.isdir(folder):
            return []
        return sorted(glob.glob(os.path.join(folder, '*.mkv')), reverse=True)

    @staticmethod
    def _format_size(num_bytes):
        size = float(num_bytes)
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024 or unit == 'GB':
                return f'{size:.0f}{unit}' if unit == 'B' else f'{size:.1f}{unit}'
            size /= 1024

    # ── Per-stream session tracking (currently playing / recording) ────────────

    def _mark_session(self, key, pid, headless=False, record_path=None, embedded=False):
        self._stream_sessions[key] = {
            'pid': pid, 'headless': headless, 'record_path': record_path,
            'embedded': embedded,
        }
        self._live_mpv_timer.start()
        self._refresh_connect_buttons()
        self._refresh_stream_badge(key)
        if record_path and self._filter_combo.currentData() == 'recording':
            self._apply_filter()

    def _end_session(self, key):
        session = self._stream_sessions.pop(key, None)
        if session and session.get('embedded'):
            cell = self._mosaic_cells.get(key)
            if cell:
                cell.set_live_mode(False)
        self._refresh_connect_buttons()
        self._refresh_stream_badge(key)
        if self._filter_combo.currentData() == 'recording':
            self._apply_filter()

    def _session_badge_text(self, key):
        """Short tag summarizing this stream's play/record state, or None for
        nothing to show — same order of precedence in both list and mosaic.
        While actively recording, the tag also carries the file's current size
        (refreshed once a second by _poll_live_mpv) so growth is visible live."""
        session = self._stream_sessions.get(key)
        if session:
            if not session['record_path']:
                return 'LIVE' if session.get('embedded') else 'PLAY'
            base = 'REC' if session['headless'] else 'PLAY·REC'
            try:
                size = self._format_size(os.path.getsize(session['record_path']))
            except OSError:
                return base   # file not written yet
            return f'{base} {size}'
        cell = self._mosaic_cells.get(key)
        if cell and cell.is_auth_failed():
            return 'AUTH'
        if self._recordings_for(key):
            return 'SAVED'
        return None

    def _session_badge_color(self, key):
        """Mosaic-only badge color: green while just watching, red the moment
        recording (or an auth failure) is involved, neutral for a saved-but-
        inactive recording."""
        session = self._stream_sessions.get(key)
        if session:
            return COLOR_FAILED if (session['headless'] or session['record_path']) \
                else COLOR_WORKING
        cell = self._mosaic_cells.get(key)
        if cell and cell.is_auth_failed():
            return COLOR_FAILED
        if self._recordings_for(key):
            return COLOR_SAVED
        return None

    def _refresh_stream_badge(self, key):
        """Recompute and apply the play/record badge for one stream, in both views."""
        badge = self._session_badge_text(key)
        cell = self._mosaic_cells.get(key)
        if cell:
            cell.set_session_badge(badge, self._session_badge_color(key))
        item = self._stream_items.get(key)
        if item:
            data = item.data(Qt.ItemDataRole.UserRole)
            title = data[2] if data else f'{key[0]}:{key[1]}'
            parts = ['⬤ ' + title]
            audio = cell.audio_type() if cell else None
            if audio:
                parts.append(audio)
            if badge:
                parts.append(badge)
            item.setText(' · '.join(parts))

    def _stop_session(self, key, title):
        session = self._stream_sessions.get(key)
        if not session:
            return
        try:
            psutil.Process(session['pid']).kill()
        except Exception:
            pass
        headless = session['headless']
        self._end_session(key)
        log_key = 'log_recording_stopped' if headless else 'log_playback_stopped'
        self._append_log(self._t(log_key).format(title))

    def _connect_all(self):
        visible = self._visible_items()
        matches = [key for key, _ in visible if self._can_connect(key)]
        if not matches:
            self._append_log(self._t('log_no_working_selected'))
            return
        config = self._prepare_run()
        if config is None:
            return
        for key, item in visible:
            if key in matches:
                item.setForeground(COLOR_LAUNCHING)
        args = self._make_args()
        self._running_source = 'connect_all'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    # ── Run control ───────────────────────────────────────────────────────────

    # source → (action button attr, normal-label translation key)
    _ACTION_BUTTONS = {
        'connect_all':      ('_connect_btn',          'btn_connect_all'),
        'connect_selected': ('_connect_selected_btn', 'btn_connect_selected'),
        'scan_all':         ('_scan_btn',             'btn_scan'),
        'scan_selected':    ('_scan_selected_btn',    'btn_scan_selected'),
    }

    def _set_running(self, running):
        t = TRANSLATIONS[self._lang]
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running and self._running_source == 'shodan')
        # Every action button follows the idle/busy rule by default...
        for btn in (self._connect_btn, self._connect_selected_btn,
                    self._scan_btn, self._scan_selected_btn):
            btn.setEnabled(not running)
        # ...except the one that triggered the run, which stays enabled and toggles to STOP
        active = self._ACTION_BUTTONS.get(self._running_source)
        if active:
            btn = getattr(self, active[0])
            btn.setEnabled(True)
            btn.setText(t['btn_stop_connect'] if running else t[active[1]])
        self._clear_btn.setEnabled(not running)
        self._clear_failed_btn.setEnabled(not running)
        self._load_streams_btn.setEnabled(not running)
        self._save_streams_btn.setEnabled(not running)
        self._list_radio.setEnabled(not running)
        self._mosaic_radio.setEnabled(not running)

    def eventFilter(self, obj, event):
        if (event.type() == QEvent.Type.KeyPress
                and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)):
            # Never start a new worker while one is running
            if self._running_source is not None:
                return True
            if obj is self._streams_list and self._streams_list.selectedItems():
                self._on_connect_selected_clicked()
                return True
            if obj is self._mosaic_grid and self._mosaic_grid.selected_keys():
                self._on_connect_selected_clicked()
                return True
        return super().eventFilter(obj, event)

    def _on_scan_btn_clicked(self):
        if self._running_source == 'scan_all':
            self._stop()
        else:
            self._scan_all()

    def _on_scan_selected_btn_clicked(self):
        if self._running_source == 'scan_selected':
            self._stop()
        else:
            self._scan_selected()

    def _scan_all(self):
        """Probe all visible streams and capture a thumbnail for each (retries failed
        ones too — this is the only way to (re)test a stream, regardless of view)."""
        visible = self._visible_items()
        if not visible:
            return
        config = self._prepare_run()
        if config is None:
            return
        for _, item in visible:
            item.setForeground(COLOR_LAUNCHING)
        matches = [key for key, _ in visible]
        args = self._make_args(probe=True)
        self._running_source = 'scan_all'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    def _selected_keys(self):
        """Currently-selected stream keys, from whichever view (list or mosaic) is active."""
        if self._mosaic_radio.isChecked():
            return self._mosaic_grid.selected_keys()
        keys = []
        for item in self._streams_list.selectedItems():
            data = item.data(Qt.ItemDataRole.UserRole)
            if data:
                keys.append((data[0], data[1]))
        return keys

    def _scan_selected(self):
        """Probe the selected streams and capture a thumbnail for each — the way to
        retry a 'failed' stream, regardless of view."""
        selected_keys = self._selected_keys()
        if not selected_keys:
            return
        config = self._prepare_run()
        if config is None:
            return
        matches = []
        for ip, port in selected_keys:
            item = self._stream_items.get((ip, port))
            if item:
                item.setForeground(COLOR_LAUNCHING)
                matches.append((ip, port))
        if not matches:
            return
        args = self._make_args(probe=True)
        self._running_source = 'scan_selected'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    def _on_connect_btn_clicked(self):
        if self._running_source == 'connect_all':
            self._stop()
        else:
            self._connect_all()

    def _on_connect_selected_clicked(self):
        if self._running_source == 'connect_selected':
            self._stop()
        else:
            self._connect_selected()

    def _connect_selected(self):
        selected_keys = self._selected_keys()
        matches = [key for key in selected_keys if self._can_connect(key)]
        if not matches:
            self._append_log(self._t('log_no_working_selected'))
            return
        config = self._prepare_run()
        if config is None:
            return
        for ip, port in matches:
            item = self._stream_items.get((ip, port))
            if item:
                item.setForeground(COLOR_LAUNCHING)
        self._apply_filter()
        args = self._make_args()
        self._running_source = 'connect_selected'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    def _on_stats_update(self, procs, wins):
        self._last_stats = (procs, wins)
        self._refresh_stats_label()

    def _refresh_stats_label(self):
        procs, _ = self._last_stats
        procs += len(self._reconnect_pids)
        wins = len(self._live_mpv_pids)
        t = TRANSLATIONS[self._lang]
        self._stats_label.setText(
            f'{t["lbl_stat_proc"]}: {procs} / {self.max_proc_spin.value()}   '
            f'{t["lbl_stat_win"]}: {wins}'
        )

    # ── Mosaic helpers ────────────────────────────────────────────────────────

    def _sync_mosaic_cells(self):
        """Create mosaic cells for any stream_items not yet in the mosaic.
        Cells start in 'waiting' state — no thumbnail generation until user acts."""
        t = TRANSLATIONS[self._lang]
        for (ip, port), item in self._stream_items.items():
            if (ip, port) not in self._mosaic_cells:
                data = item.data(Qt.ItemDataRole.UserRole)
                title = data[2] if data else f'{ip}:{port}'
                self._mosaic_grid.add_cell(
                    ip, port, title,
                    t['mosaic_connecting'], t['mosaic_no_signal'],
                    t['mosaic_waiting'], t['mosaic_working'])
                cell = self._mosaic_grid.get_cell(ip, port)
                cell.set_status('waiting')
                self._mosaic_cells[(ip, port)] = cell
                self._mosaic_grid.set_cell_visible(ip, port, not item.isHidden())

    @staticmethod
    def _pid_alive(pid):
        try:
            return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
        except psutil.NoSuchProcess:
            return False

    def _poll_live_mpv(self):
        """Remove PIDs of closed MPV windows/processes and refresh the counter.
        A double-click connection stays in both _live_mpv_pids (Win) and
        _reconnect_pids (Proc) once confirmed working, so both are pruned here
        together — matching how the batch worker only drops a process from Proc
        once it actually exits, not once its window is merely confirmed.
        Per-stream sessions (playing/recording) are pruned the same way, since a
        headless recording has no window and would otherwise never get noticed."""
        dead_live = {pid for pid in self._live_mpv_pids if not self._pid_alive(pid)}
        dead_reconnect = {pid for pid in self._reconnect_pids if not self._pid_alive(pid)}
        dead_sessions = [key for key, s in self._stream_sessions.items()
                        if not self._pid_alive(s['pid'])]
        if dead_live or dead_reconnect or dead_sessions:
            self._live_mpv_pids -= dead_live
            self._reconnect_pids -= dead_reconnect
            for key in dead_sessions:
                self._end_session(key)
            self._refresh_stats_label()
        # Live-growing size on the REC/PLAY·REC badge for whatever is still recording.
        for key, session in self._stream_sessions.items():
            if session['record_path']:
                self._refresh_stream_badge(key)
        if not self._live_mpv_pids and not self._reconnect_pids and not self._stream_sessions:
            self._live_mpv_timer.stop()

    def _add_live_mpv_pid(self, pid):
        self._live_mpv_pids.add(pid)
        self._live_mpv_timer.start()
        self._refresh_stats_label()

    @pyqtSlot(int, str, int, str)
    def _on_worker_window_opened(self, pid, ip, port, record_path):
        self._add_live_mpv_pid(pid)
        self._mark_session((ip, port), pid, record_path=record_path or None)

    def _on_view_mode_changed(self, _btn, checked):
        if not checked:
            return
        mosaic = self._mosaic_radio.isChecked()
        self._streams_list.setVisible(not mosaic)
        self._mosaic_grid.setVisible(mosaic)
        self._thumb_size_combo.setVisible(mosaic)
        if mosaic:
            self._sync_mosaic_cells()
        self._refresh_connect_buttons()

    def _on_thumb_size_changed(self, _index):
        w, h = self._thumb_size_combo.currentData()
        self._mosaic_grid.set_thumb_size(w, h)

    def _retry_or_fail_thumbnail(self, ip, port, cell):
        """Re-queue thumbnail generation or mark as failed if retries exhausted."""
        if cell.has_thumbnail():
            return   # already have one, nothing to do
        if self.mpv_path.text().strip() and cell.retries() < MAX_THUMB_RETRIES:
            cell.bump_retries()
            cell.set_status('launching')   # back to orange while retrying
            self._queue_thumbnail(ip, port)
        else:
            cell.set_status('failed')

    def _on_thumbnail_ready(self, ip, port, pixmap):
        try:
            cell = self._mosaic_cells.get((ip, port))
            if cell:
                if pixmap and not pixmap.isNull():
                    cell.set_thumbnail(pixmap)
                    cell.set_status('working')
                elif not cell.has_thumbnail():
                    self._retry_or_fail_thumbnail(ip, port, cell)
        except Exception as e:
            print(f'_on_thumbnail_ready error ({ip}:{port}): {e}', file=sys.stderr)
        finally:
            thumb_dir = os.path.join(self._temp_dir, f'{ip}_{port}')
            shutil.rmtree(thumb_dir, ignore_errors=True)

    def _on_mosaic_cell_double_clicked(self, ip, port, title):
        # Reuse double-click logic: find the list item and delegate
        item = self._stream_items.get((ip, port))
        if item:
            self._on_stream_double_clicked(item)

    def _on_worker_thumbnail_generated(self, ip, port, file_path):
        """Load QPixmap in main thread (thread-safe) then update mosaic cell."""
        px = QPixmap(file_path) if file_path else None
        if px and px.isNull():
            px = None
        self._on_thumbnail_ready(ip, port, px)

    def _start_worker(self, config, args, matches=None, skip_fn=None):
        # Defensive: should never happen, but guard against double-start
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)

        args.shodan_plan = (self._shodan_info or {}).get('plan', '')
        args.log_dev_plan_limit = self._t('log_dev_plan_limit')
        max_procs_ref = [args.max_processes]
        self._proc_conn = self.max_proc_spin.valueChanged.connect(
            lambda v: max_procs_ref.__setitem__(0, v))
        thumb_dir = self._temp_dir if getattr(args, 'probe', False) else None
        w = VulnCamWorker(config, args, matches=matches, skip_fn=skip_fn,
                          max_procs_ref=max_procs_ref, thumb_base_dir=thumb_dir,
                          credentials=self._credentials)
        self.worker = w
        self._worker_refs.append(w)   # keep Python reference alive until finished

        def _worker_cleanup():
            try:
                self._worker_refs.remove(w)
            except ValueError:
                pass
            if self.worker is w:
                self.worker = None
            # w.finished (custom signal, emitted at the end of run()) can fire a
            # hair before the underlying OS thread has actually unwound; wait()
            # blocks until it truly has, avoiding "destroyed while still running".
            w.wait(5000)
            w.deleteLater()

        w.log_message.connect(self._append_log)
        w.error.connect(lambda e: self._append_log(self._t('log_worker_error').format(e)))
        w.stream_added.connect(self._on_stream_added)
        w.stream_status.connect(self._on_stream_status)
        w.stream_skipped.connect(
            lambda label: self._append_log(self._t('log_duplicate').format(label)))
        w.stats_update.connect(self._on_stats_update)
        w.window_opened.connect(self._on_worker_window_opened)
        w.thumbnail_generated.connect(self._on_worker_thumbnail_generated)
        w.finished.connect(self._on_finished)
        w.finished.connect(_worker_cleanup)   # always runs after _on_finished
        self._search_start_time = time.time()
        w.start()
        self._set_running(True)

    def _start(self):
        config = self._prepare_run()
        if config is None:
            return
        args = self._make_args(
            query         = self.query_field.text().strip() or DEFAULT_QUERY,
            extend        = self.extend_field.text().strip(),
            pages         = self.pages_spin.value(),
            random_pages  = self.random_check.isChecked(),
            total_results = self.allres_check.isChecked(),
            probe = True,
        )
        dedup = self._dedup_check.isChecked()
        items_ref = self._stream_items
        skip_fn = (lambda ip, port: (ip, port) in items_ref) if dedup else None
        self._running_source = 'shodan'
        self.log_view.clear()
        self._start_worker(config, args, skip_fn=skip_fn)

    def _stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self._append_log(self._t('log_stopping'))

    def _on_finished(self):
        self._set_running(False)
        self._running_source = None
        if hasattr(self, '_proc_conn'):
            self.max_proc_spin.valueChanged.disconnect(self._proc_conn)
        self._on_stats_update(0, 0)
        # Any stream still orange (launched but never resolved) → mark as failed
        for key, item in self._stream_items.items():
            if item.foreground().color() == COLOR_LAUNCHING:
                item.setForeground(COLOR_FAILED)
                cell = self._mosaic_cells.get(key)
                if cell and cell.status() == 'launching':
                    cell.set_status('failed')
        self._apply_filter()
        elapsed = int(time.time() - self._search_start_time)
        h, remainder = divmod(elapsed, 3600)
        m, s = divmod(remainder, 60)
        self._append_log(self._t('log_finished').format(f'{h:02d}:{m:02d}:{s:02d}'))

    def _append_log(self, msg):
        self.log_view.appendPlainText(msg)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)

