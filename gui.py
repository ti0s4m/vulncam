#!/usr/bin/env python3
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import configparser
import logging
from argparse import Namespace
from datetime import datetime
from random import shuffle

import psutil
import requests
import shodan
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QPushButton, QSpinBox, QCheckBox,
    QPlainTextEdit, QFileDialog, QMessageBox, QSizePolicy, QComboBox,
    QSplitter, QListWidget, QListWidgetItem, QScrollArea, QFrame,
    QRadioButton, QButtonGroup, QGridLayout,
)
from PyQt6.QtCore import (QThread, QThreadPool, QRunnable,
                          pyqtSignal, Qt, QTimer, QEvent, pyqtSlot, QObject)
from PyQt6.QtGui import QFont, QTextCursor, QColor, QIcon, QPixmap, QPainter

from vulncam import (
    VulnCam, check_config, check_linux_software,
    REQUIRED_SECTION, OPTIONAL_SECTION,
    DEFAULT_CONFIG_FILE, DEFAULT_QUERY, DEFAULT_MAX_PROCS, DEFAULT_PAGES,
    DEFAULT_TIMEOUT, RESULTS_PER_PAGE, MAX_PAGES,
)


_APP_ICON_B64 = "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"
_vulncam_logger = logging.getLogger('vulncam')

TRANSLATIONS = {
    'en': {
        'window_title':       'VulnCam',
        'label_language':     'Language:',
        'group_config':       'Configuration',
        'label_config_file':  'Config file:',
        'btn_browse':         'Browse...',
        'btn_save_cfg':       'Save',
        'label_shodan_key':   'Shodan API Key:',
        'label_mpv_path':     'MPV Path:',
        'label_ipgeo_key':    'IPGeo API Key (optional):',
        'group_playback':     'Playback',
        'label_max_proc':     'Max processes:',
        'btn_view_list':      'List',
        'btn_view_mosaic':    'Mosaic',
        'thumb_small':        'Small',
        'thumb_medium':       'Medium',
        'thumb_large':        'Large',
        'mosaic_connecting':  'Connecting...',
        'mosaic_working':     'Working',
        'mosaic_no_signal':   'No Signal',
        'mosaic_waiting':     'Idle',
        'check_record':       'Record streams',
        'check_leave':        'Leave windows on finish',
        'check_only':         'Check only',
        'label_probe':        'Probe (s):',
        'lbl_stat_proc':      'Proc',
        'lbl_stat_win':       'Win',
        'check_dedup':        'Skip duplicates',
        'group_search':         'Shodan search',
        'label_query':          'Query:',
        'lbl_presets':          'Presets…',
        'btn_adv_filters':      'Location',
        'label_country':        'Country:',
        'label_city':           'City:',
        'btn_clear_filters':    'Clear',
        'label_extend':         'Extend:',
        'label_pages':          'Pages:',
        'check_random':         'Random pages',
        'check_allres':         'All results',
        'btn_credits':          'Credits',
        'dlg_credits_title':    'Shodan credits',
        'dlg_credits_msg':      'Query credits: {}\nScan credits: {}',
        'dlg_credits_err':      'Could not retrieve credits. Check your API key.',
        'btn_shodan_info':      'Info',
        'log_shodan_info_err':  'Shodan info error: {}',
        'log_shodan_info_hdr':  '── Shodan account info ──',
        'log_worker_error':     'Error: {}',
        'dlg_load_err_title':   'Error',
        'log_dev_plan_limit':   'Dev plan: random pages limited to 1. Fetching 1 random page.',
        'log_duplicate':        'Already listed, skipping: {}',
        'btn_restore':        'Restore defaults',
        'btn_start':          'START',
        'btn_stop':           'STOP',
        'dlg_select_config':  'Select config file',
        'dlg_select_mpv':     'Select MPV',
        'ini_filter':         'INI files (*.ini)',
        'btn_detect_mpv':     'Detect',
        'log_mpv_detected':   'MPV auto-detected: {}',
        'log_mpv_not_found':  'MPV not found automatically. Please set the path manually.',
        'dlg_mpv_missing':    'MPV path is empty and could not be detected automatically.\nPlease install MPV or set its path manually.',
        'dlg_cfg_err_title':  'Configuration error',
        'dlg_cfg_err_msg':    'Required parameters missing (Shodan API Key and MPV Path).',
        'dlg_sw_err_title':   'Missing software',
        'dlg_sw_err_msg':     'mpv or wmctrl are not installed.',
        'log_stopping':       'Stopping...',
        'log_finished':       '── Finished ({}) ──',
        'group_streams':      'Streams',
        'label_filter':       'Filter:',
        'filter_all':         'All',
        'filter_working':     'Working',
        'filter_working_av':  'Working (AV)',
        'filter_failed':      'Failed',
        'filter_launching':   'Launching',
        'label_thumb_timeout': 'Thumb (s):',
        'check_discard':      'Discard not working',
        'btn_clear_streams':  'Clear',
        'btn_clear_failed':   'Clear failed',
        'btn_save_streams':   'Save',
        'btn_load_streams':   'Load',
        'btn_connect_all':      'Connect all',
        'btn_connect_selected': 'Connect selected',
        'btn_scan':             'Scan',
        'btn_scan_selected':    'Scan selected',
        'btn_stop_connect':     'Stop',
        'log_reconnect':      'Reconnecting: {}',
        'dlg_save_streams':   'Save stream list',
        'dlg_load_streams':   'Load stream list(s)',
        'json_filter':        'JSON files (*.json)',
        'log_load_summary':   'Loaded {0} streams, {1} duplicates skipped ({2} file(s))',
        'dlg_load_err':       'Could not read the following file(s):\n{}',
        'streams_count':      '{} / {} streams',
        'dlg_mpv_err_title':  'MPV launch error',
        'dlg_mpv_err_msg':    'Could not start MPV. Check the MPV path in the configuration.\n\n{}',
        'dlg_mpv_no_path':    'MPV path is not set. Please fill in the MPV Path field in the configuration.',
    },
    'es': {
        'window_title':       'VulnCam',
        'label_language':     'Idioma:',
        'group_config':       'Configuración',
        'label_config_file':  'Archivo config:',
        'btn_browse':         'Buscar...',
        'btn_save_cfg':       'Guardar',
        'label_shodan_key':   'Shodan API Key:',
        'label_mpv_path':     'MPV Path:',
        'label_ipgeo_key':    'IPGeo API Key (opcional):',
        'group_playback':     'Reproducción',
        'label_max_proc':     'Máx procesos:',
        'btn_view_list':      'Listado',
        'btn_view_mosaic':    'Mosaico',
        'thumb_small':        'Pequeño',
        'thumb_medium':       'Mediano',
        'thumb_large':        'Grande',
        'mosaic_connecting':  'Conectando...',
        'mosaic_working':     'Activo',
        'mosaic_no_signal':   'Sin señal',
        'mosaic_waiting':     'Idle',
        'check_record':       'Grabar streams',
        'check_leave':        'Dejar ventanas al terminar',
        'check_only':         'Solo verificar',
        'label_probe':        'Sonda (s):',
        'lbl_stat_proc':      'Proc',
        'lbl_stat_win':       'Vent',
        'check_dedup':        'Omitir duplicados',
        'group_search':         'Búsqueda Shodan',
        'label_query':          'Query:',
        'lbl_presets':          'Presets…',
        'btn_adv_filters':      'Localización',
        'label_country':        'País:',
        'label_city':           'Ciudad:',
        'btn_clear_filters':    'Limpiar',
        'label_extend':         'Extender:',
        'label_pages':          'Páginas:',
        'check_random':         'Páginas aleatorias',
        'check_allres':         'Todos los resultados',
        'btn_credits':          'Créditos',
        'dlg_credits_title':    'Créditos Shodan',
        'dlg_credits_msg':      'Créditos de consulta: {}\nCréditos de escaneo: {}',
        'dlg_credits_err':      'No se pudieron obtener los créditos. Comprueba tu API key.',
        'btn_shodan_info':      'Info',
        'log_shodan_info_err':  'Error info Shodan: {}',
        'log_shodan_info_hdr':  '── Información cuenta Shodan ──',
        'log_worker_error':     'Error: {}',
        'dlg_load_err_title':   'Error',
        'log_dev_plan_limit':   'Plan Dev: páginas aleatorias limitadas a 1. Se obtendrá 1 página aleatoria.',
        'log_duplicate':        'Ya en el listado, omitiendo: {}',
        'btn_restore':        'Restaurar valores por defecto',
        'btn_start':          'START',
        'btn_stop':           'STOP',
        'dlg_select_config':  'Seleccionar config',
        'dlg_select_mpv':     'Seleccionar MPV',
        'ini_filter':         'INI files (*.ini)',
        'btn_detect_mpv':     'Detectar',
        'log_mpv_detected':   'MPV detectado automáticamente: {}',
        'log_mpv_not_found':  'MPV no encontrado automáticamente. Por favor establece la ruta manualmente.',
        'dlg_mpv_missing':    'El campo MPV Path está vacío y no se ha podido detectar automáticamente.\nInstala MPV o establece su ruta manualmente.',
        'dlg_cfg_err_title':  'Error de configuración',
        'dlg_cfg_err_msg':    'Faltan parámetros requeridos (Shodan API Key y MPV Path).',
        'dlg_sw_err_title':   'Software no encontrado',
        'dlg_sw_err_msg':     'mpv o wmctrl no están instalados.',
        'log_stopping':       'Deteniendo...',
        'log_finished':       '── Finalizado ({}) ──',
        'group_streams':      'Streams',
        'label_filter':       'Filtrar:',
        'filter_all':         'Todas',
        'filter_working':     'Activas',
        'filter_working_av':  'Activas (AV)',
        'filter_failed':      'Fallidas',
        'filter_launching':   'Lanzando',
        'label_thumb_timeout': 'Thumb (s):',
        'check_discard':      'Descartar fallidos',
        'btn_clear_streams':  'Limpiar',
        'btn_clear_failed':   'Eliminar fallidos',
        'btn_save_streams':   'Guardar',
        'btn_load_streams':   'Cargar',
        'btn_connect_all':      'Conectar todas',
        'btn_connect_selected': 'Conectar seleccionadas',
        'btn_scan':             'Escanear',
        'btn_scan_selected':    'Escanear seleccionadas',
        'btn_stop_connect':     'Detener',
        'log_reconnect':      'Reconectando: {}',
        'dlg_save_streams':   'Guardar lista de streams',
        'dlg_load_streams':   'Cargar lista(s) de streams',
        'json_filter':        'JSON files (*.json)',
        'log_load_summary':   'Cargados {0} streams, {1} duplicados omitidos ({2} fichero(s))',
        'dlg_load_err':       'No se pudieron leer los siguientes ficheros:\n{}',
        'streams_count':      '{} / {} streams',
        'dlg_mpv_err_title':  'Error al lanzar MPV',
        'dlg_mpv_err_msg':    'No se pudo iniciar MPV. Comprueba la ruta del MPV en la configuración.\n\n{}',
        'dlg_mpv_no_path':    'La ruta de MPV no está configurada. Por favor rellena el campo MPV Path en la configuración.',
    },
}

_COLOR_IDLE      = QColor('#707070')
_COLOR_LAUNCHING = QColor('#E8A020')
_COLOR_WORKING   = QColor('#20A050')
_COLOR_FAILED    = QColor('#C03030')

PROBE_DEFAULT = 10

THUMB_SIZES = [
    ('small',  160,  90),
    ('medium', 240, 135),
    ('large',  320, 180),
]
THUMB_W = 240
THUMB_H = 135   # 16:9 medium (default)
MAX_THUMB_RETRIES = 2

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


def _get_open_windows():
    """Return list of visible window titles, cross-platform."""
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


# ── Mosaic view ───────────────────────────────────────────────────────────────

class MosaicCell(QFrame):
    double_clicked = pyqtSignal(str, int, str)   # ip, port, title
    clicked        = pyqtSignal(str, int)         # ip, port

    def __init__(self, ip, port, title, connect_text, no_signal_text,
                 waiting_text='Idle', working_text='Working',
                 thumb_w=THUMB_W, thumb_h=THUMB_H, parent=None):
        super().__init__(parent)
        self._ip = ip
        self._port = port
        self._title = title
        self._connect_text = connect_text
        self._no_signal_text = no_signal_text
        self._waiting_text = waiting_text
        self._working_text = working_text
        self._status = 'launching'
        self._has_thumbnail = False
        self._source_pixmap = None
        self._thumb_retries = 0
        self._selected = False
        self._filter_hidden = False
        self._thumb_w = thumb_w
        self._thumb_h = thumb_h
        self.setFixedWidth(thumb_w + 20)
        self.setFrameShape(QFrame.Shape.Box)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        self._img_lbl = QLabel()
        self._img_lbl.setFixedSize(thumb_w, thumb_h)
        self._img_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._img_lbl)
        self._audio_badge = QLabel(self._img_lbl)
        self._audio_badge.setStyleSheet(
            'background: rgba(0,0,0,170); color: #ffffff;'
            ' padding: 1px 4px; border-radius: 3px;'
            ' font-size: 9px; font-weight: bold;')
        self._audio_badge.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._audio_badge.setVisible(False)
        self._title_lbl = QLabel()
        self._title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_lbl.setWordWrap(True)
        self._title_lbl.setFont(QFont('Monospace', 7))
        layout.addWidget(self._title_lbl)
        self._update_label(title)
        self._refresh()

    def _make_placeholder(self, text, color):
        try:
            px = QPixmap(self._thumb_w, self._thumb_h)
            px.fill(QColor('#1a1a1a'))
            p = QPainter(px)
            p.setPen(color)
            p.setFont(QFont('Sans', 11, QFont.Weight.Bold))
            p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, text)
            p.end()
            return px
        except Exception as e:
            print(f'MosaicCell._make_placeholder error: {e}', file=sys.stderr)
            return QPixmap(self._thumb_w, self._thumb_h)

    def _refresh(self):
        if not self._has_thumbnail:
            if self._status == 'waiting':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._waiting_text, QColor('#606060')))
            elif self._status == 'launching':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._connect_text, _COLOR_LAUNCHING))
            elif self._status == 'working':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._working_text, _COLOR_WORKING))
            else:
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._no_signal_text, _COLOR_FAILED))
        c = {'waiting': '#404040', 'launching': '#E8A020',
             'working': '#20A050', 'failed': '#C03030'}
        col = c.get(self._status, '#E8A020')
        bg = '#1e2a38' if self._selected else '#0d0d0d'
        border = f'3px solid #ffffff' if self._selected else f'2px solid {col}'
        self.setStyleSheet(
            f'MosaicCell {{ border: {border}; border-radius: 4px;'
            f' background: {bg}; }}'
            f'QLabel {{ border: none; color: #dddddd; }}')

    def set_selected(self, selected):
        self._selected = selected
        self._refresh()

    def set_status(self, status):
        self._status = status
        self._refresh()

    def set_thumbnail(self, pixmap):
        self._has_thumbnail = True
        self._source_pixmap = pixmap
        self._render_thumbnail()
        self._refresh()

    def _render_thumbnail(self):
        pixmap = self._source_pixmap
        if pixmap is None:
            return
        w, h = self._thumb_w, self._thumb_h
        try:
            scaled = pixmap.scaled(w, h,
                                   Qt.AspectRatioMode.KeepAspectRatio,
                                   Qt.TransformationMode.SmoothTransformation)
            final = QPixmap(w, h)
            final.fill(QColor('#000000'))
            p = QPainter(final)
            p.drawPixmap((w - scaled.width()) // 2,
                         (h - scaled.height()) // 2, scaled)
            p.end()
            self._img_lbl.setPixmap(final)
        except Exception as e:
            print(f'MosaicCell._render_thumbnail error: {e}', file=sys.stderr)
            self._img_lbl.setPixmap(pixmap.scaled(
                w, h, Qt.AspectRatioMode.KeepAspectRatio))

    def set_audio_type(self, audio_type):
        """Show badge 'V'/'AV' at bottom-right of thumbnail, or hide if None."""
        if audio_type is None:
            self._audio_badge.setVisible(False)
            return
        self._audio_badge.setText(audio_type)
        self._audio_badge.adjustSize()
        self._reposition_badge()
        self._audio_badge.setVisible(True)
        self._audio_badge.raise_()

    def _reposition_badge(self):
        b = self._audio_badge
        b.move(self._thumb_w - b.width() - 4,
               self._thumb_h - b.height() - 4)

    def resize_thumb(self, w, h):
        self._thumb_w = w
        self._thumb_h = h
        self.setFixedWidth(w + 20)
        self._img_lbl.setFixedSize(w, h)
        if self._audio_badge.isVisible():
            self._reposition_badge()
        if self._has_thumbnail:
            self._render_thumbnail()
        else:
            self._refresh()

    def _update_label(self, title):
        self._title = title
        try:
            core = title.split('] ', 1)[1]
            ip_port = core.split(' ')[0]
            geo = core.split('(')[1].rstrip(')') if '(' in core else ''
        except IndexError:
            ip_port = f'{self._ip}:{self._port}'
            geo = ''
        self._title_lbl.setText(f'{ip_port}\n{geo}' if geo else ip_port)

    def reset(self, keep_thumbnail=False):
        """Reset cell to launching state. keep_thumbnail preserves existing image."""
        if not keep_thumbnail:
            self._has_thumbnail = False
            self._source_pixmap = None
        self._thumb_retries = 0
        self._status = 'launching'
        self._audio_badge.setVisible(False)
        self._refresh()

    def audio_type(self):
        """Return the stored audio type ('V', 'AV') or None if not probed yet."""
        if self._audio_badge.isVisible():
            return self._audio_badge.text()
        return None

    def status(self):
        return self._status

    def has_thumbnail(self):
        return self._has_thumbnail

    def retranslate(self, connect_text, no_signal_text, waiting_text, working_text):
        self._connect_text = connect_text
        self._no_signal_text = no_signal_text
        self._waiting_text = waiting_text
        self._working_text = working_text
        if not self._has_thumbnail:
            self._refresh()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self._ip, self._port)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        self.double_clicked.emit(self._ip, self._port, self._title)
        super().mouseDoubleClickEvent(event)


class MosaicGrid(QScrollArea):
    cell_double_clicked = pyqtSignal(str, int, str)
    selection_changed   = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        self._container = QWidget()
        self._container.setStyleSheet('background: #0a0a0a;')
        self.setWidget(self._container)
        self._glayout = QGridLayout(self._container)
        self._glayout.setSpacing(8)
        self._glayout.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self._cells = {}         # (ip, port) → MosaicCell
        self._order = []         # insertion order of (ip, port)
        self._selected = set()   # set of (ip, port)
        self._thumb_w = THUMB_W
        self._thumb_h = THUMB_H
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._do_relayout)

    def add_cell(self, ip, port, title, connect_text, no_signal_text,
                waiting_text='Idle', working_text='Working'):
        key = (ip, port)
        if key in self._cells:
            return
        cell = MosaicCell(ip, port, title, connect_text, no_signal_text,
                          waiting_text, working_text,
                          self._thumb_w, self._thumb_h,
                          parent=self._container)
        cell.double_clicked.connect(self.cell_double_clicked)
        cell.clicked.connect(self._on_cell_clicked)
        self._cells[key] = cell
        self._order.append(key)
        self._timer.start()

    def _on_cell_clicked(self, ip, port):
        key = (ip, port)
        modifiers = QApplication.keyboardModifiers()
        ctrl = bool(modifiers & Qt.KeyboardModifier.ControlModifier)
        if ctrl:
            # Toggle this cell
            if key in self._selected:
                self._selected.discard(key)
                self._cells[key].set_selected(False)
            else:
                self._selected.add(key)
                self._cells[key].set_selected(True)
        else:
            # Single select: deselect all others
            for k, c in self._cells.items():
                c.set_selected(k == key)
            self._selected = {key}
        self.selection_changed.emit()

    def selected_keys(self):
        return list(self._selected)

    def clear_selection(self):
        for key in list(self._selected):
            cell = self._cells.get(key)
            if cell:
                cell.set_selected(False)
        self._selected.clear()
        self.selection_changed.emit()

    def remove_cell(self, ip, port):
        key = (ip, port)
        cell = self._cells.pop(key, None)
        if cell:
            self._order.remove(key)
            self._selected.discard(key)
            self._glayout.removeWidget(cell)
            cell.deleteLater()
            self._timer.start()

    def get_cell(self, ip, port):
        return self._cells.get((ip, port))

    def set_cell_visible(self, ip, port, visible):
        cell = self._cells.get((ip, port))
        if cell:
            cell._filter_hidden = not visible
        self._timer.start()

    def _do_relayout(self):
        while self._glayout.count():
            self._glayout.takeAt(0)
        avail = self.viewport().width() - 16
        cell_w = self._thumb_w + 20 + 8   # fixed cell width + spacing
        cols = max(1, avail // cell_w)
        row = col = 0
        for key in self._order:
            cell = self._cells.get(key)
            if cell:
                if not cell._filter_hidden:
                    self._glayout.addWidget(cell, row, col)
                    cell.show()
                    col += 1
                    if col >= cols:
                        col = 0
                        row += 1
                else:
                    cell.hide()
        self._glayout.setRowStretch(row + 1, 1)

    def set_thumb_size(self, w, h):
        self._thumb_w = w
        self._thumb_h = h
        for cell in self._cells.values():
            cell.resize_thumb(w, h)
        self._timer.start()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._timer.start()


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


class GUIVulnCam(VulnCam):
    """VulnCam for GUI: no signal.signal setup, no sys.exit, status callbacks."""

    def __init__(self, config, args):
        self.config        = config
        self.random_pages  = args.random_pages
        self.leave_windows = args.leave_windows
        self.max_processes = args.max_processes
        self.stream_record = args.stream_record
        self.processes       = {}
        self.signal_received = False
        self._geo_cache        = {}
        self._last_geo_request = 0.0
        self.api = shodan.Shodan(config[REQUIRED_SECTION]['shodanapikey'])
        self._known_pids      = set()
        self.check_only        = args.check_only
        self.probe_seconds     = args.probe_seconds
        self.generate_mosaic   = getattr(args, 'generate_mosaic', False)
        self.thumb_timeout     = getattr(args, 'thumb_timeout', DEFAULT_TIMEOUT)
        self.shodan_plan       = getattr(args, 'shodan_plan', '')
        self._log_dev_plan_limit = getattr(args, 'log_dev_plan_limit', '')
        self.thumb_base_dir    = None    # set by worker before run()
        self.on_stream_added       = None
        self.on_stream_status      = None
        self.on_window_opened      = None   # (pid) → called when live MPV window appears
        self.on_thumbnail_generated = None  # (ip, port, file_path) -> None
        self.should_skip_stream    = None
        self.on_stream_skipped     = None
        self.on_stats_update       = None
        self.get_max_processes     = None

    def _sigint_handler(self, _signum, _frame):
        self.signal_received = True
        for pid in list(self.processes):
            if not self.leave_windows or not self.processes[pid]['working']:
                try:
                    self.processes[pid]['process'].kill()
                except Exception:
                    pass
                self.processes.pop(pid, None)

    def _active_processes(self):
        if self.check_only or self.generate_mosaic:
            # Silent modes: just count; _check_working handles cleanup
            return sum(1 for info in self.processes.values()
                       if info['process'].poll() is None)
        cnt = 0
        for pid in list(self.processes):
            try:
                p = psutil.Process(pid)
                if p.status() == psutil.STATUS_ZOMBIE:
                    info = self.processes.pop(pid)
                    info['process'].kill()
                    if not info['working'] and self.on_stream_status:
                        self.on_stream_status(info['title'], 'failed')
                else:
                    cnt += 1
            except psutil.NoSuchProcess:
                info = self.processes.pop(pid)
                if not info['working'] and self.on_stream_status:
                    self.on_stream_status(info['title'], 'failed')
        return cnt

    def _check_working(self):
        # Detect new PIDs in both modes
        for pid, info in list(self.processes.items()):
            if pid not in self._known_pids:
                self._known_pids.add(pid)
                if self.on_stream_added:
                    self.on_stream_added(info['title'])

        if self.check_only:
            now = time.time()
            for pid in list(self.processes):
                info = self.processes[pid]
                ret = info['process'].poll()
                elapsed = now - info['launch_time']
                if ret is not None:
                    self.processes.pop(pid)
                    # exit 0 + ran for (probe - 2) seconds or more → working
                    if ret == 0 and elapsed >= (self.probe_seconds - 2):
                        _vulncam_logger.debug('%s is working (exit 0, %.1fs)', info['title'], elapsed)
                        if self.on_stream_status:
                            self.on_stream_status(info['title'], 'working')
                    else:
                        if self.on_stream_status:
                            self.on_stream_status(info['title'], 'failed')
                elif elapsed > (self.probe_seconds + 15):
                    # Safety kill for hung processes
                    try:
                        info['process'].kill()
                    except Exception:
                        pass
                    self.processes.pop(pid)
                    if self.on_stream_status:
                        self.on_stream_status(info['title'], 'failed')
            if self.on_stats_update:
                self.on_stats_update(len(self.processes), 0)
            return 0  # no visible windows in check-only mode

        if self.generate_mosaic:
            now = time.time()
            for pid in list(self.processes):
                info = self.processes[pid]
                ret = info['process'].poll()
                if ret is not None:
                    self.processes.pop(pid)
                    thumb_dir = info.get('thumb_dir', '')
                    # MPV may exit non-zero even when the frame was saved;
                    # check file existence rather than relying on exit code.
                    thumb_file = None
                    if thumb_dir:
                        # Encode mode outputs thumb.png; fallback for old --vo=image names
                        for name in ('thumb.png', '00000001.png',
                                     '00000001.jpg', '00000001.webp'):
                            candidate = os.path.join(thumb_dir, name)
                            if os.path.isfile(candidate) \
                                    and os.path.getsize(candidate) > 0:
                                thumb_file = candidate
                                break
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
            return 0

        current_windows = _get_open_windows()
        now = time.time()
        cnt_working = 0
        for pid in list(self.processes):
            title = self.processes[pid]['title']
            if title in current_windows:
                if not self.processes[pid]['working']:
                    _vulncam_logger.debug('%s is working :)', title)
                    if self.on_stream_status:
                        self.on_stream_status(title, 'working')
                    if self.on_window_opened:
                        self.on_window_opened(pid)
                self.processes[pid]['working'] = True
                cnt_working += 1
            elif (now - self.processes[pid]['launch_time']) >= DEFAULT_TIMEOUT:
                was_working = self.processes[pid]['working']
                _vulncam_logger.debug('Killing %s as it is not working.', title)
                self.processes[pid]['process'].kill()
                self.processes.pop(pid)
                if not was_working and self.on_stream_status:
                    self.on_stream_status(title, 'failed')
        if self.on_stats_update:
            self.on_stats_update(len(self.processes), cnt_working)
        return cnt_working

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
                from random import sample
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
        """Single POST to ip-api.com/batch — up to 100 IPs, counts as 1 request."""
        try:
            r = requests.post(
                'http://ip-api.com/batch',
                json=[{'query': ip} for ip in ips],
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
            pass  # geo is optional

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
        for i in range(0, len(ips), 100):
            self._batch_geo_lookup(ips[i:i + 100])
        self._run_match_loop(matches)

    def run_matches(self, matches):
        # Batch geo lookup for IPs not already cached (e.g. loaded from JSON)
        uncached = [ip for ip, _port in matches if ip not in self._geo_cache]
        if uncached:
            _vulncam_logger.info('Fetching geo data for %d IPs...', len(uncached))
            for i in range(0, len(uncached), 100):
                self._batch_geo_lookup(uncached[i:i + 100])
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
            if self.check_only:
                cmd = [mpv_path,
                       '--vo=null', '--ao=null',
                       '--end=%d' % self.probe_seconds,
                       '--really-quiet', '--no-terminal', '--force-window=no',
                       'rtsp://%s:%d' % match]
            elif self.generate_mosaic:
                thumb_dir = os.path.join(
                    self.thumb_base_dir or '', f'{match[0]}_{match[1]}')
                os.makedirs(thumb_dir, exist_ok=True)
                thumb_file_path = os.path.join(thumb_dir, 'thumb.png')
                cmd = [mpv_path, f'rtsp://{match[0]}:{match[1]}',
                       f'-o={thumb_file_path}', '--ovc=png', '--frames=1',
                       '--really-quiet', '--no-terminal',
                       f'--end={self.thumb_timeout}']
            elif self.stream_record:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                mkv_file = '%s_%d.mkv' % (ts, idx + 1)
                cmd = [mpv_path, f'--title={title}',
                       f'--stream-record={mkv_file}',
                       'rtsp://%s:%d' % match, '--mute=yes']
            else:
                cmd = [mpv_path, f'--title={title}',
                       'rtsp://%s:%d' % match, '--mute=yes']
            if not self.check_only and not self.generate_mosaic \
                    and sys.platform == 'linux':
                cmd.append('--gpu-context=x11egl')
            popen_env = None
            if self.generate_mosaic and sys.platform == 'linux':
                popen_env = os.environ.copy()
                popen_env.pop('DISPLAY', None)
                popen_env.pop('WAYLAND_DISPLAY', None)
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
            }
            time.sleep(0.2)
            self._check_working()  # detect new PID immediately → on_stream_added

        if self.signal_received:
            return
        if not self.check_only and not self.generate_mosaic and self.leave_windows:
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
    window_opened       = pyqtSignal(int)             # pid

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


class VulnCamWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._lang = 'en'
        self.worker = None
        self._shodan_info = None   # cached result of api.info(); refreshed on key change
        self._stream_items = {}    # (ip, port) → QListWidgetItem
        self._mosaic_cells = {}    # (ip, port) → MosaicCell
        self._audio_probes  = {}   # (ip, port) → AudioProbeTask.Signals
        self._worker_refs   = []   # keep-alive: holds Python refs to workers until finished
        self._live_mpv_pids = set()
        self._live_mpv_timer = QTimer(self)
        self._live_mpv_timer.setInterval(1000)
        self._live_mpv_timer.timeout.connect(self._poll_live_mpv)
        self._search_start_time = 0.0
        self._running_source = None   # 'shodan' | 'connect_all' | 'connect_selected'
        self._last_stats = (0, 0)
        self._reconnect_pids = set()
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
        self._live_mpv_timer.stop()
        self._live_mpv_pids.clear()
        self._thumb_manager.stop()
        QThreadPool.globalInstance().waitForDone(4000)
        self._audio_probes.clear()
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
        pb_num_row.addStretch()
        self._stats_label = QLabel()
        pb_num_row.addWidget(self._stats_label)
        pb_layout.addLayout(pb_num_row)
        self.max_proc_spin.valueChanged.connect(lambda _: self._refresh_stats_label())

        pb_check_row = QHBoxLayout()
        self.record_check = QCheckBox()
        self.leave_check  = QCheckBox()
        for w in (self.record_check, self.leave_check):
            pb_check_row.addWidget(w)
        pb_check_row.addStretch()
        pb_layout.addLayout(pb_check_row)

        pb_scan_row = QHBoxLayout()
        self._check_only_check = QCheckBox()
        pb_scan_row.addWidget(self._check_only_check)
        pb_scan_row.addSpacing(8)
        self._label_probe = QLabel()
        pb_scan_row.addWidget(self._label_probe)
        self._probe_spin = QSpinBox()
        self._probe_spin.setRange(5, 60)
        self._probe_spin.setValue(PROBE_DEFAULT)
        self._probe_spin.setEnabled(True)
        pb_scan_row.addWidget(self._probe_spin)
        pb_scan_row.addStretch()
        self._label_thumb_timeout = QLabel()
        pb_scan_row.addWidget(self._label_thumb_timeout)
        self._thumb_timeout_spin = QSpinBox()
        self._thumb_timeout_spin.setRange(5, 60)
        self._thumb_timeout_spin.setValue(DEFAULT_TIMEOUT)
        pb_scan_row.addWidget(self._thumb_timeout_spin)
        self._check_only_check.setChecked(True)
        self._check_only_check.toggled.connect(self._probe_spin.setEnabled)
        self._check_only_check.toggled.connect(self._label_probe.setEnabled)
        pb_layout.addLayout(pb_scan_row)


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

        self._streams_group = QGroupBox()
        sg_layout = QVBoxLayout(self._streams_group)

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
        self._filter_combo.addItem('', 'failed')
        self._filter_combo.addItem('', 'launching')
        self._filter_combo.setCurrentIndex(1)
        self._filter_combo.currentIndexChanged.connect(self._apply_filter)
        view_row.addWidget(self._filter_combo)
        view_row.addStretch()
        self._count_label = QLabel()
        view_row.addWidget(self._count_label)
        sg_layout.addLayout(view_row)
        self._view_btn_group.buttonToggled.connect(self._on_view_mode_changed)

        # Row 1: data management actions
        actions_row1 = QHBoxLayout()
        self._discard_check = QCheckBox()
        self._discard_check.setChecked(False)
        actions_row1.addWidget(self._discard_check)
        actions_row1.addStretch()
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
            actions_row1.addWidget(w)
        sg_layout.addLayout(actions_row1)

        # Row 2: connection actions
        actions_row2 = QHBoxLayout()
        self._connect_btn = QPushButton()
        self._connect_btn.clicked.connect(self._on_connect_btn_clicked)
        self._connect_selected_btn = QPushButton()
        self._connect_selected_btn.clicked.connect(self._on_connect_selected_clicked)
        self._scan_btn = QPushButton()
        self._scan_btn.setVisible(False)
        self._scan_btn.clicked.connect(self._on_scan_btn_clicked)
        self._scan_selected_btn = QPushButton()
        self._scan_selected_btn.setVisible(False)
        self._scan_selected_btn.clicked.connect(self._on_scan_selected_btn_clicked)
        for w in (self._connect_btn, self._connect_selected_btn,
                  self._scan_btn, self._scan_selected_btn):
            actions_row2.addWidget(w)
        actions_row2.addStretch()
        sg_layout.addLayout(actions_row2)

        self._streams_list = QListWidget()
        self._streams_list.setFont(QFont('Monospace', 8))
        self._streams_list.setWordWrap(True)
        self._streams_list.setSelectionMode(
            QListWidget.SelectionMode.ExtendedSelection)
        self._streams_list.itemDoubleClicked.connect(self._on_stream_double_clicked)
        self._streams_list.installEventFilter(self)
        sg_layout.addWidget(self._streams_list)

        self._mosaic_grid = MosaicGrid()
        self._mosaic_grid.cell_double_clicked.connect(
            self._on_mosaic_cell_double_clicked)
        self._mosaic_grid.setVisible(False)
        self._mosaic_grid.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._mosaic_grid.installEventFilter(self)
        sg_layout.addWidget(self._mosaic_grid)

        rl.addWidget(self._playback_group)
        rl.addWidget(self._streams_group)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([600, 600])
        root.addWidget(splitter)

        self._retranslate()

    def _retranslate(self):
        t = TRANSLATIONS[self._lang]
        self.setWindowTitle(t['window_title'])
        self._lang_label.setText(t['label_language'])
        self._cfg_group.setTitle(t['group_config'])
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
        self.record_check.setText(t['check_record'])
        self.leave_check.setText(t['check_leave'])
        self._check_only_check.setText(t['check_only'])
        self._label_probe.setText(t['label_probe'])
        self._label_thumb_timeout.setText(t['label_thumb_timeout'])
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
        self._streams_group.setTitle(t['group_streams'])
        self._label_filter.setText(t['label_filter'])
        self._filter_combo.setItemText(0, t['filter_all'])
        self._filter_combo.setItemText(1, t['filter_working'])
        self._filter_combo.setItemText(2, t['filter_working_av'])
        self._filter_combo.setItemText(3, t['filter_failed'])
        self._filter_combo.setItemText(4, t['filter_launching'])
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
        self.record_check.setChecked(False)
        self.leave_check.setChecked(False)
        self.allres_check.setChecked(False)
        self._dedup_check.setChecked(True)
        self._check_only_check.setChecked(True)
        self._probe_spin.setValue(PROBE_DEFAULT)
        self._thumb_timeout_spin.setValue(DEFAULT_TIMEOUT)
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
            item.setForeground(_COLOR_LAUNCHING)
            item.setData(Qt.ItemDataRole.UserRole, (ip, port, title))
            item.setHidden(False)
        else:
            item = QListWidgetItem('⬤ ' + title)
            item.setForeground(_COLOR_LAUNCHING)
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
            if self._mosaic_radio.isChecked() and self._running_source is None:
                mpv = self.mpv_path.text().strip()
                if mpv:
                    self._thumb_manager.add(ip, port, mpv, self._thumb_timeout_spin.value())
        elif key and key in self._mosaic_cells:
            regenerating = self._running_source in ('shodan', 'scan_all', 'scan_selected')
            if regenerating:
                self._mosaic_cells[key].reset(keep_thumbnail=False)
            else:
                # Live connection (connect_all / connect_selected): keep thumbnail
                # and current status — only clear the audio badge so it re-probes
                cell = self._mosaic_cells[key]
                cell._thumb_retries = 0
                cell.set_audio_type(None)

        self._apply_filter()
        if not item.isHidden():
            self._streams_list.scrollToItem(item)

    def _on_stream_status(self, title, status):
        ip, port = self._parse_ip_port(title)
        if ip is None:
            return
        key = (ip, port)
        item = self._stream_items.get(key)
        if item:
            if status == 'failed' and self._discard_check.isChecked():
                self._remove_stream(key, item)
                self._update_count()
                return
            item.setForeground(_COLOR_WORKING if status == 'working' else _COLOR_FAILED)
            self._apply_filter()
        cell = self._mosaic_cells.get((ip, port))
        if cell and not cell.has_thumbnail():
            mosaic_run_active = (self._mosaic_radio.isChecked()
                                 and self._running_source is not None)
            if status == 'failed' and self._mosaic_radio.isChecked() \
                    and not mosaic_run_active:
                # Worker reported failure → retry via ThumbnailManager
                self._retry_or_fail_thumbnail(ip, port, cell)
            elif status == 'working' and self._mosaic_radio.isChecked() \
                    and self._running_source is None:
                # Stream confirmed working with no active run (e.g. double-click) →
                # now safe to capture thumbnail (no competing MPV window process)
                cell.set_status(status)
                mpv = self.mpv_path.text().strip()
                if mpv:
                    self._thumb_manager.add(ip, port, mpv, self._thumb_timeout_spin.value())
            else:
                cell.set_status(status)
        if status == 'working':
            self._launch_audio_probe(ip, port)

    def _launch_audio_probe(self, ip, port):
        key = (ip, port)
        if key in self._audio_probes:
            return
        task = AudioProbeTask(ip, port)
        task.signals.done.connect(self._on_audio_probe_done)
        self._audio_probes[key] = task.signals   # keep Signals alive until done
        QThreadPool.globalInstance().start(task)

    @pyqtSlot(str, int, str)
    def _on_audio_probe_done(self, ip, port, result):
        key = (ip, port)
        self._audio_probes.pop(key, None)
        item = self._stream_items.get(key)
        if item:
            text = item.text()
            for badge in (' · V', ' · AV'):
                text = text.replace(badge, '')
            item.setText(text + f' · {result}')
            self._apply_filter()
        cell = self._mosaic_cells.get(key)
        if cell:
            cell.set_audio_type(result)

    def _on_stream_double_clicked(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        ip, port, title = data
        mpv_path = self.mpv_path.text().strip()
        if not mpv_path:
            QMessageBox.warning(self, self._t('dlg_mpv_err_title'),
                                self._t('dlg_mpv_no_path'))
            return
        prev_color = item.foreground().color()
        cmd = [mpv_path, f'--title={title}']
        if self.record_check.isChecked():
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            cmd.append(f'--stream-record={ts}_{ip}_{port}.mkv')
        cmd += [f'rtsp://{ip}:{port}', '--mute=yes']
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
        item.setForeground(_COLOR_LAUNCHING)
        self._append_log(self._t('log_reconnect').format(title))
        self._reconnect_pids.add(proc.pid)
        self._refresh_stats_label()
        self._watch_reconnect(title, ip, port, proc.pid)

    def _watch_reconnect(self, title, ip, port, pid):
        """Poll for the MPV window every second until it appears or timeout expires."""
        start = time.time()

        def _finish(status):
            self._reconnect_pids.discard(pid)
            if status == 'working':
                self._add_live_mpv_pid(pid)
            self._refresh_stats_label()
            self._on_stream_status(title, status)

        def check():
            try:
                psutil.Process(pid)
            except psutil.NoSuchProcess:
                timer.stop()
                _finish('failed')
                return
            if title in _get_open_windows():
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
            'working':    _COLOR_WORKING,
            'working_av': _COLOR_WORKING,
            'failed':     _COLOR_FAILED,
            'launching':  _COLOR_LAUNCHING,
        }
        target = color_map.get(fval)
        for i in range(self._streams_list.count()):
            item = self._streams_list.item(i)
            if fval == 'all':
                hidden = False
            elif fval == 'working_av':
                hidden = not (item.foreground().color() == _COLOR_WORKING
                              and ' · AV' in item.text())
            else:
                hidden = bool(target and item.foreground().color() != target)
            item.setHidden(hidden)
            data = item.data(Qt.ItemDataRole.UserRole)
            if data:
                ip, port, _ = data
                self._mosaic_grid.set_cell_visible(ip, port, not hidden)
        self._update_count()

    def _visible_items(self):
        """Returns list of (key, item) for currently visible stream items."""
        return [(k, v) for k, v in self._stream_items.items() if not v.isHidden()]

    def _remove_stream(self, key, item):
        """Remove a stream from list, mosaic and stream_items dict."""
        self._audio_probes.pop(key, None)
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
            if item.foreground().color() == _COLOR_FAILED:
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
            entry = {'ip': ip, 'port': port, 'title': item.text()[2:]}
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
        audio_map = {}   # key → audio type, for applying badges after sync
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
                display = '⬤ ' + title + (f' · {audio}' if audio else '')
                item = QListWidgetItem(display)
                item.setForeground(_COLOR_IDLE)
                item.setData(Qt.ItemDataRole.UserRole, (ip, int(port), title))
                self._stream_items[key] = item
                self._streams_list.addItem(item)
                if audio:
                    audio_map[key] = audio
                added += 1
        if errors:
            QMessageBox.warning(self, self._t('dlg_load_err_title'),
                                self._t('dlg_load_err').format('\n'.join(errors)))
        if self._mosaic_radio.isChecked():
            self._sync_mosaic_cells()
        for key, audio in audio_map.items():
            cell = self._mosaic_cells.get(key)
            if cell:
                cell.set_audio_type(audio)
        self._filter_combo.setCurrentIndex(0)  # reset to All so loaded streams are visible
        self._apply_filter()
        self._append_log(self._t('log_load_summary').format(added, skipped, len(paths)))

    def _connect_all(self):
        visible = self._visible_items()
        if not visible:
            return
        if not self._ensure_mpv_path():
            return
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return

        for _, item in visible:
            item.setForeground(_COLOR_LAUNCHING)

        matches = [key for key, _ in visible]
        args = Namespace(
            random_pages  = False,
            leave_windows = self.leave_check.isChecked(),
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            stream_record = self.record_check.isChecked(),
            check_only    = self._check_only_check.isChecked() and self._list_radio.isChecked(),
            probe_seconds = self._probe_spin.value(),
            generate_mosaic  = False,
            thumb_timeout    = self._thumb_timeout_spin.value(),
            verbose          = False,
        )
        self._running_source = 'connect_all'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    # ── Run control ───────────────────────────────────────────────────────────

    def _set_running(self, running):
        t = TRANSLATIONS[self._lang]
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running and self._running_source == 'shodan')
        if self._running_source == 'connect_all':
            self._connect_btn.setText(
                t['btn_stop_connect'] if running else t['btn_connect_all'])
            self._connect_btn.setEnabled(True)
            self._connect_selected_btn.setEnabled(not running)
            self._scan_btn.setEnabled(not running)
            self._scan_selected_btn.setEnabled(not running)
        elif self._running_source == 'connect_selected':
            self._connect_selected_btn.setText(
                t['btn_stop_connect'] if running else t['btn_connect_selected'])
            self._connect_selected_btn.setEnabled(True)
            self._connect_btn.setEnabled(not running)
            self._scan_btn.setEnabled(not running)
            self._scan_selected_btn.setEnabled(not running)
        elif self._running_source == 'scan_all':
            self._scan_btn.setText(
                t['btn_stop_connect'] if running else t['btn_scan'])
            self._scan_btn.setEnabled(True)
            self._connect_btn.setEnabled(not running)
            self._connect_selected_btn.setEnabled(not running)
            self._scan_selected_btn.setEnabled(not running)
        elif self._running_source == 'scan_selected':
            self._scan_selected_btn.setText(
                t['btn_stop_connect'] if running else t['btn_scan_selected'])
            self._scan_selected_btn.setEnabled(True)
            self._connect_btn.setEnabled(not running)
            self._connect_selected_btn.setEnabled(not running)
            self._scan_btn.setEnabled(not running)
        else:
            self._connect_btn.setEnabled(not running)
            self._connect_selected_btn.setEnabled(not running)
            self._scan_btn.setEnabled(not running)
            self._scan_selected_btn.setEnabled(not running)
        self._clear_btn.setEnabled(not running)
        self._clear_failed_btn.setEnabled(not running)
        self._load_streams_btn.setEnabled(not running)
        self._save_streams_btn.setEnabled(not running)
        self._list_radio.setEnabled(not running)
        self._mosaic_radio.setEnabled(not running)
        self.record_check.setEnabled(not running)
        self._check_only_check.setEnabled(not running and self._list_radio.isChecked())

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
        """Generate thumbnails for all visible streams in mosaic mode."""
        visible = self._visible_items()
        if not visible:
            return
        if not self._ensure_mpv_path():
            return
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return
        for _, item in visible:
            item.setForeground(_COLOR_LAUNCHING)
        matches = [key for key, _ in visible]
        args = Namespace(
            random_pages  = False,
            leave_windows = False,
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            stream_record = False,
            check_only    = False,
            probe_seconds = self._probe_spin.value(),
            generate_mosaic = True,
            thumb_timeout   = self._thumb_timeout_spin.value(),
            verbose         = False,
        )
        self._running_source = 'scan_all'
        self.log_view.clear()
        self._start_worker(config, args, matches=matches)

    def _scan_selected(self):
        """Generate thumbnails for selected streams in mosaic mode."""
        selected_keys = self._mosaic_grid.selected_keys()
        if not selected_keys:
            return
        if not self._ensure_mpv_path():
            return
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return
        matches = []
        for ip, port in selected_keys:
            item = self._stream_items.get((ip, port))
            if item:
                item.setForeground(_COLOR_LAUNCHING)
                matches.append((ip, port))
        if not matches:
            return
        args = Namespace(
            random_pages  = False,
            leave_windows = False,
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            stream_record = False,
            check_only    = False,
            probe_seconds = self._probe_spin.value(),
            generate_mosaic = True,
            thumb_timeout   = self._thumb_timeout_spin.value(),
            verbose         = False,
        )
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
        # Get selection from the active view (list or mosaic)
        if self._mosaic_radio.isChecked():
            selected_keys = self._mosaic_grid.selected_keys()
            if not selected_keys:
                return
        else:
            selected_items = self._streams_list.selectedItems()
            if not selected_items:
                return
            selected_keys = []
            for item in selected_items:
                data = item.data(Qt.ItemDataRole.UserRole)
                if data:
                    selected_keys.append((data[0], data[1]))
        if not selected_keys:
            return
        if not self._ensure_mpv_path():
            return
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return
        matches = []
        for ip, port in selected_keys:
            item = self._stream_items.get((ip, port))
            if item:
                ip_d, port_d, _ = item.data(Qt.ItemDataRole.UserRole)
                matches.append((ip_d, port_d))
                item.setForeground(_COLOR_LAUNCHING)
        if not matches:
            return
        self._apply_filter()
        args = Namespace(
            random_pages  = False,
            leave_windows = self.leave_check.isChecked(),
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            stream_record = self.record_check.isChecked(),
            check_only    = self._check_only_check.isChecked() and self._list_radio.isChecked(),
            probe_seconds = self._probe_spin.value(),
            generate_mosaic  = False,
            thumb_timeout    = self._thumb_timeout_spin.value(),
            verbose          = False,
        )
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

    def _poll_live_mpv(self):
        """Remove PIDs of closed MPV windows and refresh the counter."""
        dead = set()
        for pid in self._live_mpv_pids:
            try:
                p = psutil.Process(pid)
                if p.status() == psutil.STATUS_ZOMBIE:
                    dead.add(pid)
            except psutil.NoSuchProcess:
                dead.add(pid)
        if dead:
            self._live_mpv_pids -= dead
            self._refresh_stats_label()
        if not self._live_mpv_pids:
            self._live_mpv_timer.stop()

    def _add_live_mpv_pid(self, pid):
        self._live_mpv_pids.add(pid)
        self._live_mpv_timer.start()
        self._refresh_stats_label()

    @pyqtSlot(int)
    def _on_worker_window_opened(self, pid):
        self._add_live_mpv_pid(pid)

    def _on_view_mode_changed(self, _btn, checked):
        if not checked:
            return
        mosaic = self._mosaic_radio.isChecked()
        self._streams_list.setVisible(not mosaic)
        self._mosaic_grid.setVisible(mosaic)
        self._scan_btn.setVisible(mosaic)
        self._scan_selected_btn.setVisible(mosaic)
        self._thumb_size_combo.setVisible(mosaic)
        # Check Only is incompatible with mosaic (thumbnail capture acts as the check)
        self._check_only_check.setEnabled(not mosaic)
        self._probe_spin.setEnabled(not mosaic and self._check_only_check.isChecked())
        self._label_probe.setEnabled(not mosaic and self._check_only_check.isChecked())
        if mosaic:
            self._sync_mosaic_cells()

    def _on_thumb_size_changed(self, _index):
        w, h = self._thumb_size_combo.currentData()
        self._mosaic_grid.set_thumb_size(w, h)

    def _retry_or_fail_thumbnail(self, ip, port, cell):
        """Re-queue thumbnail generation or mark as failed if retries exhausted."""
        if cell.has_thumbnail():
            return   # already have one, nothing to do
        mpv = self.mpv_path.text().strip()
        if mpv and cell._thumb_retries < MAX_THUMB_RETRIES:
            cell._thumb_retries += 1
            cell.set_status('launching')   # back to orange while retrying
            self._thumb_manager.add(ip, port, mpv, self._thumb_timeout_spin.value())
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
        thumb_dir = self._temp_dir if getattr(args, 'generate_mosaic', False) else None
        w = VulnCamWorker(config, args, matches=matches, skip_fn=skip_fn,
                          max_procs_ref=max_procs_ref, thumb_base_dir=thumb_dir)
        self.worker = w
        self._worker_refs.append(w)   # keep Python reference alive until finished

        def _worker_cleanup():
            try:
                self._worker_refs.remove(w)
            except ValueError:
                pass
            if self.worker is w:
                self.worker = None
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
        if not self._ensure_mpv_path():
            return
        config = self._build_config()
        if not check_config(config):
            QMessageBox.critical(self, self._t('dlg_cfg_err_title'),
                                 self._t('dlg_cfg_err_msg'))
            return
        if sys.platform == 'linux' and not check_linux_software():
            QMessageBox.critical(self, self._t('dlg_sw_err_title'),
                                 self._t('dlg_sw_err_msg'))
            return
        args = Namespace(
            query         = self.query_field.text().strip() or DEFAULT_QUERY,
            extend        = self.extend_field.text().strip(),
            pages         = self.pages_spin.value(),
            max_processes = self.max_proc_spin.value(),
            max_windows   = 9999,
            random_pages  = self.random_check.isChecked(),
            stream_record = self.record_check.isChecked(),
            leave_windows = self.leave_check.isChecked(),
            total_results = self.allres_check.isChecked(),
            check_only       = self._check_only_check.isChecked() and self._list_radio.isChecked(),
            probe_seconds    = self._probe_spin.value(),
            generate_mosaic  = self._mosaic_radio.isChecked(),
            thumb_timeout    = self._thumb_timeout_spin.value(),
            verbose          = False,
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
            if item.foreground().color() == _COLOR_LAUNCHING:
                item.setForeground(_COLOR_FAILED)
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


def _qt_message_handler(mode, context, message):
    """Forward Qt warnings/errors to stderr so they appear in the terminal."""
    import traceback
    levels = {0: 'Qt[Debug]', 1: 'Qt[Warning]', 2: 'Qt[Critical]',
              3: 'Qt[Fatal]', 4: 'Qt[Info]'}
    print(f'{levels.get(mode, "Qt[?]")}: {message}', file=sys.stderr)


def main():
    import base64
    from PyQt6.QtCore import qInstallMessageHandler
    import traceback

    def _excepthook(exc_type, exc_value, exc_tb):
        msg = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb))
        print(msg, file=sys.stderr)
        try:
            with open('/tmp/vulncam_crash.log', 'a') as f:
                f.write(msg + '\n')
        except Exception:
            pass

    sys.excepthook = _excepthook
    qInstallMessageHandler(_qt_message_handler)

    app = QApplication(sys.argv)
    app.setApplicationName('VulnCam')
    app.setDesktopFileName('vulncam')
    pixmap = QPixmap()
    pixmap.loadFromData(base64.b64decode(_APP_ICON_B64))
    icon = QIcon(pixmap)
    app.setWindowIcon(icon)
    window = VulnCamWindow()
    window.setWindowIcon(icon)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
