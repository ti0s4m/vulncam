"""Mosaic view widgets: individual stream cells and the grid layout."""
import sys

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QFrame, QScrollArea, QGridLayout,
)
from PyQt6.QtCore import Qt, QTimer, QPoint, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPixmap, QPainter

from gui_constants import COLOR_LAUNCHING, COLOR_WORKING, COLOR_FAILED, THUMB_W, THUMB_H

# ── Mosaic view ───────────────────────────────────────────────────────────────

class MosaicCell(QFrame):
    double_clicked = pyqtSignal(str, int, str)   # ip, port, title
    clicked        = pyqtSignal(str, int)         # ip, port
    context_menu_requested = pyqtSignal(str, int, QPoint)   # ip, port, global pos

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
        self._placeholder_cache = {}   # (text, color, w, h) → QPixmap
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
        self._session_badge = QLabel(self._img_lbl)
        self._session_badge.setStyleSheet(
            'background: rgba(0,0,0,170); color: #ffcc00;'
            ' padding: 1px 4px; border-radius: 3px;'
            ' font-size: 9px; font-weight: bold;')
        self._session_badge.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._session_badge.setVisible(False)
        self._session_badge.move(4, 4)   # top-left; audio badge owns bottom-right
        self._title_lbl = QLabel()
        self._title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_lbl.setWordWrap(True)
        self._title_lbl.setFont(QFont('Monospace', 7))
        layout.addWidget(self._title_lbl)
        self._update_label(title)
        self._refresh()

    def _make_placeholder(self, text, color):
        key = (text, color.name(), self._thumb_w, self._thumb_h)
        cached = self._placeholder_cache.get(key)
        if cached is not None:
            return cached
        try:
            px = QPixmap(self._thumb_w, self._thumb_h)
            px.fill(QColor('#1a1a1a'))
            p = QPainter(px)
            p.setPen(color)
            p.setFont(QFont('Sans', 11, QFont.Weight.Bold))
            p.drawText(px.rect(), Qt.AlignmentFlag.AlignCenter, text)
            p.end()
        except Exception as e:
            print(f'MosaicCell._make_placeholder error: {e}', file=sys.stderr)
            px = QPixmap(self._thumb_w, self._thumb_h)
        self._placeholder_cache[key] = px
        return px

    def _refresh(self):
        if not self._has_thumbnail:
            if self._status == 'waiting':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._waiting_text, QColor('#606060')))
            elif self._status == 'launching':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._connect_text, COLOR_LAUNCHING))
            elif self._status == 'working':
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._working_text, COLOR_WORKING))
            else:
                self._img_lbl.setPixmap(
                    self._make_placeholder(self._no_signal_text, COLOR_FAILED))
        c = {'waiting': '#404040', 'launching': COLOR_LAUNCHING.name(),
             'working': COLOR_WORKING.name(), 'failed': COLOR_FAILED.name()}
        col = c.get(self._status, COLOR_LAUNCHING.name())
        bg = '#1e2a38' if self._selected else '#0d0d0d'
        border = '3px solid #ffffff' if self._selected else f'2px solid {col}'
        self.setStyleSheet(
            f'MosaicCell {{ border: {border}; border-radius: 4px;'
            f' background: {bg}; }}'
            f'QLabel {{ border: none; color: #dddddd; }}')

    def set_selected(self, selected):
        self._selected = selected
        self._refresh()

    def set_filter_hidden(self, hidden):
        self._filter_hidden = hidden

    def is_filter_hidden(self):
        return self._filter_hidden

    def retries(self):
        return self._thumb_retries

    def bump_retries(self):
        self._thumb_retries += 1

    def reset_retries(self):
        self._thumb_retries = 0

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

    def set_session_badge(self, text):
        """Show a short play/record-state tag (e.g. 'PLAY', 'REC', 'SAVED') top-left,
        or hide it when text is None."""
        if not text:
            self._session_badge.setVisible(False)
            return
        self._session_badge.setText(text)
        self._session_badge.adjustSize()
        self._session_badge.setVisible(True)
        self._session_badge.raise_()

    def resize_thumb(self, w, h):
        self._placeholder_cache.clear()   # cached placeholders are size-specific
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
        self._session_badge.setVisible(False)
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
        elif event.button() == Qt.MouseButton.RightButton:
            self.context_menu_requested.emit(
                self._ip, self._port, event.globalPosition().toPoint())
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        self.double_clicked.emit(self._ip, self._port, self._title)
        super().mouseDoubleClickEvent(event)


class MosaicGrid(QScrollArea):
    cell_double_clicked = pyqtSignal(str, int, str)
    cell_context_menu_requested = pyqtSignal(str, int, QPoint)
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
        cell.context_menu_requested.connect(self.cell_context_menu_requested)
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

    def select_only(self, ip, port):
        """Select exactly this cell, deselecting everything else (right-click UX)."""
        key = (ip, port)
        for k, c in self._cells.items():
            c.set_selected(k == key)
        self._selected = {key}
        self.selection_changed.emit()

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
            cell.set_filter_hidden(not visible)
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
                if not cell.is_filter_hidden():
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

