"""Constants shared between the mosaic widgets and the main window."""
from PyQt6.QtGui import QColor

COLOR_IDLE      = QColor('#707070')
COLOR_LAUNCHING = QColor('#E8A020')
COLOR_WORKING   = QColor('#20A050')
COLOR_FAILED    = QColor('#C03030')

THUMB_SIZES = [
    ('small',  160,  90),
    ('medium', 240, 135),
    ('large',  320, 180),
]
THUMB_W, THUMB_H = THUMB_SIZES[1][1:]   # 16:9 medium (default)
MAX_THUMB_RETRIES = 2
