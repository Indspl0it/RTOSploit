"""Coverage visualization and analysis for RTOSploit.

Provides tools for reading AFL-style coverage bitmaps, mapping coverage
to firmware addresses, and visualizing heatmaps in terminal and HTML.
"""

from rtosploit.coverage.bitmap_reader import BitmapReader, CoverageMap, BITMAP_SIZE
from rtosploit.coverage.mapper import CoverageMapper
from rtosploit.coverage.visualizer import CoverageVisualizer

__all__ = [
    "BitmapReader",
    "CoverageMap",
    "CoverageMapper",
    "CoverageVisualizer",
    "BITMAP_SIZE",
]
