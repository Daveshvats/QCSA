"""v5.9: Supports real graphics in terminals that implement inline-image protocols:
  - Kitty graphics protocol (Kitty, Ghostty)
  - iTerm2 inline-image protocol (iTerm2, WezTerm, VS Code)
  - Sixel (xterm with Sixel, Windows Terminal)
  - ASCII fallback (plain console, CI logs, piped output)

v5.10: Added Windows Terminal (Sixel) support via WT_SESSION detection.
"""
from __future__ import annotations

import base64
import io
import os
import sys
import zlib
import threading
import time
from pathlib import Path
from typing import Optional, List, Tuple

# Lazy import PIL only when needed (asset loading)
_PIL_AVAILABLE = None


def _check_pil() -> bool:
    global _PIL_AVAILABLE
    if _PIL_AVAILABLE is None:
        try:
            from PIL import Image  # noqa: F401
            _PIL_AVAILABLE = True
        except ImportError:
            _PIL_AVAILABLE = False
    return _PIL_AVAILABLE


def detect_terminal_protocol() -> str:
    """Detect the terminal's inline-image protocol."""
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    term = os.environ.get("TERM", "").lower()
    wt_session = os.environ.get("WT_SESSION")
    
    # Windows Terminal (supports Sixel in recent versions)
    if wt_session is not None:
        return "sixel"
        
    if "kitty" in term or "ghostty" in term_program:
        return "kitty"
    if term_program in ("iterm.app", "wezterm", "vscode"):
        return "iterm2"
    if "sixel" in term:
        return "sixel"
    
    return "ascii"


def is_image_supported() -> bool:
    """Check if the current terminal supports inline images."""
    return detect_terminal_protocol() != "ascii"


# ============================================================================
# Kitty Graphics Protocol
# ============================================================================

def _kitty_encode_image(image_path: str, width: int = 0, height: int = 0) -> str:
    """Encode an image for the Kitty graphics protocol."""
    with open(image_path, "rb") as f:
        data = f.read()
    
    # Base64 encode the image data
    b64 = base64.b64encode(data).decode("ascii")
    
    # Split into chunks of 4096 bytes (Kitty limit)
    chunks = [b64[i:i+4096] for i in range(0, len(b64), 4096)]
    
    # Build the escape sequence
    # f=100 (transmit data), t=d (direct), i=1 (image id)
    parts = []
    for i, chunk in enumerate(chunks):
        if i == 0:
            # First chunk: include image dimensions
            args = "f=100,t=d,i=1"
            if width > 0:
                args += f",w={width}"
            if height > 0:
                args += f",h={height}"
            parts.append(f"\x1b_G{args};{chunk}\x1b\\")
        else:
            # Subsequent chunks
            if i == len(chunks) - 1:
                parts.append(f"\x1b_Gm=1;{chunk}\x1b\\")
            else:
                parts.append(f"\x1b_Gm=1;{chunk}\x1b\\")
    
    return "".join(parts)


def _kitty_clear_image() -> str:
    """Clear the Kitty image."""
    return "\x1b_Ga=d,d=i\x1b\\"


# ============================================================================
# iTerm2 Inline Image Protocol
# ============================================================================

def _iterm2_encode_image(image_path: str, width: Optional[int] = None,
                          height: Optional[int] = None) -> str:
    """Encode an image for the iTerm2 inline image protocol."""
    with open(image_path, "rb") as f:
        data = f.read()
    
    b64 = base64.b64encode(data).decode("ascii")
    
    # Build the escape sequence
    args = ""
    if width is not None:
        args += f";width={width}px"
    if height is not None:
        args += f";height={height}px"
    
    return f"\x1b]1337;File=inline=1{name_with_size(data)}{args}:{b64}\x07"


def _iterm2_clear_image() -> str:
    """Clear the iTerm2 image (not standard, but we can try)."""
    return "\x1b]1337;File=inline=1;doNotClear=0:\x07"


def _name_with_size(data: bytes) -> str:
    """Build the name=...;size=... part of the iTerm2 sequence."""
    size = len(data)
    return f";size={size}"


# ============================================================================
# Sixel Protocol
# ============================================================================

def _sixel_encode_image(image_path: str) -> str:
    """Encode an image for the Sixel protocol."""
    if not _check_pil():
        return ""
    
    from PIL import Image
    
    try:
        img = Image.open(image_path)
        # Convert to P (palette) mode for Sixel
        if img.mode != "P":
            # Create a palette from the image
            img = img.convert("P", palette=Image.Palette.ADAPTIVE, colors=256)
        
        output = io.BytesIO()
        img.save(output, format="sixel")
        return output.getvalue().decode("ascii", errors="replace")
    except Exception:
        return ""


def _sixel_clear_image() -> str:
    """Clear the Sixel image."""
    return "\x1b[2J\x1b[H"


# ============================================================================
# Image Mascot Class
# ============================================================================

class ImageMascot:
    """Render the Loomy mascot using inline images when available."""
    
    def __init__(self, protocol: Optional[str] = None):
        self.protocol = protocol or detect_terminal_protocol()
        self._frames: List[str] = []
        self._frame_paths: List[Path] = []
        self._animation_thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._current_frame = 0
        
        # Load frames
        self._load_frames()
    
    def _load_frames(self) -> None:
        """Load PNG frames from assets/frames/ directory."""
        if self.protocol == "ascii":
            return
        
        frames_dir = Path(__file__).parent / "assets" / "frames"
        if not frames_dir.exists():
            return
        
        # Load all frame paths sorted
        frame_paths = sorted(frames_dir.glob("frame_*.png"))
        if not frame_paths:
            return
        
        self._frame_paths = frame_paths
        
        # Pre-encode frames for Kitty/iTerm2 (Sixel is encoded on-the-fly)
        if self.protocol in ("kitty", "iterm2"):
            for path in frame_paths:
                if self.protocol == "kitty":
                    encoded = _kitty_encode_image(str(path), width=20, height=10)
                else:
                    encoded = _iterm2_encode_image(str(path), width=20, height=10)
                self._frames.append(encoded)
    
    def say(self, phase: str = "init", message: str = "") -> None:
        """Show a static frame with a message."""
        if self.protocol == "ascii" or not self._frame_paths:
            return
        
        # Pick a frame based on phase
        if phase == "init":
            frame_idx = 0
        elif phase == "done":
            frame_idx = min(7, len(self._frame_paths) - 1)
        elif phase == "pass":
            frame_idx = min(7, len(self._frame_paths) - 1)
        elif phase == "warn":
            frame_idx = min(3, len(self._frame_paths) - 1)
        else:
            frame_idx = self._current_frame % len(self._frame_paths)
        
        self._render_frame(frame_idx)
        
        if message:
            print(f"\n  {message}")
    
    def start_animation(self, phase: str = "layers", message: str = "") -> None:
        """Start animated rendering in a background thread."""
        if self.protocol == "ascii" or not self._frame_paths:
            return
        
        self._stop_flag.clear()
        self._animation_thread = threading.Thread(
            target=self._animate, daemon=True
        )
        self._animation_thread.start()
    
    def stop_animation(self) -> None:
        """Stop the animation thread."""
        self._stop_flag.set()
        if self._animation_thread and self._animation_thread.is_alive():
            self._animation_thread.join(timeout=1.0)
        self._animation_thread = None
    
    def update_phase(self, phase: str, message: str = "") -> None:
        """Update the animation phase (no-op for image mode)."""
        pass
    
    def _animate(self) -> None:
        """Animation loop running in background thread."""
        frame_count = len(self._frame_paths)
        if frame_count == 0:
            return
        
        while not self._stop_flag.is_set():
            self._render_frame(self._current_frame)
            self._current_frame = (self._current_frame + 1) % frame_count
            time.sleep(0.12)  # 120ms per frame (same as original GIF)
    
    def _render_frame(self, idx: int) -> None:
        """Render a single frame."""
        if idx >= len(self._frame_paths):
            return
        
        if self.protocol == "kitty":
            if idx < len(self._frames):
                sys.stdout.write(self._frames[idx])
                sys.stdout.flush()
        elif self.protocol == "iterm2":
            if idx < len(self._frames):
                sys.stdout.write(self._frames[idx])
                sys.stdout.flush()
        elif self.protocol == "sixel":
            if not _check_pil():
                return
            encoded = _sixel_encode_image(str(self._frame_paths[idx]))
            if encoded:
                sys.stdout.write(f"\r{encoded}")
                sys.stdout.flush()


# ============================================================================
# Module-level convenience
# ============================================================================

_global_image_mascot: Optional[ImageMascot] = None


def get_image_mascot() -> Optional[ImageMascot]:
    """Get or create the global ImageMascot instance."""
    global _global_image_mascot
    if _global_image_mascot is None:
        protocol = detect_terminal_protocol()
        if protocol == "ascii":
            return None
        _global_image_mascot = ImageMascot(protocol=protocol)
    return _global_image_mascot