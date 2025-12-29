"""Simulated waveform animation for voice calls"""

import asyncio
import random
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.text import Text


# Unicode block characters for waveform visualization
BLOCKS = " ▁▂▃▄▅▆▇█"


class WaveformDisplay:
    """Animated waveform display for active calls"""

    def __init__(self, width: int = 32, console: Optional[Console] = None):
        self.width = width
        self.console = console or Console()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._live: Optional[Live] = None
        self._values = [0.0] * width

    def _generate_value(self) -> float:
        """Generate a random waveform value with smooth transitions"""
        # Tend toward middle values with occasional peaks
        if random.random() < 0.1:
            return random.uniform(0.6, 1.0)  # Occasional peak
        return random.uniform(0.1, 0.5)

    def _shift_and_add(self):
        """Shift values left and add new value on right"""
        self._values = self._values[1:] + [self._generate_value()]

    def _render(self) -> Text:
        """Render current waveform as Text"""
        text = Text()
        text.append("📞 ", style="bold yellow")
        
        for val in self._values:
            idx = int(val * (len(BLOCKS) - 1))
            idx = max(0, min(idx, len(BLOCKS) - 1))
            text.append(BLOCKS[idx], style="green")
        
        text.append(" 📞", style="bold yellow")
        return text

    async def _animate(self):
        """Animation loop"""
        try:
            while self._running:
                self._shift_and_add()
                if self._live:
                    self._live.update(self._render())
                await asyncio.sleep(0.08)  # ~12 fps
        except asyncio.CancelledError:
            pass

    async def start(self):
        """Start the waveform animation"""
        if self._running:
            return

        self._running = True
        self._values = [random.uniform(0.1, 0.4) for _ in range(self.width)]
        
        self._live = Live(
            self._render(),
            console=self.console,
            refresh_per_second=12,
            transient=True,
        )
        self._live.start()
        self._task = asyncio.create_task(self._animate())

    async def stop(self):
        """Stop the waveform animation"""
        self._running = False
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        if self._live:
            self._live.stop()
            self._live = None
