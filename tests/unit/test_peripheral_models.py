"""Unit tests for built-in peripheral models."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from rtosploit.peripherals.model import CPUState, HandlerResult
from rtosploit.peripherals.models.generic import (
    LogAndReturn,
    ReturnValue,
    ReturnZero,
)
from rtosploit.peripherals.models.stm32_hal import (
    HAL_OK,
    HAL_ERROR,
    STM32Flash,
    STM32GPIO,
    STM32HALBase,
    STM32I2C,
    STM32RCC,
    STM32SPI,
    STM32Timer,
    STM32UART,
)


def _cpu(r0=0, r1=0, r2=0, r3=0, gdb=None):
    """Create a CPUState with given argument registers."""
    regs = {"r0": r0, "r1": r1, "r2": r2, "r3": r3, "sp": 0x20008000, "lr": 0x08001001}
    return CPUState(regs=regs, _gdb=gdb)


# ---------------------------------------------------------------------------
# Generic models
# ---------------------------------------------------------------------------

class TestReturnZero:
    def test_returns_zero(self):
        m = ReturnZero("rz", 0, 0)
        result = m.intercept_any(_cpu())
        assert result.intercept is True
        assert result.return_value == 0


class TestReturnValue:
    def test_returns_configured_value(self):
        m = ReturnValue("rv", 0, 0, value=42)
        handler = m._find_handler("__return_value__")
        result = handler(_cpu())
        assert result.return_value == 42


class TestLogAndReturn:
    def test_returns_zero(self):
        m = LogAndReturn("log", 0, 0)
        handler = m._find_handler("__log_and_return__")
        result = handler(_cpu(r0=1, r1=2, r2=3, r3=4))
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# STM32 HAL Base
# ---------------------------------------------------------------------------

class TestSTM32HALBase:
    def test_hal_init(self):
        m = STM32HALBase()
        handler = m._find_handler("HAL_Init")
        result = handler(_cpu())
        assert result.return_value == HAL_OK

    def test_hal_get_tick(self):
        m = STM32HALBase()
        handler = m._find_handler("HAL_GetTick")
        result = handler(_cpu())
        assert isinstance(result.return_value, int)
        assert result.return_value >= 0

    def test_hal_delay_skipped(self):
        m = STM32HALBase()
        handler = m._find_handler("HAL_Delay")
        result = handler(_cpu(r0=1000))
        assert result.intercept is True
        assert result.return_value is None  # void

    def test_hal_inc_tick(self):
        m = STM32HALBase()
        handler = m._find_handler("HAL_IncTick")
        result = handler(_cpu())
        assert result.return_value is None


# ---------------------------------------------------------------------------
# STM32 RCC
# ---------------------------------------------------------------------------

class TestSTM32RCC:
    def test_osc_config(self):
        m = STM32RCC()
        result = m._find_handler("HAL_RCC_OscConfig")(_cpu())
        assert result.return_value == HAL_OK

    def test_clock_config(self):
        m = STM32RCC()
        result = m._find_handler("HAL_RCC_ClockConfig")(_cpu())
        assert result.return_value == HAL_OK

    def test_get_sysclk(self):
        m = STM32RCC()
        result = m._find_handler("HAL_RCC_GetSysClockFreq")(_cpu())
        assert result.return_value == 72_000_000

    def test_get_pclk1(self):
        m = STM32RCC()
        result = m._find_handler("HAL_RCC_GetPCLK1Freq")(_cpu())
        assert result.return_value == 36_000_000


# ---------------------------------------------------------------------------
# STM32 GPIO
# ---------------------------------------------------------------------------

class TestSTM32GPIO:
    def test_init(self):
        m = STM32GPIO()
        result = m._find_handler("HAL_GPIO_Init")(_cpu())
        assert result.return_value is None  # void

    def test_write_and_read_pin(self):
        gdb = MagicMock()
        m = STM32GPIO()
        # Write pin 0x01 = SET
        m._find_handler("HAL_GPIO_WritePin")(_cpu(r1=0x01, r2=1, gdb=gdb))
        # Read pin 0x01
        result = m._find_handler("HAL_GPIO_ReadPin")(_cpu(r1=0x01, gdb=gdb))
        assert result.return_value == 1

    def test_read_unset_pin(self):
        m = STM32GPIO()
        result = m._find_handler("HAL_GPIO_ReadPin")(_cpu(r1=0x04))
        assert result.return_value == 0

    def test_toggle_pin(self):
        m = STM32GPIO()
        m._find_handler("HAL_GPIO_WritePin")(_cpu(r1=0x02, r2=1))
        m._find_handler("HAL_GPIO_TogglePin")(_cpu(r1=0x02))
        result = m._find_handler("HAL_GPIO_ReadPin")(_cpu(r1=0x02))
        assert result.return_value == 0  # toggled off


# ---------------------------------------------------------------------------
# STM32 UART
# ---------------------------------------------------------------------------

class TestSTM32UART:
    def test_init(self):
        m = STM32UART()
        result = m._find_handler("HAL_UART_Init")(_cpu())
        assert result.return_value == HAL_OK

    def test_transmit(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"hello"
        m = STM32UART()
        m._find_handler("HAL_UART_Transmit")(_cpu(r1=0x20002000, r2=5, gdb=gdb))
        assert len(m.tx_log) == 1
        assert m.tx_log[0] == b"hello"

    def test_receive_with_data(self):
        gdb = MagicMock()
        m = STM32UART()
        m.inject_rx(b"\x01\x02\x03")
        m._find_handler("HAL_UART_Receive")(_cpu(r1=0x20003000, r2=3, gdb=gdb))
        # Should write data to buffer
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x01\x02\x03")
        assert len(m.rx_buffer) == 0

    def test_receive_empty_buffer(self):
        gdb = MagicMock()
        m = STM32UART()
        m._find_handler("HAL_UART_Receive")(_cpu(r1=0x20003000, r2=4, gdb=gdb))
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x00\x00\x00\x00")


# ---------------------------------------------------------------------------
# STM32 SPI
# ---------------------------------------------------------------------------

class TestSTM32SPI:
    def test_init(self):
        m = STM32SPI()
        result = m._find_handler("HAL_SPI_Init")(_cpu())
        assert result.return_value == HAL_OK

    def test_transmit(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"\xAA\xBB"
        m = STM32SPI()
        m._find_handler("HAL_SPI_Transmit")(_cpu(r1=0x20002000, r2=2, gdb=gdb))
        assert m.tx_log == [b"\xAA\xBB"]


# ---------------------------------------------------------------------------
# STM32 I2C
# ---------------------------------------------------------------------------

class TestSTM32I2C:
    def test_init(self):
        m = STM32I2C()
        result = m._find_handler("HAL_I2C_Init")(_cpu())
        assert result.return_value == HAL_OK

    def test_master_transmit(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"\x01\x02"
        m = STM32I2C()
        m._find_handler("HAL_I2C_Master_Transmit")(_cpu(r1=0x50, r2=0x20002000, r3=2, gdb=gdb))
        assert len(m.tx_log) == 1
        assert m.tx_log[0] == (0x50, b"\x01\x02")


# ---------------------------------------------------------------------------
# STM32 Flash
# ---------------------------------------------------------------------------

class TestSTM32Flash:
    def test_unlock_and_program(self):
        m = STM32Flash()
        m._find_handler("HAL_FLASH_Unlock")(_cpu())
        result = m._find_handler("HAL_FLASH_Program")(_cpu())
        assert result.return_value == HAL_OK

    def test_program_without_unlock(self):
        m = STM32Flash()
        result = m._find_handler("HAL_FLASH_Program")(_cpu())
        assert result.return_value == HAL_ERROR

    def test_lock(self):
        m = STM32Flash()
        m._find_handler("HAL_FLASH_Unlock")(_cpu())
        m._find_handler("HAL_FLASH_Lock")(_cpu())
        result = m._find_handler("HAL_FLASH_Program")(_cpu())
        assert result.return_value == HAL_ERROR


# ---------------------------------------------------------------------------
# STM32 Timer
# ---------------------------------------------------------------------------

class TestSTM32Timer:
    def test_init(self):
        m = STM32Timer()
        result = m._find_handler("HAL_TIM_Base_Init")(_cpu())
        assert result.return_value == HAL_OK

    def test_start_stop(self):
        m = STM32Timer()
        m._find_handler("HAL_TIM_Base_Start")(_cpu())
        assert m._running is True
        m._find_handler("HAL_TIM_Base_Stop")(_cpu())
        assert m._running is False
