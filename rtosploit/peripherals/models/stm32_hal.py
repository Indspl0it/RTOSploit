"""STM32 HAL peripheral models for firmware rehosting.

Implements handlers for ST's Hardware Abstraction Layer (HAL) functions,
allowing STM32 firmware to run in QEMU without real hardware peripherals.
"""

from __future__ import annotations

import logging
import time

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

logger = logging.getLogger(__name__)

# HAL status codes
HAL_OK = 0
HAL_ERROR = 1
HAL_BUSY = 2
HAL_TIMEOUT = 3


class STM32HALBase(PeripheralModel):
    """Core HAL functions: HAL_Init, HAL_GetTick, HAL_Delay.

    Maintains a virtual tick counter that advances with wall-clock time.
    HAL_Delay is intercepted to skip actual delays.
    """

    def __init__(self, name: str = "hal_base", base_addr: int = 0, size: int = 0) -> None:
        super().__init__(name, base_addr, size)
        self._tick_start = time.monotonic()

    def _get_tick_ms(self) -> int:
        """Return milliseconds since init."""
        return int((time.monotonic() - self._tick_start) * 1000) & 0xFFFFFFFF

    @hal_handler("HAL_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        self._tick_start = time.monotonic()
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_GetTick")
    def handle_get_tick(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=self._get_tick_ms())

    @hal_handler("HAL_Delay")
    def handle_delay(self, cpu: CPUState) -> HandlerResult:
        delay_ms = cpu.get_arg(0)
        logger.debug("HAL_Delay(%d ms) — skipped", delay_ms)
        return HandlerResult(return_value=None)  # void function

    @hal_handler("HAL_IncTick")
    def handle_inc_tick(self, cpu: CPUState) -> HandlerResult:
        # SysTick increments the tick — we use wall clock instead, so just skip
        return HandlerResult(return_value=None)

    @hal_handler("HAL_GetHalVersion")
    def handle_get_version(self, cpu: CPUState) -> HandlerResult:
        # Return HAL version 1.7.0 encoded as 0x01070000
        return HandlerResult(return_value=0x01070000)


class STM32RCC(PeripheralModel):
    """Reset and Clock Configuration.

    Always reports clocks configured successfully and returns default frequencies.
    """

    # Default clock frequencies (Hz)
    SYSCLK = 72_000_000   # 72 MHz
    HCLK = 72_000_000
    PCLK1 = 36_000_000    # APB1
    PCLK2 = 72_000_000    # APB2

    def __init__(
        self,
        name: str = "rcc",
        base_addr: int = 0x40021000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)

    @hal_handler("HAL_RCC_OscConfig")
    def handle_osc_config(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_RCC_ClockConfig")
    def handle_clock_config(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_RCC_GetSysClockFreq")
    def handle_get_sysclk(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=self.SYSCLK)

    @hal_handler("HAL_RCC_GetHCLKFreq")
    def handle_get_hclk(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=self.HCLK)

    @hal_handler("HAL_RCC_GetPCLK1Freq")
    def handle_get_pclk1(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=self.PCLK1)

    @hal_handler("HAL_RCC_GetPCLK2Freq")
    def handle_get_pclk2(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=self.PCLK2)

    @hal_handler("SystemClock_Config")
    def handle_system_clock_config(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void function


class STM32GPIO(PeripheralModel):
    """GPIO peripheral model.

    Tracks pin state in registers. ReadPin returns stored values,
    WritePin/TogglePin update them.
    """

    def __init__(
        self,
        name: str = "gpio_a",
        base_addr: int = 0x40020000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._pin_state: int = 0  # Output data register shadow

    @hal_handler("HAL_GPIO_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("HAL_GPIO_DeInit")
    def handle_deinit(self, cpu: CPUState) -> HandlerResult:
        self._pin_state = 0
        return HandlerResult(return_value=None)

    @hal_handler("HAL_GPIO_ReadPin")
    def handle_read_pin(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)  # GPIO_Pin (bitmask)
        value = 1 if (self._pin_state & pin) else 0
        return HandlerResult(return_value=value)

    @hal_handler("HAL_GPIO_WritePin")
    def handle_write_pin(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)
        state = cpu.get_arg(2)  # GPIO_PIN_SET=1, GPIO_PIN_RESET=0
        if state:
            self._pin_state |= pin
        else:
            self._pin_state &= ~pin
        return HandlerResult(return_value=None)

    @hal_handler("HAL_GPIO_TogglePin")
    def handle_toggle_pin(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(1)
        self._pin_state ^= pin
        return HandlerResult(return_value=None)


class STM32UART(PeripheralModel):
    """UART peripheral model.

    Transmit captures output data, Receive returns from an injectable RX buffer.
    """

    def __init__(
        self,
        name: str = "uart1",
        base_addr: int = 0x40011000,
        size: int = 0x400,
        uart_id: int = 1,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.uart_id = uart_id
        self.tx_log: list[bytes] = []
        self.rx_buffer: bytearray = bytearray()

    def inject_rx(self, data: bytes) -> None:
        """Inject data into the receive buffer for the firmware to read."""
        self.rx_buffer.extend(data)

    @hal_handler("HAL_UART_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler(["HAL_UART_Transmit", "HAL_UART_Transmit_IT", "HAL_UART_Transmit_DMA"])
    def handle_transmit(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        length = cpu.get_arg(2)
        if buf_ptr and length > 0:
            data = cpu.read_memory(buf_ptr, length)
            self.tx_log.append(data)
            logger.debug("UART%d TX: %r", self.uart_id, data)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler(["HAL_UART_Receive", "HAL_UART_Receive_IT", "HAL_UART_Receive_DMA"])
    def handle_receive(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        length = cpu.get_arg(2)
        if buf_ptr and length > 0:
            available = min(length, len(self.rx_buffer))
            if available > 0:
                data = bytes(self.rx_buffer[:available])
                del self.rx_buffer[:available]
                cpu.write_memory(buf_ptr, data)
                # Zero-fill remaining
                if available < length:
                    cpu.write_memory(buf_ptr + available, b"\x00" * (length - available))
            else:
                cpu.write_memory(buf_ptr, b"\x00" * length)
        return HandlerResult(return_value=HAL_OK)


class STM32SPI(PeripheralModel):
    """SPI peripheral model. Transmit/Receive return success."""

    def __init__(
        self,
        name: str = "spi1",
        base_addr: int = 0x40013000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []
        self.rx_buffer: bytearray = bytearray()

    @hal_handler("HAL_SPI_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_SPI_Transmit")
    def handle_transmit(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        length = cpu.get_arg(2)
        if buf_ptr and length > 0:
            data = cpu.read_memory(buf_ptr, length)
            self.tx_log.append(data)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_SPI_Receive")
    def handle_receive(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        length = cpu.get_arg(2)
        if buf_ptr and length > 0:
            available = min(length, len(self.rx_buffer))
            if available > 0:
                data = bytes(self.rx_buffer[:available])
                del self.rx_buffer[:available]
                cpu.write_memory(buf_ptr, data)
                if available < length:
                    cpu.write_memory(buf_ptr + available, b"\x00" * (length - available))
            else:
                cpu.write_memory(buf_ptr, b"\x00" * length)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_SPI_TransmitReceive")
    def handle_transmit_receive(self, cpu: CPUState) -> HandlerResult:
        tx_ptr = cpu.get_arg(1)
        rx_ptr = cpu.get_arg(2)
        length = cpu.get_arg(3)
        if tx_ptr and length > 0:
            data = cpu.read_memory(tx_ptr, length)
            self.tx_log.append(data)
        if rx_ptr and length > 0:
            cpu.write_memory(rx_ptr, b"\x00" * length)
        return HandlerResult(return_value=HAL_OK)


class STM32I2C(PeripheralModel):
    """I2C peripheral model."""

    def __init__(
        self,
        name: str = "i2c1",
        base_addr: int = 0x40005400,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[tuple[int, bytes]] = []  # (dev_addr, data)
        self.rx_buffer: bytearray = bytearray()

    @hal_handler("HAL_I2C_Init")
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_I2C_Master_Transmit")
    def handle_master_tx(self, cpu: CPUState) -> HandlerResult:
        dev_addr = cpu.get_arg(1)
        buf_ptr = cpu.get_arg(2)
        length = cpu.get_arg(3)
        if buf_ptr and length > 0:
            data = cpu.read_memory(buf_ptr, length)
            self.tx_log.append((dev_addr, data))
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_I2C_Master_Receive")
    def handle_master_rx(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(2)
        length = cpu.get_arg(3)
        if buf_ptr and length > 0:
            available = min(length, len(self.rx_buffer))
            if available > 0:
                data = bytes(self.rx_buffer[:available])
                del self.rx_buffer[:available]
                cpu.write_memory(buf_ptr, data)
                if available < length:
                    cpu.write_memory(buf_ptr + available, b"\x00" * (length - available))
            else:
                cpu.write_memory(buf_ptr, b"\x00" * length)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_I2C_Mem_Read")
    def handle_mem_read(self, cpu: CPUState) -> HandlerResult:
        # Args: hi2c, DevAddress, MemAddress, MemAddSize, pData (stack), Size (stack)
        buf_ptr = cpu.get_arg(4)  # arg4 is on stack
        length = cpu.get_arg(5)   # arg5 is on stack
        if buf_ptr and length > 0:
            cpu.write_memory(buf_ptr, b"\x00" * length)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_I2C_Mem_Write")
    def handle_mem_write(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)


class STM32Flash(PeripheralModel):
    """Flash peripheral model."""

    def __init__(
        self,
        name: str = "flash",
        base_addr: int = 0x40023C00,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._unlocked = False

    @hal_handler("HAL_FLASH_Unlock")
    def handle_unlock(self, cpu: CPUState) -> HandlerResult:
        self._unlocked = True
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_FLASH_Lock")
    def handle_lock(self, cpu: CPUState) -> HandlerResult:
        self._unlocked = False
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_FLASH_Program")
    def handle_program(self, cpu: CPUState) -> HandlerResult:
        if not self._unlocked:
            return HandlerResult(return_value=HAL_ERROR)
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_FLASH_OB_Unlock")
    def handle_ob_unlock(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)


class STM32Timer(PeripheralModel):
    """Timer peripheral model."""

    def __init__(
        self,
        name: str = "tim1",
        base_addr: int = 0x40010000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._running = False

    @hal_handler("HAL_TIM_Base_Init")
    def handle_base_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_TIM_Base_Start")
    def handle_base_start(self, cpu: CPUState) -> HandlerResult:
        self._running = True
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_TIM_Base_Stop")
    def handle_base_stop(self, cpu: CPUState) -> HandlerResult:
        self._running = False
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_TIM_Base_Start_IT")
    def handle_base_start_it(self, cpu: CPUState) -> HandlerResult:
        self._running = True
        return HandlerResult(return_value=HAL_OK)

    @hal_handler("HAL_TIM_Base_Stop_IT")
    def handle_base_stop_it(self, cpu: CPUState) -> HandlerResult:
        self._running = False
        return HandlerResult(return_value=HAL_OK)
