"""Nordic nRF5 SDK peripheral models for firmware rehosting.

Implements handlers for Nordic's nRF5 SDK and nrfx driver functions,
allowing nRF52-based firmware to run in QEMU without real hardware peripherals.
"""

from __future__ import annotations

import logging

from rtosploit.peripherals.model import (
    CPUState,
    HandlerResult,
    PeripheralModel,
    hal_handler,
)

logger = logging.getLogger(__name__)

# nRF SDK error codes
NRF_SUCCESS = 0
NRF_ERROR_INVALID_STATE = 8
NRF_ERROR_NOT_FOUND = 0x0009


class NRF5Base(PeripheralModel):
    """Core nRF5 SDK init functions: clock, power management, logging, SoftDevice.

    All init functions return NRF_SUCCESS to let firmware boot.
    """

    def __init__(
        self,
        name: str = "nrf5_base",
        base_addr: int = 0,
        size: int = 0,
    ) -> None:
        super().__init__(name, base_addr, size)

    @hal_handler("nrf_drv_clock_init")
    def handle_clock_init(self, cpu: CPUState) -> HandlerResult:
        logger.debug("nrf_drv_clock_init()")
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_clock_lfclk_request")
    def handle_lfclk_request(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_drv_clock_hfclk_request")
    def handle_hfclk_request(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_pwr_mgmt_init")
    def handle_pwr_mgmt_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_pwr_mgmt_run")
    def handle_pwr_mgmt_run(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_log_init")
    def handle_log_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_log_process")
    def handle_log_process(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=0)  # 0 = no pending logs

    @hal_handler("nrf_sdh_enable_request")
    def handle_sdh_enable_request(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_sdh_ble_enable")
    def handle_sdh_ble_enable(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_crypto_init")
    def handle_crypto_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_wdt_init")
    def handle_wdt_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_wdt_feed")
    def handle_wdt_feed(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_drv_wdt_channel_alloc")
    def handle_wdt_channel_alloc(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)


class NRF5UART(PeripheralModel):
    """nRF5 UART driver model with RX buffer injection.

    Supports both legacy nrf_drv_uart and nrfx_uarte driver APIs.
    TX data is logged, RX reads from an injectable buffer.
    """

    def __init__(
        self,
        name: str = "nrf5_uart0",
        base_addr: int = 0x40002000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []
        self.rx_buffer: bytearray = bytearray()

    def inject_rx(self, data: bytes) -> None:
        """Inject data into the receive buffer for the firmware to read."""
        self.rx_buffer.extend(data)

    @hal_handler(["nrf_drv_uart_init", "nrfx_uarte_init"])
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler(["nrf_drv_uart_rx", "nrfx_uarte_rx"])
    def handle_rx(self, cpu: CPUState) -> HandlerResult:
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
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler(["nrf_drv_uart_tx", "nrfx_uarte_tx"])
    def handle_tx(self, cpu: CPUState) -> HandlerResult:
        buf_ptr = cpu.get_arg(1)
        length = cpu.get_arg(2)
        if buf_ptr and length > 0:
            data = cpu.read_memory(buf_ptr, length)
            self.tx_log.append(data)
            logger.debug("nRF5 UART TX: %r", data)
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_uart_rx_abort")
    def handle_rx_abort(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_drv_uart_uninit")
    def handle_uninit(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void


class NRF5SPI(PeripheralModel):
    """nRF5 SPI driver model.

    Supports both legacy nrf_drv_spi and nrfx_spim driver APIs.
    """

    def __init__(
        self,
        name: str = "nrf5_spi0",
        base_addr: int = 0x40003000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[bytes] = []
        self.rx_buffer: bytearray = bytearray()

    @hal_handler(["nrf_drv_spi_init", "nrfx_spim_init"])
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler(["nrf_drv_spi_transfer", "nrfx_spim_xfer"])
    def handle_transfer(self, cpu: CPUState) -> HandlerResult:
        tx_ptr = cpu.get_arg(1)
        rx_ptr = cpu.get_arg(2)
        tx_len = cpu.get_arg(3)
        if tx_ptr and tx_len > 0:
            data = cpu.read_memory(tx_ptr, tx_len)
            self.tx_log.append(data)
            logger.debug("nRF5 SPI TX: %r", data)
        if rx_ptr and tx_len > 0:
            cpu.write_memory(rx_ptr, b"\x00" * tx_len)
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_spi_uninit")
    def handle_uninit(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void


class NRF5TWI(PeripheralModel):
    """nRF5 TWI (I2C) driver model.

    Supports both legacy nrf_drv_twi and nrfx_twim driver APIs.
    """

    def __init__(
        self,
        name: str = "nrf5_twi0",
        base_addr: int = 0x40003000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.tx_log: list[tuple[int, bytes]] = []  # (addr, data)

    @hal_handler(["nrf_drv_twi_init", "nrfx_twim_init"])
    def handle_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_twi_tx")
    def handle_tx(self, cpu: CPUState) -> HandlerResult:
        addr = cpu.get_arg(1)
        data_ptr = cpu.get_arg(2)
        length = cpu.get_arg(3)
        if data_ptr and length > 0:
            data = cpu.read_memory(data_ptr, length)
            self.tx_log.append((addr, data))
            logger.debug("nRF5 TWI TX to 0x%02x: %r", addr, data)
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler(["nrf_drv_twi_rx", "nrfx_twim_xfer"])
    def handle_rx(self, cpu: CPUState) -> HandlerResult:
        data_ptr = cpu.get_arg(2)
        length = cpu.get_arg(3)
        if data_ptr and length > 0:
            cpu.write_memory(data_ptr, b"\x00" * length)
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_twi_uninit")
    def handle_uninit(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void


class NRF5GPIO(PeripheralModel):
    """nRF5 GPIO driver model with pin state tracking.

    Tracks a 32-bit pin state register for read/write/toggle operations.
    """

    def __init__(
        self,
        name: str = "nrf5_gpio",
        base_addr: int = 0x50000000,
        size: int = 0x400,
    ) -> None:
        super().__init__(name, base_addr, size)
        self._pin_state: int = 0  # 32-bit output register

    @hal_handler("nrf_drv_gpiote_init")
    def handle_gpiote_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_gpiote_in_init")
    def handle_gpiote_in_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_drv_gpiote_out_init")
    def handle_gpiote_out_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("nrf_gpio_pin_set")
    def handle_pin_set(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(0)
        if pin < 32:
            self._pin_state |= (1 << pin)
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_gpio_pin_clear")
    def handle_pin_clear(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(0)
        if pin < 32:
            self._pin_state &= ~(1 << pin)
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_gpio_pin_read")
    def handle_pin_read(self, cpu: CPUState) -> HandlerResult:
        pin = cpu.get_arg(0)
        if pin < 32:
            value = (self._pin_state >> pin) & 1
        else:
            value = 0
        return HandlerResult(return_value=value)

    @hal_handler("nrf_gpio_cfg_output")
    def handle_cfg_output(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void

    @hal_handler("nrf_gpio_cfg_input")
    def handle_cfg_input(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=None)  # void


class NRF5BLE(PeripheralModel):
    """nRF5 SoftDevice BLE stub.

    All SoftDevice BLE calls return NRF_SUCCESS. sd_ble_evt_get returns
    NRF_ERROR_NOT_FOUND (0x0009) to indicate no pending BLE events.
    """

    def __init__(
        self,
        name: str = "nrf5_ble",
        base_addr: int = 0,
        size: int = 0,
    ) -> None:
        super().__init__(name, base_addr, size)
        self.ble_events: list[bytes] = []

    @hal_handler("sd_ble_enable")
    def handle_ble_enable(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gap_scan_start")
    def handle_gap_scan_start(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gap_scan_stop")
    def handle_gap_scan_stop(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gap_adv_start")
    def handle_gap_adv_start(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gap_adv_stop")
    def handle_gap_adv_stop(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gap_connect")
    def handle_gap_connect(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gatts_service_add")
    def handle_gatts_service_add(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gatts_characteristic_add")
    def handle_gatts_char_add(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gattc_read")
    def handle_gattc_read(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_gattc_write")
    def handle_gattc_write(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("sd_ble_evt_get")
    def handle_ble_evt_get(self, cpu: CPUState) -> HandlerResult:
        # Return NRF_ERROR_NOT_FOUND = no pending events
        return HandlerResult(return_value=NRF_ERROR_NOT_FOUND)


class NRF5Timer(PeripheralModel):
    """nRF5 app_timer model.

    All timer operations return NRF_SUCCESS.
    """

    def __init__(
        self,
        name: str = "nrf5_timer",
        base_addr: int = 0,
        size: int = 0,
    ) -> None:
        super().__init__(name, base_addr, size)

    @hal_handler("app_timer_init")
    def handle_timer_init(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("app_timer_create")
    def handle_timer_create(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("app_timer_start")
    def handle_timer_start(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)

    @hal_handler("app_timer_stop")
    def handle_timer_stop(self, cpu: CPUState) -> HandlerResult:
        return HandlerResult(return_value=NRF_SUCCESS)
