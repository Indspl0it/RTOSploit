"""Unit tests for Nordic nRF5 peripheral models."""

from __future__ import annotations

from unittest.mock import MagicMock


from rtosploit.peripherals.model import CPUState
from rtosploit.peripherals.models.nrf5_hal import (
    NRF_ERROR_NOT_FOUND,
    NRF5Base,
    NRF5BLE,
    NRF5GPIO,
    NRF5SPI,
    NRF5TWI,
    NRF5Timer,
    NRF5UART,
)


def _cpu(r0=0, r1=0, r2=0, r3=0, gdb=None):
    """Create a CPUState with given argument registers."""
    regs = {"r0": r0, "r1": r1, "r2": r2, "r3": r3, "sp": 0x20008000, "lr": 0x08001001}
    return CPUState(regs=regs, _gdb=gdb)


# ---------------------------------------------------------------------------
# NRF5Base
# ---------------------------------------------------------------------------

class TestNRF5Base:
    def test_nrf5_base_clock_init(self):
        m = NRF5Base()
        result = m._find_handler("nrf_drv_clock_init")(_cpu())
        assert result.intercept is True
        assert result.return_value == 0

    def test_nrf5_base_pwr_mgmt_init(self):
        m = NRF5Base()
        result = m._find_handler("nrf_pwr_mgmt_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_pwr_mgmt_run(self):
        m = NRF5Base()
        result = m._find_handler("nrf_pwr_mgmt_run")(_cpu())
        assert result.return_value is None  # void

    def test_nrf5_base_log_init(self):
        m = NRF5Base()
        result = m._find_handler("nrf_log_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_log_process(self):
        m = NRF5Base()
        result = m._find_handler("nrf_log_process")(_cpu())
        assert result.return_value == 0  # no pending logs

    def test_nrf5_base_sdh_enable(self):
        m = NRF5Base()
        result = m._find_handler("nrf_sdh_enable_request")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_sdh_ble_enable(self):
        m = NRF5Base()
        result = m._find_handler("nrf_sdh_ble_enable")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_crypto_init(self):
        m = NRF5Base()
        result = m._find_handler("nrf_crypto_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_wdt_init(self):
        m = NRF5Base()
        result = m._find_handler("nrf_drv_wdt_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_base_wdt_feed(self):
        m = NRF5Base()
        result = m._find_handler("nrf_drv_wdt_feed")(_cpu())
        assert result.return_value is None  # void

    def test_nrf5_base_wdt_channel_alloc(self):
        m = NRF5Base()
        result = m._find_handler("nrf_drv_wdt_channel_alloc")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# NRF5UART
# ---------------------------------------------------------------------------

class TestNRF5UART:
    def test_nrf5_uart_init(self):
        m = NRF5UART()
        result = m._find_handler("nrf_drv_uart_init")(_cpu())
        assert result.intercept is True
        assert result.return_value == 0

    def test_nrf5_uart_nrfx_init(self):
        m = NRF5UART()
        result = m._find_handler("nrfx_uarte_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_uart_rx_with_data(self):
        gdb = MagicMock()
        m = NRF5UART()
        m.inject_rx(b"\xAA\xBB\xCC")
        m._find_handler("nrf_drv_uart_rx")(_cpu(r1=0x20003000, r2=3, gdb=gdb))
        gdb.write_memory.assert_called_once_with(0x20003000, b"\xAA\xBB\xCC")
        assert len(m.rx_buffer) == 0

    def test_nrf5_uart_rx_empty(self):
        gdb = MagicMock()
        m = NRF5UART()
        m._find_handler("nrf_drv_uart_rx")(_cpu(r1=0x20003000, r2=4, gdb=gdb))
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x00\x00\x00\x00")

    def test_nrf5_uart_tx_logs_data(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"hello nrf"
        m = NRF5UART()
        m._find_handler("nrf_drv_uart_tx")(_cpu(r1=0x20002000, r2=9, gdb=gdb))
        assert len(m.tx_log) == 1
        assert m.tx_log[0] == b"hello nrf"

    def test_nrf5_uart_nrfx_rx(self):
        gdb = MagicMock()
        m = NRF5UART()
        m.inject_rx(b"\x01\x02")
        m._find_handler("nrfx_uarte_rx")(_cpu(r1=0x20003000, r2=2, gdb=gdb))
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x01\x02")

    def test_nrf5_uart_uninit(self):
        m = NRF5UART()
        result = m._find_handler("nrf_drv_uart_uninit")(_cpu())
        assert result.return_value is None


# ---------------------------------------------------------------------------
# NRF5SPI
# ---------------------------------------------------------------------------

class TestNRF5SPI:
    def test_nrf5_spi_init(self):
        m = NRF5SPI()
        result = m._find_handler("nrf_drv_spi_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_spi_transfer(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"\xDE\xAD"
        m = NRF5SPI()
        result = m._find_handler("nrf_drv_spi_transfer")(
            _cpu(r1=0x20002000, r2=0x20003000, r3=2, gdb=gdb)
        )
        assert result.return_value == 0
        assert m.tx_log == [b"\xDE\xAD"]
        # RX buffer filled with zeros
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x00\x00")

    def test_nrf5_spi_nrfx_init(self):
        m = NRF5SPI()
        result = m._find_handler("nrfx_spim_init")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# NRF5TWI (I2C)
# ---------------------------------------------------------------------------

class TestNRF5TWI:
    def test_nrf5_twi_init(self):
        m = NRF5TWI()
        result = m._find_handler("nrf_drv_twi_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_twi_tx(self):
        gdb = MagicMock()
        gdb.read_memory.return_value = b"\x01\x02"
        m = NRF5TWI()
        result = m._find_handler("nrf_drv_twi_tx")(
            _cpu(r1=0x50, r2=0x20002000, r3=2, gdb=gdb)
        )
        assert result.return_value == 0
        assert len(m.tx_log) == 1
        assert m.tx_log[0] == (0x50, b"\x01\x02")

    def test_nrf5_twi_rx(self):
        gdb = MagicMock()
        m = NRF5TWI()
        result = m._find_handler("nrf_drv_twi_rx")(
            _cpu(r1=0x50, r2=0x20003000, r3=4, gdb=gdb)
        )
        assert result.return_value == 0
        gdb.write_memory.assert_called_once_with(0x20003000, b"\x00\x00\x00\x00")

    def test_nrf5_twi_nrfx_init(self):
        m = NRF5TWI()
        result = m._find_handler("nrfx_twim_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_twi_uninit(self):
        m = NRF5TWI()
        result = m._find_handler("nrf_drv_twi_uninit")(_cpu())
        assert result.return_value is None


# ---------------------------------------------------------------------------
# NRF5GPIO
# ---------------------------------------------------------------------------

class TestNRF5GPIO:
    def test_nrf5_gpio_init(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_drv_gpiote_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_gpio_pin_set_clear_read(self):
        m = NRF5GPIO()
        # Set pin 5
        m._find_handler("nrf_gpio_pin_set")(_cpu(r0=5))
        result = m._find_handler("nrf_gpio_pin_read")(_cpu(r0=5))
        assert result.return_value == 1

        # Clear pin 5
        m._find_handler("nrf_gpio_pin_clear")(_cpu(r0=5))
        result = m._find_handler("nrf_gpio_pin_read")(_cpu(r0=5))
        assert result.return_value == 0

    def test_nrf5_gpio_read_unset(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_gpio_pin_read")(_cpu(r0=10))
        assert result.return_value == 0

    def test_nrf5_gpio_cfg_output(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_gpio_cfg_output")(_cpu())
        assert result.return_value is None  # void

    def test_nrf5_gpio_cfg_input(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_gpio_cfg_input")(_cpu())
        assert result.return_value is None  # void

    def test_nrf5_gpio_gpiote_in_init(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_drv_gpiote_in_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_gpio_gpiote_out_init(self):
        m = NRF5GPIO()
        result = m._find_handler("nrf_drv_gpiote_out_init")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# NRF5BLE (SoftDevice)
# ---------------------------------------------------------------------------

class TestNRF5BLE:
    def test_nrf5_ble_enable(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_enable")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gap_scan_start(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gap_scan_start")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gap_adv_start(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gap_adv_start")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gap_connect(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gap_connect")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_evt_get(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_evt_get")(_cpu())
        assert result.return_value == NRF_ERROR_NOT_FOUND  # 0x0009

    def test_nrf5_ble_gattc_read(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gattc_read")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gattc_write(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gattc_write")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gatts_service_add(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gatts_service_add")(_cpu())
        assert result.return_value == 0

    def test_nrf5_ble_gatts_char_add(self):
        m = NRF5BLE()
        result = m._find_handler("sd_ble_gatts_characteristic_add")(_cpu())
        assert result.return_value == 0


# ---------------------------------------------------------------------------
# NRF5Timer
# ---------------------------------------------------------------------------

class TestNRF5Timer:
    def test_nrf5_timer_init(self):
        m = NRF5Timer()
        result = m._find_handler("app_timer_init")(_cpu())
        assert result.return_value == 0

    def test_nrf5_timer_create_start_stop(self):
        m = NRF5Timer()
        result = m._find_handler("app_timer_create")(_cpu())
        assert result.return_value == 0
        result = m._find_handler("app_timer_start")(_cpu())
        assert result.return_value == 0
        result = m._find_handler("app_timer_stop")(_cpu())
        assert result.return_value == 0
