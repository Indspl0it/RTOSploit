"""HAL function database -- maps vendor SDK symbols to peripheral handlers.

When firmware is fingerprinted and symbols like HAL_UART_Receive or
nrf_drv_uart_rx are found, this database tells us what vendor SDK the
symbol belongs to, what peripheral type it controls, what semantic role
it plays, and which model class + handler method should intercept it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class HALFunctionEntry:
    """A single hookable HAL/SDK function."""
    symbol: str              # e.g., "HAL_UART_Receive"
    vendor: str              # "stm32", "nrf5", "zephyr"
    peripheral_type: str     # "uart", "spi", "i2c", "ble", "gpio", "clock", "timer", "flash", "init", "power"
    semantic: str            # "input", "output", "init", "query", "delay", "config"
    model_class: str         # Full dotted path to Python class
    handler_name: str        # Method name on the model class (matches @hal_handler)
    description: str = ""


class HALDatabase:
    """Database of hookable HAL/SDK functions across vendors."""

    def __init__(self) -> None:
        self._entries: list[HALFunctionEntry] = []
        self._by_symbol: dict[str, HALFunctionEntry] = {}
        self._load_all()

    def _load_all(self) -> None:
        """Load all vendor entries."""
        self._load_stm32()
        self._load_nrf5()
        self._load_zephyr()
        # Build index
        for entry in self._entries:
            self._by_symbol[entry.symbol] = entry

    def _add(self, symbol: str, vendor: str, peripheral_type: str, semantic: str,
             model_class: str, handler_name: str, description: str = "") -> None:
        self._entries.append(HALFunctionEntry(
            symbol=symbol, vendor=vendor, peripheral_type=peripheral_type,
            semantic=semantic, model_class=model_class,
            handler_name=handler_name, description=description,
        ))

    def lookup_symbol(self, symbol_name: str) -> Optional[HALFunctionEntry]:
        """Find entry by exact symbol name."""
        return self._by_symbol.get(symbol_name)

    def lookup_vendor(self, vendor: str) -> list[HALFunctionEntry]:
        """Get all entries for a vendor."""
        return [e for e in self._entries if e.vendor == vendor]

    def lookup_peripheral(self, peripheral_type: str) -> list[HALFunctionEntry]:
        """Get all entries for a peripheral type."""
        return [e for e in self._entries if e.peripheral_type == peripheral_type]

    def get_input_functions(self) -> list[HALFunctionEntry]:
        """Get all functions with semantic='input'."""
        return [e for e in self._entries if e.semantic == "input"]

    def match_firmware_symbols(self, symbols: dict[str, int]) -> list[tuple[HALFunctionEntry, int]]:
        """Match firmware symbol table against database.

        Returns list of (entry, address) for each matched symbol.
        """
        matches = []
        for sym_name, addr in symbols.items():
            entry = self._by_symbol.get(sym_name)
            if entry is not None:
                matches.append((entry, addr))
        return matches

    def get_vendors(self) -> list[str]:
        """Return unique vendor names."""
        return sorted(set(e.vendor for e in self._entries))

    def get_peripheral_types(self) -> list[str]:
        """Return unique peripheral types."""
        return sorted(set(e.peripheral_type for e in self._entries))

    @property
    def size(self) -> int:
        return len(self._entries)

    # ------------------------------------------------------------------
    # STM32 HAL entries (~40)
    # ------------------------------------------------------------------

    def _load_stm32(self) -> None:
        """Load STM32 HAL function entries."""
        _stm32 = "rtosploit.peripherals.models.stm32_hal"

        # STM32HALBase
        _cls = f"{_stm32}.STM32HALBase"
        self._add("HAL_Init", "stm32", "init", "init", _cls, "HAL_Init")
        self._add("HAL_GetTick", "stm32", "init", "query", _cls, "HAL_GetTick")
        self._add("HAL_Delay", "stm32", "init", "delay", _cls, "HAL_Delay")
        self._add("HAL_IncTick", "stm32", "init", "config", _cls, "HAL_IncTick")
        self._add("HAL_GetHalVersion", "stm32", "init", "query", _cls, "HAL_GetHalVersion")

        # STM32RCC
        _cls = f"{_stm32}.STM32RCC"
        self._add("HAL_RCC_OscConfig", "stm32", "clock", "config", _cls, "HAL_RCC_OscConfig")
        self._add("HAL_RCC_ClockConfig", "stm32", "clock", "config", _cls, "HAL_RCC_ClockConfig")
        self._add("HAL_RCC_GetSysClockFreq", "stm32", "clock", "query", _cls, "HAL_RCC_GetSysClockFreq")
        self._add("HAL_RCC_GetHCLKFreq", "stm32", "clock", "query", _cls, "HAL_RCC_GetHCLKFreq")
        self._add("HAL_RCC_GetPCLK1Freq", "stm32", "clock", "query", _cls, "HAL_RCC_GetPCLK1Freq")
        self._add("HAL_RCC_GetPCLK2Freq", "stm32", "clock", "query", _cls, "HAL_RCC_GetPCLK2Freq")
        self._add("SystemClock_Config", "stm32", "clock", "config", _cls, "SystemClock_Config")

        # STM32GPIO
        _cls = f"{_stm32}.STM32GPIO"
        self._add("HAL_GPIO_Init", "stm32", "gpio", "init", _cls, "HAL_GPIO_Init")
        self._add("HAL_GPIO_DeInit", "stm32", "gpio", "init", _cls, "HAL_GPIO_DeInit")
        self._add("HAL_GPIO_ReadPin", "stm32", "gpio", "input", _cls, "HAL_GPIO_ReadPin")
        self._add("HAL_GPIO_WritePin", "stm32", "gpio", "output", _cls, "HAL_GPIO_WritePin")
        self._add("HAL_GPIO_TogglePin", "stm32", "gpio", "output", _cls, "HAL_GPIO_TogglePin")

        # STM32UART
        _cls = f"{_stm32}.STM32UART"
        self._add("HAL_UART_Init", "stm32", "uart", "init", _cls, "HAL_UART_Init")
        self._add("HAL_UART_Transmit", "stm32", "uart", "output", _cls, "HAL_UART_Transmit")
        self._add("HAL_UART_Transmit_IT", "stm32", "uart", "output", _cls, "HAL_UART_Transmit_IT")
        self._add("HAL_UART_Transmit_DMA", "stm32", "uart", "output", _cls, "HAL_UART_Transmit_DMA")
        self._add("HAL_UART_Receive", "stm32", "uart", "input", _cls, "HAL_UART_Receive")
        self._add("HAL_UART_Receive_IT", "stm32", "uart", "input", _cls, "HAL_UART_Receive_IT")
        self._add("HAL_UART_Receive_DMA", "stm32", "uart", "input", _cls, "HAL_UART_Receive_DMA")

        # STM32SPI
        _cls = f"{_stm32}.STM32SPI"
        self._add("HAL_SPI_Init", "stm32", "spi", "init", _cls, "HAL_SPI_Init")
        self._add("HAL_SPI_Transmit", "stm32", "spi", "output", _cls, "HAL_SPI_Transmit")
        self._add("HAL_SPI_Receive", "stm32", "spi", "input", _cls, "HAL_SPI_Receive")
        self._add("HAL_SPI_TransmitReceive", "stm32", "spi", "input", _cls, "HAL_SPI_TransmitReceive")

        # STM32I2C
        _cls = f"{_stm32}.STM32I2C"
        self._add("HAL_I2C_Init", "stm32", "i2c", "init", _cls, "HAL_I2C_Init")
        self._add("HAL_I2C_Master_Transmit", "stm32", "i2c", "output", _cls, "HAL_I2C_Master_Transmit")
        self._add("HAL_I2C_Master_Receive", "stm32", "i2c", "input", _cls, "HAL_I2C_Master_Receive")
        self._add("HAL_I2C_Mem_Read", "stm32", "i2c", "input", _cls, "HAL_I2C_Mem_Read")
        self._add("HAL_I2C_Mem_Write", "stm32", "i2c", "output", _cls, "HAL_I2C_Mem_Write")

        # STM32Flash
        _cls = f"{_stm32}.STM32Flash"
        self._add("HAL_FLASH_Unlock", "stm32", "flash", "config", _cls, "HAL_FLASH_Unlock")
        self._add("HAL_FLASH_Lock", "stm32", "flash", "config", _cls, "HAL_FLASH_Lock")
        self._add("HAL_FLASH_Program", "stm32", "flash", "output", _cls, "HAL_FLASH_Program")
        self._add("HAL_FLASH_OB_Unlock", "stm32", "flash", "config", _cls, "HAL_FLASH_OB_Unlock")

        # STM32Timer
        _cls = f"{_stm32}.STM32Timer"
        self._add("HAL_TIM_Base_Init", "stm32", "timer", "init", _cls, "HAL_TIM_Base_Init")
        self._add("HAL_TIM_Base_Start", "stm32", "timer", "config", _cls, "HAL_TIM_Base_Start")
        self._add("HAL_TIM_Base_Stop", "stm32", "timer", "config", _cls, "HAL_TIM_Base_Stop")
        self._add("HAL_TIM_Base_Start_IT", "stm32", "timer", "config", _cls, "HAL_TIM_Base_Start_IT")
        self._add("HAL_TIM_Base_Stop_IT", "stm32", "timer", "config", _cls, "HAL_TIM_Base_Stop_IT")

    # ------------------------------------------------------------------
    # Nordic nRF5 SDK entries (~50)
    # ------------------------------------------------------------------

    def _load_nrf5(self) -> None:
        """Load Nordic nRF5 SDK function entries."""
        _nrf5 = "rtosploit.peripherals.models.nrf5_hal"

        # NRF5Base
        _cls = f"{_nrf5}.NRF5Base"
        self._add("nrf_drv_clock_init", "nrf5", "clock", "init", _cls, "nrf_drv_clock_init")
        self._add("nrf_drv_clock_lfclk_request", "nrf5", "clock", "config", _cls, "nrf_drv_clock_lfclk_request")
        self._add("nrf_drv_clock_hfclk_request", "nrf5", "clock", "config", _cls, "nrf_drv_clock_hfclk_request")
        self._add("nrf_pwr_mgmt_init", "nrf5", "power", "init", _cls, "nrf_pwr_mgmt_init")
        self._add("nrf_pwr_mgmt_run", "nrf5", "power", "config", _cls, "nrf_pwr_mgmt_run")
        self._add("nrf_log_init", "nrf5", "init", "init", _cls, "nrf_log_init")
        self._add("nrf_log_process", "nrf5", "init", "query", _cls, "nrf_log_process")
        self._add("nrf_sdh_enable_request", "nrf5", "init", "init", _cls, "nrf_sdh_enable_request")
        self._add("nrf_sdh_ble_enable", "nrf5", "init", "init", _cls, "nrf_sdh_ble_enable")
        self._add("nrf_crypto_init", "nrf5", "init", "init", _cls, "nrf_crypto_init")
        self._add("nrf_drv_wdt_init", "nrf5", "timer", "init", _cls, "nrf_drv_wdt_init")
        self._add("nrf_drv_wdt_feed", "nrf5", "timer", "config", _cls, "nrf_drv_wdt_feed")
        self._add("nrf_drv_wdt_channel_alloc", "nrf5", "timer", "config", _cls, "nrf_drv_wdt_channel_alloc")

        # NRF5UART
        _cls = f"{_nrf5}.NRF5UART"
        self._add("nrf_drv_uart_init", "nrf5", "uart", "init", _cls, "nrf_drv_uart_init")
        self._add("nrf_drv_uart_rx", "nrf5", "uart", "input", _cls, "nrf_drv_uart_rx")
        self._add("nrf_drv_uart_tx", "nrf5", "uart", "output", _cls, "nrf_drv_uart_tx")
        self._add("nrf_drv_uart_rx_abort", "nrf5", "uart", "config", _cls, "nrf_drv_uart_rx_abort")
        self._add("nrf_drv_uart_uninit", "nrf5", "uart", "init", _cls, "nrf_drv_uart_uninit")
        self._add("nrfx_uarte_init", "nrf5", "uart", "init", _cls, "nrfx_uarte_init")
        self._add("nrfx_uarte_rx", "nrf5", "uart", "input", _cls, "nrfx_uarte_rx")
        self._add("nrfx_uarte_tx", "nrf5", "uart", "output", _cls, "nrfx_uarte_tx")

        # NRF5SPI
        _cls = f"{_nrf5}.NRF5SPI"
        self._add("nrf_drv_spi_init", "nrf5", "spi", "init", _cls, "nrf_drv_spi_init")
        self._add("nrf_drv_spi_transfer", "nrf5", "spi", "input", _cls, "nrf_drv_spi_transfer")
        self._add("nrf_drv_spi_uninit", "nrf5", "spi", "init", _cls, "nrf_drv_spi_uninit")
        self._add("nrfx_spim_init", "nrf5", "spi", "init", _cls, "nrfx_spim_init")
        self._add("nrfx_spim_xfer", "nrf5", "spi", "input", _cls, "nrfx_spim_xfer")

        # NRF5TWI (I2C)
        _cls = f"{_nrf5}.NRF5TWI"
        self._add("nrf_drv_twi_init", "nrf5", "i2c", "init", _cls, "nrf_drv_twi_init")
        self._add("nrf_drv_twi_tx", "nrf5", "i2c", "output", _cls, "nrf_drv_twi_tx")
        self._add("nrf_drv_twi_rx", "nrf5", "i2c", "input", _cls, "nrf_drv_twi_rx")
        self._add("nrf_drv_twi_uninit", "nrf5", "i2c", "init", _cls, "nrf_drv_twi_uninit")
        self._add("nrfx_twim_init", "nrf5", "i2c", "init", _cls, "nrfx_twim_init")
        self._add("nrfx_twim_xfer", "nrf5", "i2c", "input", _cls, "nrfx_twim_xfer")

        # NRF5GPIO
        _cls = f"{_nrf5}.NRF5GPIO"
        self._add("nrf_drv_gpiote_init", "nrf5", "gpio", "init", _cls, "nrf_drv_gpiote_init")
        self._add("nrf_drv_gpiote_in_init", "nrf5", "gpio", "config", _cls, "nrf_drv_gpiote_in_init")
        self._add("nrf_drv_gpiote_out_init", "nrf5", "gpio", "config", _cls, "nrf_drv_gpiote_out_init")
        self._add("nrf_gpio_pin_set", "nrf5", "gpio", "output", _cls, "nrf_gpio_pin_set")
        self._add("nrf_gpio_pin_clear", "nrf5", "gpio", "output", _cls, "nrf_gpio_pin_clear")
        self._add("nrf_gpio_pin_read", "nrf5", "gpio", "input", _cls, "nrf_gpio_pin_read")
        self._add("nrf_gpio_cfg_output", "nrf5", "gpio", "config", _cls, "nrf_gpio_cfg_output")
        self._add("nrf_gpio_cfg_input", "nrf5", "gpio", "config", _cls, "nrf_gpio_cfg_input")

        # NRF5BLE (SoftDevice)
        _cls = f"{_nrf5}.NRF5BLE"
        self._add("sd_ble_gap_scan_start", "nrf5", "ble", "input", _cls, "sd_ble_gap_scan_start")
        self._add("sd_ble_gap_scan_stop", "nrf5", "ble", "config", _cls, "sd_ble_gap_scan_stop")
        self._add("sd_ble_gap_adv_start", "nrf5", "ble", "config", _cls, "sd_ble_gap_adv_start")
        self._add("sd_ble_gap_adv_stop", "nrf5", "ble", "config", _cls, "sd_ble_gap_adv_stop")
        self._add("sd_ble_gap_connect", "nrf5", "ble", "config", _cls, "sd_ble_gap_connect")
        self._add("sd_ble_gatts_service_add", "nrf5", "ble", "config", _cls, "sd_ble_gatts_service_add")
        self._add("sd_ble_gatts_characteristic_add", "nrf5", "ble", "config", _cls, "sd_ble_gatts_characteristic_add")
        self._add("sd_ble_gattc_read", "nrf5", "ble", "input", _cls, "sd_ble_gattc_read")
        self._add("sd_ble_gattc_write", "nrf5", "ble", "output", _cls, "sd_ble_gattc_write")
        self._add("sd_ble_enable", "nrf5", "ble", "init", _cls, "sd_ble_enable")
        self._add("sd_ble_evt_get", "nrf5", "ble", "input", _cls, "sd_ble_evt_get")

        # NRF5Timer
        _cls = f"{_nrf5}.NRF5Timer"
        self._add("app_timer_init", "nrf5", "timer", "init", _cls, "app_timer_init")
        self._add("app_timer_create", "nrf5", "timer", "config", _cls, "app_timer_create")
        self._add("app_timer_start", "nrf5", "timer", "config", _cls, "app_timer_start")
        self._add("app_timer_stop", "nrf5", "timer", "config", _cls, "app_timer_stop")

    # ------------------------------------------------------------------
    # Zephyr RTOS entries (~20)
    # ------------------------------------------------------------------

    def _load_zephyr(self) -> None:
        """Load Zephyr RTOS function entries."""
        _zephyr = "rtosploit.peripherals.models.zephyr_hal"

        # ZephyrBase
        _cls = f"{_zephyr}.ZephyrBase"
        self._add("device_get_binding", "zephyr", "init", "query", _cls, "device_get_binding")
        self._add("device_is_ready", "zephyr", "init", "query", _cls, "device_is_ready")
        self._add("k_sleep", "zephyr", "init", "delay", _cls, "k_sleep")
        self._add("k_msleep", "zephyr", "init", "delay", _cls, "k_msleep")
        self._add("k_busy_wait", "zephyr", "init", "delay", _cls, "k_busy_wait")

        # ZephyrUART
        _cls = f"{_zephyr}.ZephyrUART"
        self._add("uart_irq_rx_enable", "zephyr", "uart", "config", _cls, "uart_irq_rx_enable")
        self._add("uart_irq_rx_disable", "zephyr", "uart", "config", _cls, "uart_irq_rx_disable")
        self._add("uart_fifo_read", "zephyr", "uart", "input", _cls, "uart_fifo_read")
        self._add("uart_fifo_fill", "zephyr", "uart", "output", _cls, "uart_fifo_fill")
        self._add("uart_poll_in", "zephyr", "uart", "input", _cls, "uart_poll_in")
        self._add("uart_poll_out", "zephyr", "uart", "output", _cls, "uart_poll_out")

        # ZephyrSPI
        _cls = f"{_zephyr}.ZephyrSPI"
        self._add("spi_transceive", "zephyr", "spi", "input", _cls, "spi_transceive")
        self._add("spi_read", "zephyr", "spi", "input", _cls, "spi_read")
        self._add("spi_write", "zephyr", "spi", "output", _cls, "spi_write")

        # ZephyrI2C
        _cls = f"{_zephyr}.ZephyrI2C"
        self._add("i2c_transfer", "zephyr", "i2c", "input", _cls, "i2c_transfer")
        self._add("i2c_write", "zephyr", "i2c", "output", _cls, "i2c_write")
        self._add("i2c_read", "zephyr", "i2c", "input", _cls, "i2c_read")

        # ZephyrGPIO
        _cls = f"{_zephyr}.ZephyrGPIO"
        self._add("gpio_pin_configure", "zephyr", "gpio", "config", _cls, "gpio_pin_configure")
        self._add("gpio_pin_set", "zephyr", "gpio", "output", _cls, "gpio_pin_set")
        self._add("gpio_pin_get", "zephyr", "gpio", "input", _cls, "gpio_pin_get")
        self._add("gpio_pin_toggle", "zephyr", "gpio", "output", _cls, "gpio_pin_toggle")

        # ZephyrBLE
        _cls = f"{_zephyr}.ZephyrBLE"
        self._add("bt_enable", "zephyr", "ble", "init", _cls, "bt_enable")
        self._add("bt_le_adv_start", "zephyr", "ble", "config", _cls, "bt_le_adv_start")
        self._add("bt_le_scan_start", "zephyr", "ble", "input", _cls, "bt_le_scan_start")
        self._add("bt_le_scan_stop", "zephyr", "ble", "config", _cls, "bt_le_scan_stop")
