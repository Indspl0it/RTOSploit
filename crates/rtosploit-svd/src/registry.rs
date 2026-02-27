//! Known MCU peripheral registry — priority ordering for stub generation.

/// Priority level for peripheral stub generation.
/// Lower number = generate first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Critical = 0,   // Clock, Flash — firmware hangs without these
    High = 1,       // GPIO, UART — commonly polled during init
    Medium = 2,     // Timer, SPI, I2C — needed for full boot
    Low = 3,        // ADC, DAC, DMA — application-specific
}

/// Known peripheral name patterns and their assigned priorities.
static PERIPHERAL_PRIORITY_PATTERNS: &[(&str, Priority)] = &[
    // Critical — P0
    ("RCC",    Priority::Critical),
    ("CLK",    Priority::Critical),
    ("PMC",    Priority::Critical),
    ("CGU",    Priority::Critical),
    ("FLASH",  Priority::Critical),
    ("FMC",    Priority::Critical),
    ("FCR",    Priority::Critical),
    // High — P1
    ("GPIO",   Priority::High),
    ("PORT",   Priority::High),
    ("UART",   Priority::High),
    ("USART",  Priority::High),
    ("LPUART", Priority::High),
    ("UARTE",  Priority::High),
    // Medium — P2
    ("TIM",    Priority::Medium),
    ("TIMER",  Priority::Medium),
    ("TC",     Priority::Medium),
    ("SPI",    Priority::Medium),
    ("I2C",    Priority::Medium),
    ("TWI",    Priority::Medium),
    ("PWM",    Priority::Medium),
    // Low — P3
    ("ADC",    Priority::Low),
    ("DAC",    Priority::Low),
    ("DMA",    Priority::Low),
    ("CAN",    Priority::Low),
    ("USB",    Priority::Low),
    ("ETH",    Priority::Low),
    ("SDMMC",  Priority::Low),
    ("SDIO",   Priority::Low),
];

/// Determine the priority of a peripheral by name.
pub fn peripheral_priority(name: &str) -> Priority {
    let upper = name.to_uppercase();
    for &(pattern, priority) in PERIPHERAL_PRIORITY_PATTERNS {
        if upper.contains(pattern) {
            return priority;
        }
    }
    Priority::Low
}

/// Return peripherals sorted by priority (critical first).
pub fn sort_by_priority<T, F>(items: &mut Vec<T>, name_fn: F)
where
    F: Fn(&T) -> &str,
{
    items.sort_by_key(|item| peripheral_priority(name_fn(item)) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rcc_is_critical() {
        assert_eq!(peripheral_priority("RCC"), Priority::Critical);
        assert_eq!(peripheral_priority("RCC1"), Priority::Critical);
    }

    #[test]
    fn test_gpio_is_high() {
        assert_eq!(peripheral_priority("GPIOA"), Priority::High);
        assert_eq!(peripheral_priority("GPIO0"), Priority::High);
    }

    #[test]
    fn test_uart_is_high() {
        assert_eq!(peripheral_priority("UART0"), Priority::High);
        assert_eq!(peripheral_priority("USART1"), Priority::High);
    }

    #[test]
    fn test_timer_is_medium() {
        assert_eq!(peripheral_priority("TIM1"), Priority::Medium);
        assert_eq!(peripheral_priority("TIMER0"), Priority::Medium);
    }

    #[test]
    fn test_adc_is_low() {
        assert_eq!(peripheral_priority("ADC1"), Priority::Low);
    }

    #[test]
    fn test_unknown_is_low() {
        assert_eq!(peripheral_priority("SOMETHING_WEIRD"), Priority::Low);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Medium);
        assert!(Priority::Medium < Priority::Low);
    }
}
