#include "furi.h"
#include <furi_hal.h>

#include <furi_hal_resources.h>

#define TAG "FTDI_GPIO"

/*
 * FlipTDI TB2 physical SPI mapping.
 *
 * Logical FT232H / MPSSE:
 *   B0 = SCK  -> Flipper Pin 5 -> PB3
 *   B1 = MOSI -> Flipper Pin 2 -> PA7
 *   B2 = MISO -> Flipper Pin 3 -> PA6
 *   B3 = CS   -> Flipper Pin 4 -> PA4
 *
 * B4..B7 are intentionally unavailable: the TB2 bridge owns only SPI pins.
 */
#define gpio_b0 (gpio_ext_pb3)
#define gpio_b1 (gpio_ext_pa7)
#define gpio_b2 (gpio_ext_pa6)
#define gpio_b3 (gpio_ext_pa4)

void ftdi_gpio_set_direction(uint8_t gpio_mask) {
    // B0 / SCK -> gpio_ext_pb3
    if(gpio_mask & 0b00000001) {
        LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_3, LL_GPIO_MODE_OUTPUT);
    } else {
        LL_GPIO_SetPinMode(GPIOB, LL_GPIO_PIN_3, LL_GPIO_MODE_INPUT);
    }

    // B1 / MOSI -> gpio_ext_pa7
    if(gpio_mask & 0b00000010) {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_7, LL_GPIO_MODE_OUTPUT);
    } else {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_7, LL_GPIO_MODE_INPUT);
    }

    // B2 / MISO -> gpio_ext_pa6
    if(gpio_mask & 0b00000100) {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_6, LL_GPIO_MODE_OUTPUT);
    } else {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_6, LL_GPIO_MODE_INPUT);
    }

    // B3 / CS -> gpio_ext_pa4
    if(gpio_mask & 0b00001000) {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_4, LL_GPIO_MODE_OUTPUT);
    } else {
        LL_GPIO_SetPinMode(GPIOA, LL_GPIO_PIN_4, LL_GPIO_MODE_INPUT);
    }
}

void ftdi_gpio_init(uint8_t gpio_mask) {
    /* Preload safe output levels before switching pin modes. This prevents a
     * transient CS-low selection while the USB bridge is starting. */
    furi_hal_gpio_write(&gpio_b0, false);
    furi_hal_gpio_write(&gpio_b1, false);
    furi_hal_gpio_write(&gpio_b3, true);
    furi_hal_gpio_init(&gpio_b0, GpioModeInput, GpioPullNo, GpioSpeedVeryHigh);
    furi_hal_gpio_init(&gpio_b1, GpioModeInput, GpioPullNo, GpioSpeedVeryHigh);
    furi_hal_gpio_init(&gpio_b2, GpioModeInput, GpioPullNo, GpioSpeedVeryHigh);
    furi_hal_gpio_init(&gpio_b3, GpioModeOutputPushPull, GpioPullNo, GpioSpeedVeryHigh);
    ftdi_gpio_set_direction(gpio_mask);
}

void ftdi_gpio_deinit(void) {
    furi_hal_gpio_init(&gpio_b0, GpioModeAnalog, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_init(&gpio_b1, GpioModeAnalog, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_init(&gpio_b2, GpioModeAnalog, GpioPullNo, GpioSpeedLow);
    furi_hal_gpio_init(&gpio_b3, GpioModeAnalog, GpioPullNo, GpioSpeedLow);
}
