#pragma once
#include "ftdi.h"
#include <furi.h>
#include <furi_hal.h>

void ftdi_gpio_set_direction(uint8_t gpio_mask);
void ftdi_gpio_init(uint8_t gpio_mask);
void ftdi_gpio_deinit(void);

/*
 * FlipTDI TB2 physical SPI mapping:
 *   B0 = SCK  -> Flipper Pin 5 -> PB3
 *   B1 = MOSI -> Flipper Pin 2 -> PA7
 *   B2 = MISO -> Flipper Pin 3 -> PA6
 *   B3 = CS   -> Flipper Pin 4 -> PA4
 */

static inline uint8_t ftdi_gpio_get_b0(void) { // B0 / SCK -> gpio_ext_pb3
    return (GPIOB->IDR & LL_GPIO_PIN_3) ? 0b00000001 : 0;
}

static inline uint8_t ftdi_gpio_get_b1(void) { // B1 / MOSI -> gpio_ext_pa7
    return (GPIOA->IDR & LL_GPIO_PIN_7) ? 0b00000010 : 0;
}

static inline uint8_t ftdi_gpio_get_b2(void) { // B2 / MISO -> gpio_ext_pa6
    return (GPIOA->IDR & LL_GPIO_PIN_6) ? 0b00000100 : 0;
}

static inline uint8_t ftdi_gpio_get_b3(void) { // B3 / CS -> gpio_ext_pa4
    return (GPIOA->IDR & LL_GPIO_PIN_4) ? 0b00001000 : 0;
}

static inline uint8_t ftdi_gpio_get_b4(void) {
    return 0;
}
static inline uint8_t ftdi_gpio_get_b5(void) {
    return 0;
}
static inline uint8_t ftdi_gpio_get_b6(void) {
    return 0;
}
static inline uint8_t ftdi_gpio_get_b7(void) {
    return 0;
}

static inline void ftdi_gpio_set_noop(uint8_t state) {
    UNUSED(state);
}

static inline void ftdi_gpio_set_b0(uint8_t state) { // B0 / SCK -> gpio_ext_pb3
    if(state) {
        GPIOB->BSRR = LL_GPIO_PIN_3;
    } else {
        GPIOB->BRR = LL_GPIO_PIN_3;
    }
}

static inline void ftdi_gpio_set_b1(uint8_t state) { // B1 / MOSI -> gpio_ext_pa7
    if(state) {
        GPIOA->BSRR = LL_GPIO_PIN_7;
    } else {
        GPIOA->BRR = LL_GPIO_PIN_7;
    }
}

static inline void ftdi_gpio_set_b2(uint8_t state) { // B2 / MISO -> gpio_ext_pa6
    if(state) {
        GPIOA->BSRR = LL_GPIO_PIN_6;
    } else {
        GPIOA->BRR = LL_GPIO_PIN_6;
    }
}

static inline void ftdi_gpio_set_b3(uint8_t state) { // B3 / CS -> gpio_ext_pa4
    if(state) {
        GPIOA->BSRR = LL_GPIO_PIN_4;
    } else {
        GPIOA->BRR = LL_GPIO_PIN_4;
    }
}

static inline void ftdi_gpio_set_b4(uint8_t state) {
    UNUSED(state);
}
static inline void ftdi_gpio_set_b5(uint8_t state) {
    UNUSED(state);
}
static inline void ftdi_gpio_set_b6(uint8_t state) {
    UNUSED(state);
}
static inline void ftdi_gpio_set_b7(uint8_t state) {
    UNUSED(state);
}
