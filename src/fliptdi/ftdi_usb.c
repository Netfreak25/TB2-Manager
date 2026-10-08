#include "ftdi_usb.h"
#include <furi_hal.h>
#include "ftdi.h"
#include "ftdi_usb_tx.h"
#include <stdlib.h>

#define TAG "FTDI USB"

#define FTDI_USB_VID (0x0403)
#define FTDI_USB_PID (0x6014)

#define FTDI_USB_EP_IN  (0x81)
#define FTDI_USB_EP_OUT (0x02)

#define FTDI_USB_EP_IN_SIZE  (64UL)
#define FTDI_USB_EP_OUT_SIZE (64UL)

#define FTDI_USB_RX_MAX_SIZE       (FTDI_USB_EP_OUT_SIZE)
#define FTDI_USB_MODEM_STATUS_SIZE (sizeof(uint16_t))
#define FTDI_USB_TX_MAX_SIZE       (FTDI_USB_EP_IN_SIZE - FTDI_USB_MODEM_STATUS_SIZE)
#define FTDI_USB_TX_RETRY_TICKS    (1U)
#define FTDI_USB_TX_SELF_RETRY_MAX (4U)

typedef struct {
    uint16_t status;
    uint8_t data[FTDI_USB_TX_MAX_SIZE];
} FtdiTxData;

static usbd_respond ftdi_usb_ep_config(usbd_device* dev, uint8_t cfg);
static usbd_respond
    ftdi_usb_control(usbd_device* dev, usbd_ctlreq* req, usbd_rqc_callback* callback);
static bool ftdi_usb_send(usbd_device* dev, uint8_t* buf, uint16_t len);
static int32_t ftdi_usb_receive(usbd_device* dev, uint8_t* buf, uint16_t max_len);

typedef struct {
    Ftdi* ftdi;
    uint16_t* status;
} FtdiUsbTxSource;

static uint16_t ftdi_usb_prepare_tx(void* context, uint8_t* packet, uint16_t capacity) {
    FtdiUsbTxSource* source = context;
    if(capacity < sizeof(FtdiTxData)) return 0;
    FtdiTxData* tx_data = (FtdiTxData*)packet;
    Ftdi* ftdi = source->ftdi;
    uint16_t status = *source->status;
    tx_data->status = status;
    uint32_t data_len = ftdi_available_tx_buf(ftdi);
    if(data_len > FTDI_USB_TX_MAX_SIZE) data_len = FTDI_USB_TX_MAX_SIZE;
    if(data_len > 0) data_len = ftdi_get_tx_buf(ftdi, tx_data->data, data_len);
    return (uint16_t)(data_len + FTDI_USB_MODEM_STATUS_SIZE);
}

static bool ftdi_usb_submit_tx(void* context, const uint8_t* packet, uint16_t length) {
    return ftdi_usb_send((usbd_device*)context, (uint8_t*)packet, length);
}

typedef enum {
    EventExit = (1 << 0),
    EventReset = (1 << 1),
    EventRx = (1 << 2),
    EventTx = (1 << 3),
    EventTxComplete = (1 << 4),
    EventResetSio = (1 << 5),
    EventTxImmediate = (1 << 6),
    EventPurgeRx = (1 << 7),
    EventPurgeTx = (1 << 8),
    EventSetBitmode = (1 << 9),

    EventAll = EventExit | EventReset | EventRx | EventTx | EventTxComplete | EventResetSio |
               EventTxImmediate | EventPurgeRx | EventPurgeTx | EventSetBitmode,
} FtdiEvent;

struct FtdiUsb {
    FuriHalUsbInterface usb;
    FuriHalUsbInterface* usb_prev;

    FuriThread* thread;
    usbd_device* dev;
    Ftdi* ftdi;
    uint8_t data_recvest[8];
    uint16_t data_recvest_len;

    bool tx_complete;
    bool tx_immediate;
    bool thread_started;
    bool shutting_down;
    bool stop_requested;
    uint16_t bitmode_value;
    uint16_t bitmode_index;
};

static void ftdi_usb_schedule_tx_retry(FtdiUsb* ftdi_usb) {
    if(ftdi_usb->shutting_down) return;
    furi_delay_tick(FTDI_USB_TX_RETRY_TICKS);
    if(!ftdi_usb->shutting_down)
        furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventTx);
}

static int32_t ftdi_thread_worker(void* context) {
    FtdiUsb* ftdi_usb = context;
    usbd_device* dev = ftdi_usb->dev;
    UNUSED(dev);

    uint32_t len_data = 0;
    FtdiTxData tx_data = {0};
    uint16_t* status = ftdi_get_modem_status_uint16_t(ftdi_usb->ftdi);
    FtdiUsbTxSource tx_source = {.ftdi = ftdi_usb->ftdi, .status = status};
    FtdiUsbTxState tx = {0};

    while(true) {
        uint32_t flags = furi_thread_flags_wait(EventAll, FuriFlagWaitAny, FuriWaitForever);

        /* Teardown wins over queued endpoint work. The USB interface is already
         * disconnected when deinit raises this flag. */
        if(flags & EventExit) {
            ftdi_usb_tx_reset(&tx);
            break;
        }

        /* A USB detach resets the stream in deinit and explicitly invalidates
         * a packet that could not be submitted before the detach. */
        if(flags & EventReset) {
            ftdi_usb_tx_reset(&tx);
            ftdi_reset_sio(ftdi_usb->ftdi);
            ftdi_usb->tx_complete = false;
            ftdi_usb->tx_immediate = false;
            flags &= ~(EventTx | EventTxComplete | EventTxImmediate);
        }

        /* Apply parser resets/configuration before any bulk RX from the same
         * host setup sequence. The MPSSE owner serializes these operations. */
        if(flags & EventResetSio) {
            ftdi_usb_tx_reset(&tx);
            ftdi_usb->tx_immediate = false;
            ftdi_reset_sio(ftdi_usb->ftdi);
            /* The configured IN endpoint is initially primed with a ZLP. Queue
             * the status behind its completion instead of losing RESET_SIO
             * when that transfer is still pending. */
            flags |= EventTxImmediate;
        }
        if(flags & EventPurgeRx) ftdi_reset_purge_rx(ftdi_usb->ftdi);
        if(flags & EventPurgeTx) {
            ftdi_usb_tx_reset(&tx);
            ftdi_usb->tx_immediate = false;
            ftdi_reset_purge_tx(ftdi_usb->ftdi);
        }
        if(flags & EventSetBitmode)
            ftdi_set_bitmode(ftdi_usb->ftdi, ftdi_usb->bitmode_value, ftdi_usb->bitmode_index);

        if(flags & EventRx) { //fast flag
            uint8_t buf[FTDI_USB_RX_MAX_SIZE];
            len_data = ftdi_usb_receive(dev, buf, FTDI_USB_RX_MAX_SIZE);
            // if(len_data > 0) {
            //     for(uint32_t i = 0; i < len_data; i++) {
            //         FURI_LOG_RAW_I("%c", (char)buf[i]);
            //     }
            //     FURI_LOG_RAW_I("\r\n");
            // }
            if(len_data > 0) {
                ftdi_set_rx_buf(ftdi_usb->ftdi, buf, len_data);
                ftdi_start_uart_tx(ftdi_usb->ftdi);
            }
            flags &= ~EventRx; // clear flag
        }

        if(flags) {
            if(flags & EventTxComplete) {
                ftdi_usb->tx_complete = true;
                if((tx.pending_length != 0) || (ftdi_usb->tx_immediate) ||
                   (ftdi_available_tx_buf(ftdi_usb->ftdi) != 0)) {
                    ftdi_reset_latency_timer(ftdi_usb->ftdi);
                    flags |= EventTx;
                }
            }

            if(flags & EventTxImmediate) {
                ftdi_usb->tx_immediate = true;
                if(ftdi_usb->tx_complete) {
                    flags |= EventTx;
                }
            }

            if(flags & EventTx) {
                ftdi_usb->tx_complete = false;
                bool was_retrying = tx.retrying;
                if(!tx.pending_length) ftdi_usb->tx_immediate = false;
                FtdiUsbTxStep step = ftdi_usb_tx_attempt(
                    &tx,
                    (uint8_t*)&tx_data,
                    (uint16_t)sizeof(tx_data),
                    ftdi_usb_prepare_tx,
                    &tx_source,
                    ftdi_usb_submit_tx,
                    dev,
                    FTDI_USB_TX_SELF_RETRY_MAX);
                if(step != FtdiUsbTxSubmitted) {
                    /* ftdi_get_tx_buf() is destructive. Keep this exact packet
                    * until the endpoint accepts it instead of popping again. */
                    ftdi_usb->tx_complete = true;
                    if(!was_retrying) FURI_LOG_W(TAG, "bulk IN not ready");
                    if(step == FtdiUsbTxRetry) ftdi_usb_schedule_tx_retry(ftdi_usb);
                }
            }
        }
    }

    return 0;
}

static FtdiUsb* ftdi_cur = NULL;

static void ftdi_usb_runtime_stop(FtdiUsb* ftdi_usb) {
    if(ftdi_usb->thread_started) {
        furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventExit);
        furi_thread_join(ftdi_usb->thread);
        ftdi_usb->thread_started = false;
    }
    if(ftdi_usb->thread) {
        furi_thread_free(ftdi_usb->thread);
        ftdi_usb->thread = NULL;
    }
    if(ftdi_usb->ftdi) {
        ftdi_free(ftdi_usb->ftdi);
        ftdi_usb->ftdi = NULL;
    }
}

static void ftdi_usb_callback_tx_immediate(void* context) {
    FtdiUsb* ftdi_usb = context;
    if(!ftdi_usb || !ftdi_usb->thread || ftdi_usb->shutting_down) return;

    furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventTxImmediate);
}

static void ftdi_usb_init(usbd_device* dev, FuriHalUsbInterface* intf, void* ctx) {
    UNUSED(intf);
    FtdiUsb* ftdi_usb = ctx;
    if(!ftdi_usb || !ftdi_usb->thread || !ftdi_usb->ftdi || ftdi_usb->stop_requested) {
        FURI_LOG_E(TAG, "cannot reinitialize stopped interface");
        return;
    }
    ftdi_cur = ftdi_usb;
    ftdi_usb->dev = dev;
    ftdi_usb->shutting_down = false;

    usbd_reg_config(dev, ftdi_usb_ep_config);
    usbd_reg_control(dev, ftdi_usb_control);
    usbd_connect(dev, true);

    ftdi_set_callback_tx_immediate(ftdi_usb->ftdi, ftdi_usb_callback_tx_immediate, ftdi_usb);
    if(!ftdi_usb->thread_started) {
        furi_thread_start(ftdi_usb->thread);
        ftdi_usb->thread_started = true;
    }
}

static void ftdi_usb_deinit(usbd_device* dev) {
    usbd_reg_config(dev, NULL);
    usbd_reg_control(dev, NULL);

    FtdiUsb* ftdi_usb = ftdi_cur;
    if(!ftdi_usb || ftdi_usb->dev != dev) {
        return;
    }
    ftdi_usb->shutting_down = true;
    ftdi_cur = NULL;
    if(ftdi_usb->stop_requested)
        ftdi_usb_runtime_stop(ftdi_usb);
    else {
        ftdi_reset_sio(ftdi_usb->ftdi);
        if(ftdi_usb->thread_started)
            furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventReset);
    }
}

static bool ftdi_usb_send(usbd_device* dev, uint8_t* buf, uint16_t len) {
    return usbd_ep_write(dev, FTDI_USB_EP_IN, buf, len) == len;
}

static int32_t ftdi_usb_receive(usbd_device* dev, uint8_t* buf, uint16_t max_len) {
    int32_t len = usbd_ep_read(dev, FTDI_USB_EP_OUT, buf, max_len);
    return ((len < 0) ? 0 : len);
}

static void ftdi_usb_wakeup(usbd_device* dev) {
    UNUSED(dev);
}

static void ftdi_usb_suspend(usbd_device* dev) {
    FtdiUsb* ftdi_usb = ftdi_cur;
    if(!ftdi_usb || ftdi_usb->dev != dev) return;
}

static void ftdi_usb_rx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep) {
    UNUSED(event);
    UNUSED(ep);
    FtdiUsb* ftdi_usb = ftdi_cur;
    if(!ftdi_usb || ftdi_usb->dev != dev || ftdi_usb->shutting_down || !ftdi_usb->thread) return;
    furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventRx);
}

static void ftdi_usb_tx_ep_callback(usbd_device* dev, uint8_t event, uint8_t ep) {
    UNUSED(event);
    UNUSED(ep);
    FtdiUsb* ftdi_usb = ftdi_cur;
    if(!ftdi_usb || ftdi_usb->dev != dev || ftdi_usb->shutting_down || !ftdi_usb->thread) return;
    furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventTxComplete);
}

static usbd_respond ftdi_usb_ep_config(usbd_device* dev, uint8_t cfg) {
    switch(cfg) {
    case 0: // deconfig
        if(ftdi_cur && ftdi_cur->thread && !ftdi_cur->shutting_down)
            furi_thread_flags_set(furi_thread_get_id(ftdi_cur->thread), EventReset);
        usbd_ep_deconfig(dev, FTDI_USB_EP_OUT);
        usbd_ep_deconfig(dev, FTDI_USB_EP_IN);
        usbd_reg_endpoint(dev, FTDI_USB_EP_OUT, NULL);
        usbd_reg_endpoint(dev, FTDI_USB_EP_IN, NULL);
        return usbd_ack;
    case 1: // config
        if(!ftdi_cur || ftdi_cur->dev != dev || ftdi_cur->shutting_down) return usbd_fail;
        ftdi_cur->tx_complete = false;
        ftdi_cur->tx_immediate = false;
        usbd_ep_config(
            dev, FTDI_USB_EP_IN, USB_EPTYPE_BULK /* | USB_EPTYPE_DBLBUF*/, FTDI_USB_EP_IN_SIZE);
        usbd_ep_config(
            dev, FTDI_USB_EP_OUT, USB_EPTYPE_BULK /* | USB_EPTYPE_DBLBUF*/, FTDI_USB_EP_OUT_SIZE);
        usbd_reg_endpoint(dev, FTDI_USB_EP_IN, ftdi_usb_tx_ep_callback);
        usbd_reg_endpoint(dev, FTDI_USB_EP_OUT, ftdi_usb_rx_ep_callback);
        /* Prime the configured IN endpoint exactly like the SDK CDC interface.
         * Its completion marks the first real FTDI response writable. */
        if(usbd_ep_write(dev, FTDI_USB_EP_IN, NULL, 0) < 0) return usbd_fail;
        return usbd_ack;
    }
    return usbd_fail;
}

static usbd_respond
    ftdi_usb_control(usbd_device* dev, usbd_ctlreq* req, usbd_rqc_callback* callback) {
    UNUSED(callback);
    UNUSED(dev);

    if(!(req->bmRequestType & (FtdiControlTypeVendor | FtdiControlRecipientDevice))) {
        return usbd_fail;
    }

    FtdiUsb* ftdi_usb = ftdi_cur;
    if(!ftdi_usb || ftdi_usb->dev != dev || ftdi_usb->shutting_down || !ftdi_usb->ftdi ||
       !ftdi_usb->thread) {
        return usbd_fail;
    }

#ifdef FTDI_DEBUG
    furi_log_puts("-----------\r\n");
    char tmp_str[] = "0xFFFFFFFF";
    itoa(req->bmRequestType, tmp_str, 16);
    furi_log_puts(tmp_str);
    furi_log_puts(" ");

    itoa(req->bRequest, tmp_str, 16);
    furi_log_puts(tmp_str);
    furi_log_puts(" ");

    itoa(req->wValue, tmp_str, 16);
    furi_log_puts(tmp_str);
    furi_log_puts(" ");

    itoa(req->wIndex, tmp_str, 16);
    furi_log_puts(tmp_str);
    furi_log_puts(" ");

    itoa(req->wLength, tmp_str, 16);
    furi_log_puts(tmp_str);
    furi_log_puts(" \r\n");
#endif

    switch(req->bmRequestType) {
    case FtdiControlRequestsOut:

        switch(req->bRequest) {
        case FtdiRequestsSiOReqReset:
#ifdef FTDI_DEBUG
            furi_log_puts("ftdi_usb_control OUT\r\n");
#endif
            if(req->wValue == FtdiResetSio) {
#ifdef FTDI_DEBUG
                furi_log_puts("FtdiResetSio\r\n");
#endif
                furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventResetSio);
            }
            if(req->wValue == FtdiResetPurgeRx) {
#ifdef FTDI_DEBUG
                furi_log_puts("FtdiResetPurgeRx\r\n");
#endif
                furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventPurgeRx);
            }
            if(req->wValue == FtdiResetPurgeTx) {
#ifdef FTDI_DEBUG
                furi_log_puts("FtdiResetPurgeTx\r\n");
#endif
                furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventPurgeTx);
            }
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetBitmode:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetBitmode\r\n");
#endif
            ftdi_usb->bitmode_value = req->wValue;
            ftdi_usb->bitmode_index = req->wIndex;
            furi_thread_flags_set(furi_thread_get_id(ftdi_usb->thread), EventSetBitmode);
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetLatencyTimer:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetLatencyTimer\r\n");
#endif
            ftdi_set_latency_timer(ftdi_usb->ftdi, req->wValue, req->wIndex);
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetEventChar:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetEventChar\r\n");
#endif
            //value?????? bool enable:  value |= 1 << 8
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetErrorChar:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetErrorChar\r\n");
#endif
            //value?????? bool enable:  value |= 1 << 8
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetBaudrate:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetBaudrate\r\n");
#endif
            ftdi_set_baudrate(ftdi_usb->ftdi, req->wValue, req->wIndex);
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetData:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetData\r\n");
#endif
            ftdi_set_data_config(ftdi_usb->ftdi, req->wValue, req->wIndex);
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqSetFlowCtrl:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqSetFlowCtrl\r\n");
#endif
            ftdi_set_flow_ctrl(ftdi_usb->ftdi, req->wIndex);
            return usbd_ack;
            break;
        default:
            break;
        }

        break;
    case FtdiControlRequestsIn:
#ifdef FTDI_DEBUG
        furi_log_puts("ftdi_usb_control IN\r\n");
#endif
        switch(req->bRequest) {
        case FtdiRequestsSiOReqGetLatencyTimer:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqGetLatencyTimer\r\n");
#endif
            ftdi_usb->data_recvest[0] = ftdi_get_latency_timer(ftdi_usb->ftdi);
            ftdi_usb->data_recvest_len = 1;
            ftdi_usb->dev->status.data_ptr = ftdi_usb->data_recvest;
            ftdi_usb->dev->status.data_count = ftdi_usb->data_recvest_len;
            return usbd_ack;
            break;

        case FtdiRequestsSiOReqPollModemStatus:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqPollModemStatus\r\n");
#endif
            uint16_t* status = ftdi_get_modem_status_uint16_t(ftdi_usb->ftdi);
            memcpy(ftdi_usb->data_recvest, status, sizeof(uint16_t));
            ftdi_usb->data_recvest_len = req->wLength < sizeof(uint16_t) ? req->wLength :
                                                                           sizeof(uint16_t);
            ftdi_usb->dev->status.data_ptr = ftdi_usb->data_recvest;
            ftdi_usb->dev->status.data_count = ftdi_usb->data_recvest_len;
            return usbd_ack;
            break;
        case FtdiRequestsSiOReqReadPins:
#ifdef FTDI_DEBUG
            furi_log_puts("FtdiRequestsSiOReqReadPins\r\n");
#endif
            ftdi_usb->data_recvest[0] = ftdi_get_bitbang_gpio(ftdi_usb->ftdi);
            ftdi_usb->data_recvest_len = 1;
            ftdi_usb->dev->status.data_ptr = ftdi_usb->data_recvest;
            ftdi_usb->dev->status.data_count = ftdi_usb->data_recvest_len;
            return usbd_ack;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
    return usbd_fail;
}

static const struct usb_string_descriptor dev_manuf_desc = USB_STRING_DESC("FTDI");
static const struct usb_string_descriptor dev_product_desc = USB_STRING_DESC("Core Flasher");

struct FtdiUsbDescriptor {
    struct usb_config_descriptor config;
    struct usb_interface_descriptor intf;
    struct usb_endpoint_descriptor ep_in;
    struct usb_endpoint_descriptor ep_out;
} __attribute__((packed));

static const struct usb_device_descriptor usb_ftdi_dev_descr = {
    .bLength = sizeof(struct usb_device_descriptor),
    .bDescriptorType = USB_DTYPE_DEVICE,
    .bcdUSB = VERSION_BCD(2, 0, 0),
    .bDeviceClass = USB_CLASS_PER_INTERFACE,
    .bDeviceSubClass = USB_SUBCLASS_NONE,
    .bDeviceProtocol = USB_PROTO_NONE,
    .bMaxPacketSize0 = 8, // USB_EP0_SIZE
    .idVendor = FTDI_USB_VID,
    .idProduct = FTDI_USB_PID,
    .bcdDevice = VERSION_BCD(9, 0, 0),
    .iManufacturer = 1, // UsbDevManuf
    .iProduct = 2, // UsbDevProduct
    .iSerialNumber = NO_DESCRIPTOR,
    .bNumConfigurations = 1,
};

static const struct FtdiUsbDescriptor usb_ftdi_cfg_descr = {
    .config =
        {
            .bLength = sizeof(struct usb_config_descriptor),
            .bDescriptorType = USB_DTYPE_CONFIGURATION,
            .wTotalLength = sizeof(struct FtdiUsbDescriptor),
            .bNumInterfaces = 1,
            .bConfigurationValue = 1,
            .iConfiguration = NO_DESCRIPTOR,
            .bmAttributes = USB_CFG_ATTR_RESERVED,
            .bMaxPower = USB_CFG_POWER_MA(500),
        },
    .intf =
        {
            .bLength = sizeof(struct usb_interface_descriptor),
            .bDescriptorType = USB_DTYPE_INTERFACE,
            .bInterfaceNumber = 0,
            .bAlternateSetting = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = USB_CLASS_VENDOR,
            .bInterfaceSubClass = USB_SUBCLASS_VENDOR,
            .bInterfaceProtocol = USB_PROTO_VENDOR,
            .iInterface = 2,
        },
    .ep_in =
        {
            .bLength = sizeof(struct usb_endpoint_descriptor),
            .bDescriptorType = USB_DTYPE_ENDPOINT,
            .bEndpointAddress = FTDI_USB_EP_IN,
            .bmAttributes = USB_EPTYPE_BULK,
            .wMaxPacketSize = FTDI_USB_EP_IN_SIZE,
            .bInterval = 0,
        },
    .ep_out =
        {
            .bLength = sizeof(struct usb_endpoint_descriptor),
            .bDescriptorType = USB_DTYPE_ENDPOINT,
            .bEndpointAddress = FTDI_USB_EP_OUT,
            .bmAttributes = USB_EPTYPE_BULK,
            .wMaxPacketSize = FTDI_USB_EP_OUT_SIZE,
            .bInterval = 0,
        },
};

FtdiUsb* ftdi_usb_start(uint32_t default_hz) {
    FtdiUsb* ftdi_usb = calloc(1, sizeof(FtdiUsb));
    if(!ftdi_usb) return NULL;

    ftdi_usb->thread = furi_thread_alloc();
    ftdi_usb->ftdi = ftdi_alloc(default_hz);
    if(!ftdi_usb->thread || !ftdi_usb->ftdi) {
        if(ftdi_usb->ftdi) ftdi_free(ftdi_usb->ftdi);
        if(ftdi_usb->thread) furi_thread_free(ftdi_usb->thread);
        free(ftdi_usb);
        return NULL;
    }
    furi_thread_set_name(ftdi_usb->thread, "FtdiUsb");
    furi_thread_set_stack_size(ftdi_usb->thread, 1024);
    furi_thread_set_context(ftdi_usb->thread, ftdi_usb);
    furi_thread_set_callback(ftdi_usb->thread, ftdi_thread_worker);

    ftdi_usb->usb_prev = furi_hal_usb_get_config();
    ftdi_usb->usb.init = ftdi_usb_init;
    ftdi_usb->usb.deinit = ftdi_usb_deinit;
    ftdi_usb->usb.wakeup = ftdi_usb_wakeup;
    ftdi_usb->usb.suspend = ftdi_usb_suspend;
    ftdi_usb->usb.dev_descr = (struct usb_device_descriptor*)&usb_ftdi_dev_descr;
    ftdi_usb->usb.str_manuf_descr = (void*)&dev_manuf_desc;
    ftdi_usb->usb.str_prod_descr = (void*)&dev_product_desc;
    ftdi_usb->usb.str_serial_descr = NULL;
    ftdi_usb->usb.cfg_descr = (void*)&usb_ftdi_cfg_descr;

    if(!furi_hal_usb_set_config(&ftdi_usb->usb, ftdi_usb)) {
        FURI_LOG_E(TAG, "USB locked, cannot start Core Flasher");
        ftdi_free(ftdi_usb->ftdi);
        furi_thread_free(ftdi_usb->thread);
        free(ftdi_usb);
        return NULL;
    }
    return ftdi_usb;
}

bool ftdi_usb_stop(FtdiUsb* ftdi_usb) {
    if(!ftdi_usb) return true;
    ftdi_usb->stop_requested = true;
    ftdi_usb->shutting_down = true;
    if(!furi_hal_usb_set_config(ftdi_usb->usb_prev, NULL)) {
        ftdi_usb->stop_requested = false;
        ftdi_usb->shutting_down = false;
        return false;
    }
    /* The synchronous switch has detached this interface. Deinit normally
     * stops the runtime; keep this cleanup idempotent for defensive teardown. */
    if(ftdi_cur == ftdi_usb) ftdi_cur = NULL;
    ftdi_usb_runtime_stop(ftdi_usb);
    free(ftdi_usb);
    return true;
}

bool ftdi_usb_clock_status(FtdiUsb* usb, Tb2SpiClockStatus* status) {
    return usb && usb->ftdi && ftdi_clock_status(usb->ftdi, status);
}
