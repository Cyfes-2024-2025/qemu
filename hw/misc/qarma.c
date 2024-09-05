#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "qemu/typedefs.h"
#include "hw/misc/qarma.h"
#include "crypto/qarma64.h"
#include "sysemu/device_tree.h"

#include <stdint.h>

#define TYPE_QARMA "qarma"


#define REG_KEY_LO 0x0
#define REG_KEY_HI 0x8

#define REG_PLAINTEXT 0x1010
#define REG_TWEAK 0x1018
#define REG_CIPHER 0x1020

#define CHIP_ID 0xBA000002

typedef struct qarma_device_state_s QarmaDeviceState;
DECLARE_INSTANCE_CHECKER(QarmaDeviceState, QARMA_DEVICE, TYPE_QARMA);

#define QARMA_REG_SIZE 0x2000
#define QARMA_REG_PRIV_SIZE 0x1000

struct qarma_device_state_s {
    SysBusDevice parent;
    MemoryRegion iomem;

    uint64_t chip_id;
    uint64_t number;

    uint64_t key_high;
    uint64_t key_low;
    uint64_t tweak;

    uint64_t plaintext;
    uint64_t ciphertext;
    uint64_t decoded_key;
};


static const uint64_t qarma_rounds = 7;

static uint64_t sign_pointer(uint64_t pointer, uint64_t tweak, uint64_t key_lo, uint64_t key_hi) {

    // Use bit 63 to differentiate between high and low address space
    uint64_t mask = 0x7FFFull << 48;

    // Clean the pointer from the bits that will be used for the key
    uint64_t cleaned_pointer = pointer & (~mask);
    uint64_t cipher = qarma64_enc(cleaned_pointer, tweak, key_lo, key_hi, qarma_rounds);

    return cleaned_pointer | (cipher & mask);
}

static uint64_t auth_pointer(uint64_t pointer, uint64_t tweak, uint64_t key_lo, uint64_t key_hi) {

    // Use bit 63 to differentiate between high and low address space
    uint64_t mask = 0x7FFFull << 48;

    // Clean the pointer from the bits that will be used for the key
    uint64_t cleaned_pointer = pointer & (~mask);

    uint64_t signature = pointer & mask;

    uint64_t cipher = qarma64_enc(cleaned_pointer, tweak, key_lo, key_hi, qarma_rounds);

    // Invalid signature
    if ((cipher & mask) != signature) {
        return 0;
    }

    // Signature was valid, we now restore the pointer
    if ((cleaned_pointer >> 63) == 0) {
        return cleaned_pointer;
    }

    return cleaned_pointer | (0xFFFFull << 48);
}


static uint64_t qarma_read(void *opaque, hwaddr addr, unsigned int size) {
    uint64_t cipher;
    QarmaDeviceState *state = (QarmaDeviceState*)opaque;

    qemu_log_mask(LOG_GUEST_ERROR, "qarma: read size: %u\n", size);

    switch(addr) {
    case REG_KEY_LO:
        return state->key_low;
        break;
    case REG_KEY_HI:
        return state->key_high;
        break;
    case REG_PLAINTEXT:
        return state->plaintext;
        break;
    case REG_TWEAK:
        return state->tweak;
        break;
    case REG_CIPHER:
        cipher = state->ciphertext;
        // Reading the ciphertext always destroys it
        state->ciphertext = 0;
        return cipher;
        break;
    default:
        return 0xF0000000 + addr + (size << 16);
        // return 0xDEADBEEF;
        break;
    }

    return 0;
}

static void qarma_write(void *opaque, hwaddr addr, uint64_t value, unsigned int size) {
    QarmaDeviceState *state = (QarmaDeviceState*)opaque;


    switch(addr) {
    case REG_KEY_LO:
        state->key_low = value;
        break;
    case REG_KEY_HI:
        state->key_high = value;
        break;
    case REG_PLAINTEXT:
        state->plaintext = value;
        state->ciphertext = sign_pointer(value, state->tweak, state->key_low, state->key_high);
        break;
    case REG_TWEAK:
        state->tweak = value;
        break;
    case REG_CIPHER:
        // TODO: Send an interrupt in case key is wrong
        state->ciphertext = auth_pointer(value, state->tweak, state->key_low, state->key_high);
        break;
    default:
        break;
    }
}

static const MemoryRegionOps qarma_ops = {
    .read = qarma_read,
    .write = qarma_write,
    .endianness = DEVICE_LITTLE_ENDIAN,

    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    }

};

static void qarma_instance_init(Object *obj) {
    QarmaDeviceState *state = QARMA_DEVICE(obj);

    memory_region_init_io(&state->iomem, obj, &qarma_ops, state, TYPE_QARMA, QARMA_REG_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &state->iomem);

    state->chip_id = CHIP_ID;

    state->key_low = 0xABC;
    state->key_high = 0xDEF;
    state->plaintext = 0;
    state->tweak = 0;
    state->ciphertext = 0;
}

static const TypeInfo qarma_info = {
    .name = TYPE_QARMA,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(QarmaDeviceState),
    .instance_init = qarma_instance_init
};

static void qarma_register_types(void) {
    type_register_static(&qarma_info);
};

type_init(qarma_register_types);

const char compatible[] = "daem,PtrauthDevice-1.0";

DeviceState *qarma_create(const VirtMachineState *vms, int qarma) {
    DeviceState *dev = qdev_new(TYPE_QARMA);
    MachineState *ms = MACHINE(vms);
    char *nodename;

    hwaddr base = vms->memmap[qarma].base;
    hwaddr size = vms->memmap[qarma].size;

    assert(size == QARMA_REG_SIZE);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dev), &error_fatal);
    sysbus_mmio_map(SYS_BUS_DEVICE(dev), 0, base);

    // Register the device inside the device tree
    nodename = g_strdup_printf("/ptrauth@%" PRIx64, base);
    qemu_fdt_add_subnode(ms->fdt, nodename);
    qemu_fdt_setprop(ms->fdt, nodename, "compatible", compatible, sizeof(compatible));

    qemu_fdt_setprop_sized_cells(ms->fdt, nodename, "reg",
                                 2, base,
                                 2, size - QARMA_REG_PRIV_SIZE,
                                 2, base + QARMA_REG_PRIV_SIZE,
                                 2, QARMA_REG_PRIV_SIZE);

    g_free(nodename);

    return dev;
}

