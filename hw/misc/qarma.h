#ifndef HW_QARMA_H
#define HW_QARMA_H

#include "hw/arm/virt.h"
#include "qom/object.h"

DeviceState *qarma_create(const VirtMachineState *vms, int qarma);

#endif // HW_QARMA_H
