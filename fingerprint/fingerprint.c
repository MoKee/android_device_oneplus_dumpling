/*
 * Copyright (C) 2014 The Android Open Source Project
 * Copyright (C) 2018 The MoKee Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "FingerprintHalWrapper"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <cutils/log.h>
#include <hardware/hardware.h>
#include <hardware/fingerprint.h>
#include <utils/threads.h>

#define FP_DETECT "/sys/devices/soc/soc:fingerprint_detect/sensor_version"

typedef struct {
    fingerprint_device_t base;
    union {
        fingerprint_device_t *device;
        hw_device_t *hw_device;
    } vendor;
} device_t;

static union {
    const fingerprint_module_t *module;
    const hw_module_t *hw_module;
} vendor;

static int get_sensor_version()
{
    int fd, ret;
    char buf[80];

    fd = open(FP_DETECT, O_RDONLY);
    if (fd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("%s: Failed to open fp_detect: %d %s", __func__, errno, buf);
        ret = -errno;
        goto end;
    }

    if (read(fd, buf, 80) < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("%s: Failed to read fp_detect: %d %s", __func__, errno, buf);
        ret = -errno;
        goto close;
    }

    if (sscanf(buf, "%d", &ret) != 1) {
        ALOGE("%s: Failed to parse fp_detect", __func__);
        ret = -EINVAL;
        goto close;
    }

close:
    close(fd);
end:
    return ret;
}

static int ensure_vendor_module_is_loaded(void)
{
    if (!vendor.module) {
        int ret;

        int sensor_version = get_sensor_version();
        if (sensor_version < 0) {
            ALOGE("%s: Failed to detect sensor version", __func__);
            return 0;
        }

        ALOGI("%s: Loading HAL for sensor version %d", __func__, sensor_version);
        switch (sensor_version) {
            case 0x01:
            case 0x02:
                ALOGI("%s: It's a fpc sensor", __func__);
                ret = hw_get_module_by_class("fingerprint", "fpc", &vendor.hw_module);
                break;
            case 0x03:
                ALOGI("%s: It's a goodix sensor", __func__);
                ret = hw_get_module("gf_fingerprint", &vendor.hw_module);
                break;
            default:
                ALOGE("%s: Unsupported sensor", __func__);
                return 0;
        }

        if (ret) {
            ALOGE("%s: Failed to open vendor module, error %d", __func__, ret);
            vendor.module = NULL;
        } else {
            ALOGI("%s: Loaded vendor module: %s version %x", __func__,
                vendor.module->common.name,
                vendor.module->common.module_api_version);
        }
    }

    return vendor.module != NULL;
}

static uint64_t fingerprint_pre_enroll(struct fingerprint_device *dev) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->pre_enroll(device->vendor.device);
}

static int fingerprint_enroll(struct fingerprint_device *dev,
                                const hw_auth_token_t *hat,
                                uint32_t gid,
                                uint32_t timeout_sec) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->enroll(device->vendor.device, hat, gid, timeout_sec);
}

static int fingerprint_post_enroll(struct fingerprint_device *dev)
{
    device_t *device = (device_t *) dev;
    return device->vendor.device->post_enroll(device->vendor.device);
}

static uint64_t fingerprint_get_auth_id(struct fingerprint_device *dev) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->get_authenticator_id(device->vendor.device);
}

static int fingerprint_cancel(struct fingerprint_device *dev) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->cancel(device->vendor.device);
}

#define MAX_FINGERPRINTS 100

typedef int (*enumerate_2_0) (
    struct fingerprint_device *dev, fingerprint_finger_id_t *results,
    uint32_t *max_size
);

static int fingerprint_enumerate_pre_2_1(struct fingerprint_device *dev)
{
    device_t *device = (device_t *) dev;
    fingerprint_finger_id_t results[MAX_FINGERPRINTS];
    uint32_t n = MAX_FINGERPRINTS;
    enumerate_2_0 enumerate = (enumerate_2_0) device->vendor.device->enumerate;

    int ret = enumerate(device->vendor.device, results, &n);
    if (ret == 0) {
        uint32_t i;
        fingerprint_msg_t msg;

        msg.type = FINGERPRINT_TEMPLATE_ENUMERATING;
        for (i = 0; i < n; i++) {
            msg.data.enumerated.finger = results[i];
            msg.data.enumerated.remaining_templates = n - i - 1;
            device->base.notify(&msg);
        }
    }

    return ret;
}

static int fingerprint_enumerate(struct fingerprint_device *dev)
{
    device_t *device = (device_t *) dev;
    return device->vendor.device->enumerate(device->vendor.device);
}

static int fingerprint_remove(struct fingerprint_device *dev,
                                uint32_t gid, uint32_t fid) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->remove(device->vendor.device, gid, fid);
}

static int fingerprint_set_active_group(struct fingerprint_device *dev,
                                        uint32_t gid, const char *store_path) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->set_active_group(device->vendor.device, gid, store_path);
}

static int fingerprint_authenticate(struct fingerprint_device *dev,
                                    uint64_t operation_id, uint32_t gid) {
    device_t *device = (device_t *) dev;
    return device->vendor.device->authenticate(device->vendor.device, operation_id, gid);
}

static int set_notify_callback(struct fingerprint_device *dev,
                                fingerprint_notify_t notify) {
    device_t *device = (device_t *) dev;
    device->base.notify = notify;
    return device->vendor.device->set_notify(device->vendor.device, notify);
}

static int fingerprint_close(hw_device_t *device)
{
    device_t *dev = (device_t *) device;
    int ret = dev->base.common.close(dev->vendor.hw_device);
    free(dev);
    return ret;
}

static int fingerprint_open(const hw_module_t* module, const char *id,
                            hw_device_t** device)
{
    int ret;
    device_t *dev;

    if (device == NULL) {
        ALOGE("%s: NULL device on open", __func__);
        return -EINVAL;
    }

    if (!ensure_vendor_module_is_loaded()) {
        return -EINVAL;
    }

    dev = (device_t *) calloc(sizeof(*dev), 1);
    if (!dev) {
        ALOGE("%s: failed to allocate memory", __func__);
        return -ENOMEM;
    }

    ret = vendor.module->common.methods->open(vendor.hw_module, id, &dev->vendor.hw_device);
    if (ret) {
        ALOGE("%s: failed to open, error %d\n", __func__, ret);
        free(dev);
        return ret;
    }

    dev->base.common.tag = HARDWARE_DEVICE_TAG;
    dev->base.common.version = dev->vendor.device->common.version;
    dev->base.common.module = (struct hw_module_t*) module;
    dev->base.common.close = fingerprint_close;

    dev->base.pre_enroll = fingerprint_pre_enroll;
    dev->base.enroll = fingerprint_enroll;
    dev->base.post_enroll = fingerprint_post_enroll;
    dev->base.get_authenticator_id = fingerprint_get_auth_id;
    dev->base.cancel = fingerprint_cancel;
    if (vendor.module->common.module_api_version >= FINGERPRINT_MODULE_API_VERSION_2_1) {
        dev->base.enumerate = fingerprint_enumerate;
    } else {
        dev->base.enumerate = fingerprint_enumerate_pre_2_1;
    }
    dev->base.remove = fingerprint_remove;
    dev->base.set_active_group = fingerprint_set_active_group;
    dev->base.authenticate = fingerprint_authenticate;
    dev->base.set_notify = set_notify_callback;
    dev->base.notify = NULL;

    *device = (hw_device_t*) dev;
    return 0;
}

static struct hw_module_methods_t fingerprint_module_methods = {
    .open = fingerprint_open,
};

fingerprint_module_t HAL_MODULE_INFO_SYM = {
    .common = {
        .tag                = HARDWARE_MODULE_TAG,
        .module_api_version = FINGERPRINT_MODULE_API_VERSION_2_1,
        .hal_api_version    = HARDWARE_HAL_API_VERSION,
        .id                 = FINGERPRINT_HARDWARE_MODULE_ID,
        .name               = "Fingerprint HAL Wrapper for OnePlus 5T",
        .author             = "XiNGRZ",
        .methods            = &fingerprint_module_methods,
        .dso = NULL,        /* remove compilation warnings */
        .reserved = {0},    /* remove compilation warnings */
    },
};
