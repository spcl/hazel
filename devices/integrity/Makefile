#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2015 Intel Corporation.
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 6
SO_MINOR := 0

CFLAGS += -I$(SPDK_ROOT_DIR)/lib/bdev/

# DOCA
DEBUG ?= 0
CFLAGS += -I/opt/mellanox/doca/include -Wno-deprecated-declarations -g
ifeq ($(DEBUG),1)
    CFLAGS += -g -fsanitize=address,undefined
endif

C_SRCS = vbdev_integrity.c vbdev_integrity_rpc.c doca_utils.c ipsec.c hashing.c
LIBNAME = bdev_integrity

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
