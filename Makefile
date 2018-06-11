# sun


ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = load_balancer

# all source are stored in SRCS-y
SRCS-y := main.c config.c init.c runtime.c balance.c
SRCS-y += secgw.c
SRCS-y += parser.c
SRCS-y += ipsec.c
SRCS-y += esp.c
SRCS-y += sp4.c
SRCS-y += sp6.c
SRCS-y += sa.c
SRCS-y += rt.c

CFLAGS += -O3 -g -gdwarf-2
CFLAGS += $(WERROR_FLAGS)
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS_sa.o += -diag-disable=vec
endif
CFLAGS_config.o := -D_GNU_SOURCE

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

ifeq ($(DEBUG),1)
CFLAGS += -DIPSEC_DEBUG -fstack-protector-all -O0
endif

include $(RTE_SDK)/mk/rte.extapp.mk
