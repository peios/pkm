# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_PEIOS_PNP) += peios_pnp.o

peios_pnp-y := context.o counters.o events.o flow.o identity.o ingest.o \
	       listeners.o main.o policy.o refuse.o report.o seats.o \
	       snapshot.o tags.o
peios_pnp-$(CONFIG_PEIOS_PNP_KUNIT) += kunit.o
