# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_PEIOS_NTFE) += peios_ntfe.o

peios_ntfe-y := context.o counters.o events.o flow.o identity.o ingest.o \
	       listeners.o main.o policy.o refuse.o report.o seats.o \
	       snapshot.o tags.o
peios_ntfe-$(CONFIG_PEIOS_NTFE_KUNIT) += kunit.o
