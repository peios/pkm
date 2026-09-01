# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_PEIOS_PNP) += peios_pnp.o

peios_pnp-y := ingest.o main.o policy.o seats.o snapshot.o
peios_pnp-$(CONFIG_PEIOS_PNP_KUNIT) += kunit.o
