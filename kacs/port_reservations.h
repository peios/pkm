/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PKM_KACS_PORT_RESERVATIONS_H
#define PKM_KACS_PORT_RESERVATIONS_H

#include <linux/types.h>

/*
 * Port reservations (<pkm/net.h>): the registry-backed table behind the
 * inet socket_bind check. Read from
 * Machine\System\Network\TcpIp\PortReservations through the LCS
 * self-configuration path — discovered at first-source registration,
 * refreshed on the internal watch — and published whole to the KACS Rust
 * runtime, which keeps the last known-good table (or the compiled-in
 * fallback) if a load is rejected.
 */
long pkm_kacs_port_reservations_root_discover_from_machine_hive(
	u32 source_id, const u8 machine_root_guid[16], bool *present_out,
	u8 port_guid_out[16]);
long pkm_kacs_port_reservations_refresh_from_key(u32 source_id,
						 const u8 port_guid[16]);

#endif /* PKM_KACS_PORT_RESERVATIONS_H */
