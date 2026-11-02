package backend

// The memory a VM container holds beyond its guest's RAM. The guest gets
// MEMORY_LIMIT less this reserve, unless the operator asked for the full
// limit, in which case Garden adds the reserve to the container's memory limit
// instead (see MemoryReserveMiB). The fixed amounts are what a guest that had
// filled its RAM held beyond that RAM in the container's cgroup, about 80 MiB
// on QEMU and about 35 MiB on Firecracker, with room for more sshd sessions.
const (
	QEMUMemoryReserveMiB        = 128
	FirecrackerMemoryReserveMiB = 96

	// pageTableMiBPerGuestGiB is a conservative 2 MiB for each GiB of guest
	// memory, which is eight bytes of page table for each 4 KiB page.
	pageTableMiBPerGuestGiB = 2
)

// MemoryReserveMiB returns what a VM container of limitMiB MiB keeps for the
// hypervisor, vm-launch, the initramfs, sshd sessions, and the health check
// on kind, in MiB. It is a fixed amount for each hypervisor plus a share that
// grows with the limit, for the host page tables that map the guest's memory.
// vm-launch subtracts it from the limit to size the guest, and Garden adds it
// to the limit when the guest is to have the whole of it.
func MemoryReserveMiB(kind Kind, limitMiB int) int {
	base := QEMUMemoryReserveMiB
	if kind == VMFirecracker {
		base = FirecrackerMemoryReserveMiB
	}
	return base + limitMiB*pageTableMiBPerGuestGiB/1024
}
