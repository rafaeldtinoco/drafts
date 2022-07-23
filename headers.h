#ifndef _HEADERS_H
#define _HEADERS_H

#define EPERM        1  /* Operation not permitted */
#define ENOENT       2  /* No such file or directory */
#define ESRCH        3  /* No such process */
#define EINTR        4  /* Interrupted system call */
#define EIO          5  /* I/O error */
#define ENXIO        6  /* No such device or address */
#define E2BIG        7  /* Argument list too long */
#define ENOEXEC      8  /* Exec format error */
#define EBADF        9  /* Bad file number */
#define ECHILD      10  /* No child processes */
#define EAGAIN      11  /* Try again */
#define ENOMEM      12  /* Out of memory */
#define EACCES      13  /* Permission denied */
#define EFAULT      14  /* Bad address */
#define ENOTBLK     15  /* Block device required */
#define EBUSY       16  /* Device or resource busy */
#define EEXIST      17  /* File exists */
#define EXDEV       18  /* Cross-device link */
#define ENODEV      19  /* No such device */
#define ENOTDIR     20  /* Not a directory */
#define EISDIR      21  /* Is a directory */
#define EINVAL      22  /* Invalid argument */
#define ENFILE      23  /* File table overflow */
#define EMFILE      24  /* Too many open files */
#define ENOTTY      25  /* Not a typewriter */
#define ETXTBSY     26  /* Text file busy */
#define EFBIG       27  /* File too large */
#define ENOSPC      28  /* No space left on device */
#define ESPIPE      29  /* Illegal seek */
#define EROFS       30  /* Read-only file system */
#define EMLINK      31  /* Too many links */
#define EPIPE       32  /* Broken pipe */
#define EDOM        33  /* Math argument out of domain of func */
#define ERANGE      34  /* Math result not representable */

// Ethernet Protocol IDs
#define ETH_P_LOOP	0x0060
#define ETH_P_IP	0x0800

// Protocol families
#define PF_UNSPEC	0
#define PF_LOCAL	1
#define PF_UNIX		PF_LOCAL
#define PF_FILE		PF_LOCAL
#define PF_INET		2
#define PF_BRIDGE	7
#define PF_INET6	10
#define PF_KEY		15
#define PF_NETLINK	16
#define PF_ROUTE	PF_NETLINK
#define PF_PACKET	17
#define PF_IB		27
#define PF_MPLS		28
#define PF_BLUETOOTH	31
#define PF_VSOCK	40
#define PF_XDP		44

/* Address families.  */
#define AF_UNSPEC	PF_UNSPEC
#define AF_LOCAL	PF_LOCAL
#define AF_UNIX		PF_UNIX
#define AF_FILE		PF_FILE
#define AF_INET		PF_INET
#define AF_INET6	PF_INET6
#define AF_KEY		PF_KEY
#define AF_NETLINK	PF_NETLINK
#define AF_ROUTE	PF_ROUTE
#define AF_PACKET	PF_PACKET
#define AF_IB		PF_IB
#define AF_MPLS		PF_MPLS
#define AF_BLUETOOTH	PF_BLUETOOTH
#define AF_VSOCK	PF_VSOCK
#define AF_XDP		PF_XDP

#endif