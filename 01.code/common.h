#ifndef	__COMMON_H__
#define	__COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/uio.h>

#define	BLE_MTU				20
#define SEND_BUFF_LEN       80
#define RECV_BUFF_LEN      	((BLE_MTU) + 3)

#define	DEFAULT_BLE_ADDR	"B4:99:4C:39:9C:ED"  // {{0xED, 0x9C, 0x39, 0x4C, 0x99, 0xB4}}
#define	BD_ANY_ADDR			"00:00:00:00:00:00"

#endif
