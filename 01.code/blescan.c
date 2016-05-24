#include "common.h"

#define	DEVICE_NAME_LEN	30
#define	ADDR_STR_LEN	18
#define	SCAN_RESULT_MAX	20

typedef struct __DEVICE_DESC{
    char rssi;
	char addr[ADDR_STR_LEN];
	char name[DEVICE_NAME_LEN];
}DeviceDesc;

typedef struct __SCAN_RESULT{
	int num;
	DeviceDesc desc[SCAN_RESULT_MAX];
}ScanResult;
ScanResult s_res;

int run_flag = 0;
int signal_received;

static void sigint_handler(int sig)
{
	fprintf(stdout, "Get a signal %d.\n", sig);
	signal_received = sig;
	run_flag = 0;
}

static bool add_result(const char *addr, const char *name, char rssi)
{
	int i;
	int len1;
	int len2;

	if(NULL == addr || NULL == name)
		return false;

	len1 = strlen(addr);
	len2 = strlen(name);

	for(i = 0; i < s_res.num; i++){
		if(0 == strncmp(s_res.desc[i].addr, addr, len1) && 0 == strncmp(s_res.desc[i].name, name, len2))
			break;
	}

	if(i < s_res.num){
		return false;
	}

	fprintf(stdout, "Get a new: %s\t%d\t%s\n", addr, rssi, name);
    s_res.desc[s_res.num].rssi = rssi;
	memcpy(s_res.desc[s_res.num].addr, addr, len1 + 1);
	memcpy(s_res.desc[s_res.num].name, name, len2 + 1);
	s_res.num ++;

	return true;
}

static bool eir_parse_name(uint8_t *eir, size_t eir_len,
						char *buf, size_t buf_len)
{
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */

	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case EIR_NAME_SHORT:
		case EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return true;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
    return false;
}

static int output_scan_result(int dd, unsigned char filter_type)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	socklen_t olen;
	int len;
    char rssi = 0;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		printf("Could not get socket options\n");
		return -1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		printf("Could not set socket options\n");
		return -1;
	}

	run_flag = 1;
	signal(SIGINT, sigint_handler);

	while (run_flag) {
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EINTR && signal_received == SIGINT) {
				len = 0;
				goto done;
			}

			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto done;
		}

		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		meta = (void *) ptr;

		if (meta->subevent != 0x02)
			goto done;

		/* Ignoring multiple reports */
		info = (le_advertising_info *) (meta->data + 1);
        rssi = (signed char)info->data[info->length];
//		if (check_report_filter(filter_type, info)) {
		if(1){
			char name[30];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			if(eir_parse_name(info->data, info->length, name, sizeof(name) - 1))
			    add_result(addr, name, rssi);
		}
	}

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	if (len < 0)
		return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	int dev_id = -1;
	int dd = -1;
	int err;
	unsigned char own_type = 0x00;			// LE_PUBLIC_ADDRESS;
	unsigned char scan_type = 0x01;
	unsigned char filter_type = 0;
	unsigned char filter_policy = 0x00;
	unsigned short interval = htobs(0x0010);
	unsigned short window = htobs(0x0010);
	unsigned char filter_dup = 0x01;

	dev_id = hci_get_route(NULL);
	if(dev_id < 0){
		fprintf(stdout, "Get route failed.\n");
		return -1;
	}

	dd = hci_open_dev(dev_id);
	if(dd < 0){
		perror("Open hci devices failed");
		return -1;
	}

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window, own_type, filter_policy, 10000);
	if(err < 0){
		perror("Set scan param failed");
		goto out;
	}

	err = hci_le_set_scan_enable(dd, 0x01, filter_dup, 10000);
	if(err < 0){
		perror("Enable scan failed");
		goto out;
	}
	fprintf(stdout, "Start LE scan....\n");

	memset(&s_res, 0x00, sizeof(s_res));
	output_scan_result(dd, filter_type);

	err = hci_le_set_scan_enable(dd, 0x00, filter_dup, 10000);
	if(err < 0){
		perror("Disable scan failed");
		goto out;
	}
out:
	hci_close_dev(dd);
	return err;
}
