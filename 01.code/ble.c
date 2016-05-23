#include "common.h"

#define	OP_WRITE_REQ		0x12
#define	OP_WRITE_CMD		0x52

static unsigned char rcv_buff[SEND_BUFF_LEN] = {0x00};
static int run_flag = 0;

void sig_handle(int sig)
{
    fprintf(stdout, "Get a signal %d\n", sig);
    run_flag = 0;
}

static void *thread_recv(void *arg)
{
	int sock = *((int *)arg);
	int ret = -1;
	int i;
	unsigned char opcode;
	unsigned short handle;

	if(sock < 0){
		fprintf(stdout, "thread param invalied %d\n", sock);
		return NULL;
	}	

	while(run_flag){
		usleep(1000000);

		ret = read(sock, rcv_buff, RECV_BUFF_LEN);
		if(ret < 0){
			perror("read fail ");
			continue;
		}else if(ret < 3){
			continue;
		}
		opcode = rcv_buff[0];
		handle = (rcv_buff[2] << 8) | rcv_buff[1];
		fprintf(stdout, "Opcode 0x%02X handle 0x%04X\n", opcode, handle);

		fprintf(stdout, "Read value:");
		for(i = 3; i < ret; i++){
			fprintf(stdout, " 0x%02X", rcv_buff[i]);
		}
		fprintf(stdout, "\n");
	}

	fprintf(stdout, "thread exit\n");
	return NULL;
}
#if 0
static int btRecvBuff(int sock, unsigned char *buf, int len)
{
    int ret = -1;
    int try = 10;
	int i;

    if(NULL == buf || len < 3)
        return -1;

    do{
        ret = read(sock, buf, len);
        if(ret <= 0){
            perror("read failed");
			usleep(1000000);
            continue;
        }
		fprintf(stdout, "read value:");
		for(i = 0; i < ret; i++)
			fprintf(stdout, " 0x%02X", buf[i]);
		fprintf(stdout, "\n");
    }while(-- try && run_flag);

    if(ret < 0){
        fprintf(stdout, "read data timeout\n");
        return -1;
    }

    fprintf(stdout, "len %d opcode 0x%02X\n", ret, buf[0]);
    fprintf(stdout, "0x%02X 0x%02X\n", buf[1], buf[2]);

    return len;
}
#endif
static int btSendBuff(int sock, unsigned char *buf, int len, int w_type, unsigned short handle)
{
    unsigned char t_buf[SEND_BUFF_LEN] = {0x00};
    struct iovec iov;
    int ret = -1;

    if(NULL == buf || len < 0 || len > 20){
        return -1;
    }
    t_buf[0] = w_type;
    t_buf[1] = handle & 0xFF;
    t_buf[2] = (handle << 8) & 0xFF;
    memcpy(&t_buf[3], buf, len);

    iov.iov_base = t_buf;
    iov.iov_len = len + 3;

    ret = writev(sock, &iov, 1);
    if(ret < 0){
        perror("writev failed");
        return -1;
    }else{
		fprintf(stdout, "writev success %d\n", ret);
	}

    return len;
}

/************************************************************************************/
int main(int argc, char *argv[])
{
    int sock = -1;
    int ret = -1;
    struct sockaddr_l2 addr;
    struct sockaddr_l2 other_addr;
    struct bt_security sec;
    unsigned char notify_en[2] = {0x01, 0x00};
	pthread_t t_id;

    sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if(sock < 0){
        perror("socket failed");
        return -1;
    }
    fprintf(stdout, "create socket %d success\n", sock);

    memset(&addr, 0x00, sizeof(addr));
    addr.l2_family = AF_BLUETOOTH;
    str2ba(BD_ANY_ADDR, &addr.l2_bdaddr);
    addr.l2_cid = 4;
    addr.l2_bdaddr_type = 1;

    ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0){
        perror("bind failed");
        goto out;
    }
    fprintf(stdout, "socket bind success\n");

    // opts
    memset(&sec, 0x00, sizeof(sec));
    sec.level = 1;
    ret = setsockopt(sock, SOL_BLUETOOTH, BT_SECURITY, &sec, sizeof(sec));
    if(ret < 0){
        perror("set sock opt failed");
        goto out;
    }
    fprintf(stdout, "Set socket opts success\n");

    //connect
    memset(&other_addr, 0x00, sizeof(other_addr));
    other_addr.l2_family = AF_BLUETOOTH;
    str2ba(DEFAULT_BLE_ADDR, &other_addr.l2_bdaddr);
    other_addr.l2_cid = 4;
    other_addr.l2_bdaddr_type = 1;

    ret = connect(sock, (struct sockaddr *)&other_addr, sizeof(other_addr));
    if(ret < 0){
        perror("connect failed");
        goto out;
    }
    fprintf(stdout, "connect success\n");

    signal(SIGINT, sig_handle);
#if 0
    ret = btSendBuff(sock, &value, 1, OP_WRITE_CMD, 0x0025);
    if(ret < 0)
        goto out;
    fprintf(stdout, "bluetooth send data success\n");
#endif
    usleep(50000);

    run_flag = 1;

    ret = btSendBuff(sock, notify_en, 2, OP_WRITE_REQ, 0x0029);
    if(ret < 0)
        goto out;
    fprintf(stdout, "Enable notify success\n");

#if 0
    usleep(100000);
    ret = btRecvBuff(sock, rcv_buff, RECV_BUFF_LEN);
    if(ret < 0)
        goto out;
    fprintf(stdout, "recv data success\n");
#else
	ret = pthread_create(&t_id, NULL, thread_recv, (void *)&sock);
	if(ret < 0){
		perror("pthread_create failed");
		goto out;
	}
	fprintf(stdout, "Create thread success\n");
#endif

    while(run_flag){
        usleep(500000);     // 500ms
    }

	pthread_join(t_id, NULL);
	usleep(2000000);
out:
    close(sock);

	fprintf(stdout, "Program exit\n");
    return ret;
}
