
#include "sha256.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ip/uip.h"
#include "net/rpl/rpl.h"

#include "net/netstack.h"
#include "dev/button-sensor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678

#define UDP_EXAMPLE_ID  190

char *appdata;
char *t;
 char string[90];
const char text1[100]={"client1"},
		 text2[]={"sadaf"},
		 text3[]={"this"},
		 hash[32];
   int idx;
   SHA256_CTX ctx;
int reply=0;
int flag=0;

char r1,c1;

int keys[8][8] = {    1,2,3,4,5,6,7,8,
		      9,10,11,12,13,14,15,16,
			17,18,19,20,21,22,23,24,
			25,26,27,28,29,30,31,32,
			33,34,35,36,37,38,39,40,
			41,42,43,44,45,46,47,48,
			49,50,51,52,53,54,55,56,
			57,58,59,60,61,62,63,64};

char ALPHABETS[] = "abcdefghijklmnopqrstuvwxyz";

static char ptext[100];
static char cipher[100];
int len,r,c, key, i, j, p,cp;
void decrypt(int r, int c);


static struct uip_udp_conn *server_conn;

void receive_hash();
void receive_msg();


void print_hash(unsigned char hash[]);


void print_hash(unsigned char hash[])
{
   int idx;
	char string[80];
//printf("Hash calulated : \n");
   for (idx=0; idx < 32; idx++)
	string[idx]=hash[idx];
if(strncmp(string,appdata,8)==0)
	//printf("\nAuthenticated!!!\n");
	reply = 1;
else
	//printf("\nNot Authenticated!!!");
	reply = 0;

 //printf("\nthis is string %s",string);




}


void check_hash()
{

sha256_init(&ctx);
   sha256_update(&ctx,text1,strlen(text1));
   sha256_final(&ctx,hash);
//printf("\nthis is %s\n",hash);
   print_hash(hash);
}

PROCESS(udp_server_process, "UDP server process");
AUTOSTART_PROCESSES(&udp_server_process);
/*---------------------------------------------------------------------------*/
static void

tcpip_handler(void)
{
  
//char t[80];
int i,j;
  if(uip_newdata()) {
    appdata = (char *)uip_appdata;
    appdata[uip_datalen()] = 0;
	 }
if(flag%2==0)
	receive_hash();
else
	receive_msg();


}


void receive_hash()
{
	printf("receiving...\n");
 PRINTF("\nReceived hash from client.\n");

printf("\nProcessing...");
check_hash();
  
    PRINTF("\nServer sending reply....\n");
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);

	if(reply==1)
	    uip_udp_packet_send(server_conn,"ACK",sizeof("ACK"));
	else
		uip_udp_packet_send(server_conn,"NACK",sizeof("NACK"));

    	uip_create_unspecified(&server_conn->ripaddr);
flag++;
}


void receive_msg()
{
	
char *data = appdata;

len = strlen(data);

printf("Receiving...\n");


r1 = data[len-2];
c1 = data[len-1];
r = (int)r1 - 48;
c = (int)c1 - 48;
len = len - 3;
i = 0;
while(i<=len)
{
	cipher[i] = data[i];
	i++;
}
cipher[i] = '\0';
printf("\nMessage Received : %s",cipher);
printf("\nCoordinates received is row::%c and col::%c",r1,c1);
printf("\nDecrypting.......");
  decrypt(r,c);
  printf("\nDecrypted message : %s ",ptext);

  
    PRINTF("\nServer sending reply....\n");
    uip_ipaddr_copy(&server_conn->ripaddr, &UIP_IP_BUF->srcipaddr);
		uip_udp_packet_send(server_conn,"Success",sizeof("Success"));

    	uip_create_unspecified(&server_conn->ripaddr);
flag++;
}



void decrypt(int r, int c)
{
       //	getinput();
	key = keys[r][c];
	//key = 3 ;
	len = strlen(cipher);
	for(i=0;i<len;i++)
	{
		cp = (int)cipher[i] - 97;
		//printf("\n%d ",cp);
	if(key>cp)
		p = (26-((key-cp) % 26))% 26;
	
	else
		p = (cp - key) % 26;
	//printf("%d ",p);		
	ptext[i] = ALPHABETS[p];
	}
	//printf("\n decrypted code : ");
	//puts(string);
}




/*----------0-----------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(state == ADDR_TENTATIVE || state == ADDR_PREFERRED) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
      /* hack to make address "final" */
      if (state == ADDR_TENTATIVE) {
	uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
      }
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_server_process, ev, data)
{
  uip_ipaddr_t ipaddr;
  struct uip_ds6_addr *root_if;

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  SENSORS_ACTIVATE(button_sensor);

  PRINTF("UDP server started\n");

#if UIP_CONF_ROUTER
/* The choice of server address determines its 6LoPAN header compression.
 * Obviously the choice made here must also be selected in udp-client.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 * Note Wireshark's IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from link local (MAC) address */
  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
#endif

  uip_ds6_addr_add(&ipaddr, 0, ADDR_MANUAL);
  root_if = uip_ds6_addr_lookup(&ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    dag = rpl_set_root(RPL_DEFAULT_INSTANCE,(uip_ip6addr_t *)&ipaddr);
    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &ipaddr, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
#endif /* UIP_CONF_ROUTER */
  
  print_local_addresses();

  /* The data sink runs with a 100% duty cycle in order to ensure high 
     packet reception rates. */
  NETSTACK_MAC.off(1);

  server_conn = udp_new(NULL, UIP_HTONS(UDP_CLIENT_PORT), NULL);
  if(server_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(server_conn, UIP_HTONS(UDP_SERVER_PORT));

  PRINTF("Created a server connection with remote address ");
  PRINT6ADDR(&server_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n", UIP_HTONS(server_conn->lport),
         UIP_HTONS(server_conn->rport));


  while(1) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    } else if (ev == sensors_event && data == &button_sensor) {
      PRINTF("Initiaing global repair\n");
      rpl_repair_root(RPL_DEFAULT_INSTANCE);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
