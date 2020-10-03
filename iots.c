
#include "sha256.h"
#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ip/uip-udp-packet.h"
#include "sys/ctimer.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif
#include <stdio.h>
#include <string.h>

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID  190

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif

#define START_INTERVAL		(15 * CLOCK_SECOND)
#define SEND_INTERVAL		(PERIOD * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN		1000

 int string[90];

int keys[8][8] = {    1,2,3,4,5,6,7,8,
		      9,10,11,12,13,14,15,16,
			17,18,19,20,21,22,23,24,
			25,26,27,28,29,30,31,32,
			33,34,35,36,37,38,39,40,
			41,42,43,44,45,46,47,48,
			49,50,51,52,53,54,55,56,
			57,58,59,60,61,62,63,64};

char ptext[100] = "confidential";
char cipher[100];
int len, key, i, j, p,cp;
char ALPHABETS[] = "abcdefghijklmnopqrstuvwxyz";
void encrypt(int r, int c);

static struct uip_udp_conn *client_conn;
static uip_ipaddr_t server_ipaddr;



const char text1[]={"client1"},
		 text2[]={"sadaf"},
		 text3[]={"this"},
		 hash[32];
   int idx;
   SHA256_CTX ctx;
int flag=0;

void print_hash(unsigned char hash[]);
void send_epacket(void *ptr);

void print_hash(unsigned char hash[])
{
   int idx;
	char *s;
	int n =0;
printf("hash sent : ");
   for (idx=0; idx < 32; idx++){
	//string[idx] = atoi(hash[idx]);  
	printf("%x",hash[idx]);
     
	
}
printf("%d",string);
  // printf("\n");



}


/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    }
printf("\nServer Respone received is '%s'\n", str);



if(strcmp(str,"ACK")==0)
	send_epacket(str);

else
{	printf("\nDisconnecting.....\n");
	flag=2;
}

	
}


/****************************************************************************/

void send_epacket(void *ptr)
{
  static int seq_id;
  char buf[MAX_PAYLOAD_LEN];
int r,c;
	char *message ="encrypt";
		c = rand() % 8;
		r = rand() % 8;
		c = abs(c);
		r = abs(r);
	
		printf("Coordinates sent is row::%d and col::%d ",r,c);
printf("\nEncrypting.......");
		encrypt(r,c);
 
      	printf("\nSending encrypted messsage....");
printf("\nMessage sent \n");


sprintf(buf, "%s%d%d",cipher,r,c);
  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));

flag++;


}


void encrypt(int r, int c)
{
	

//getinput();
	key = keys[r][c];
	//key = 3;
	len = strlen(ptext);
	for(i=0;i<len;i++)
	{
		p = (int)ptext[i] - 97;
		//printf("%d",p);
		cp = (p + key) % 26;
		cipher[i] = ALPHABETS[cp];
	}
	

}


/*******************************************************************************/


















/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{
  static int seq_id;
  char buf[MAX_PAYLOAD_LEN];
int idx;


	char *s;
	int n =0;
  seq_id++;




// printf("\nhash 1 : ");
   sha256_init(&ctx);
   sha256_update(&ctx,text1,strlen(text1));
   sha256_final(&ctx,hash);



printf("sending hash...");
  printf("\nhash sent : ");
   for (idx=0; idx < 32; idx++)
	PRINTF("%x",hash[idx]);

printf("\n");

 

sprintf(buf,"%s",hash);






  uip_udp_packet_sendto(client_conn, buf, strlen(buf),
                        &server_ipaddr, UIP_HTONS(UDP_SERVER_PORT));
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
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
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

/* The choice of server address determines its 6LoPAN header compression.
 * (Our address will be compressed Mode 3 since it is derived from our link-local address)
 * Obviously the choice made here must also be selected in udp-server.c.
 *
 * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
 * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
 * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
 *
 * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
 */
 
#if 0
/* Mode 1 - 64 bits inline */
   uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);
#elif 1
/* Mode 2 - 16 bits inline */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);
#else
/* Mode 3 - derived from server link-local (MAC) address */
  uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); //redbee-econotag
#endif
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic;
  static struct ctimer backoff_timer;
#if WITH_COMPOWER
  static int print = 0;
#endif

  PROCESS_BEGIN();

  PROCESS_PAUSE();

  set_global_address();
  
  PRINTF("UDP client process started\n");

  print_local_addresses();

  /* new connection with remote host */
  client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL); 
  if(client_conn == NULL) {
    PRINTF("No UDP connection available, exiting the process!\n");
    PROCESS_EXIT();
  }
  udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT)); 

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
  powertrace_sniff(POWERTRACE_ON);
#endif



  etimer_set(&periodic, SEND_INTERVAL);
  while(flag!=2) {
    PROCESS_YIELD();
    if(ev == tcpip_event) {
      tcpip_handler();
    }
    
    if(etimer_expired(&periodic)) {
      etimer_reset(&periodic);
      ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

#if WITH_COMPOWER
      if (print == 0) {
	powertrace_print("#P");
      }
      if (++print == 3) {
	print = 0;
      }
#endif

    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
