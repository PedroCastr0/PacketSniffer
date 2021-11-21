/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - Captura pacotes recebidos na interface */
/*-------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* Diretorios: net, netinet, linux contem os includes que descrevem */
/* as estruturas de dados do header dos protocolos   	  	        */

#include <net/if.h>        //estrutura ifr
#include <netinet/ether.h> //header ethernet
#include <netinet/in.h>    //definicao de protocolos
#include <arpa/inet.h>     //funcoes para manipulacao de enderecos IP

#include <netinet/in_systm.h> //tipos de dados

#define BUFFSIZE 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

unsigned char buff1[BUFFSIZE]; // buffer de recepcao

typedef struct {
    int packet_count;
    float ipv4, arp, ipv6;

} PacketSniffer;

PacketSniffer p = {
    .packet_count = 0,
    .ipv4 = 0,
    .arp = 0,
    .ipv6 = 0
};

char type[4];
int sockd;
int on;
struct ifreq ifr;

// Baseado no livro "Hacking the art of exploitation"
void dump(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++) {
        byte = data_buffer[i];
        printf("%02x ", data_buffer[i]);
        if (((i % 16) == 15) || (i == length - 1)) {
            for (j = 0; j < 15 - (i % 16); j++)
                printf("   ");
            printf("| ");
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = data_buffer[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

void intHandler(int dummy) {
    printf("#############################################\n");
    printf("\t\tESTATISTICAS\n\nTotal de pacotes = %d\nPacotes IPV4 = %.2f%%\nPacotes IPV6 = %.2f%%\nPacotes ARP = %.2f%%\n", p.packet_count, (p.ipv4 / p.packet_count) * 100, (p.ipv6 / p.packet_count) * 100, (p.arp / p.packet_count) * 100);
    exit(0);
}

int main(int argc, char **argv) {
    int recv_length;
    signal(SIGINT, intHandler);
    /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
    /* De um "man" para ver os parametros.*/
    /* htons: converte um short (2-byte) integer para standard network byte order. */
    if ((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        printf("Erro na criacao do socket.\n");
        exit(1);
    }

    // O procedimento abaixo eh utilizado para "setar" a interface em modo promiscuo
    strcpy(ifr.ifr_name, "wlo1"); // wlo1 wifi

    if (ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
        printf("erro no ioctl!");

    ioctl(sockd, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sockd, SIOCSIFFLAGS, &ifr);

    // recepcao de pacotes
    while (1) {
        recv_length = recv(sockd, (char *)&buff1, sizeof(buff1), 0x0);
        printf("MAC Destino: %x:%x:%x:%x:%x:%x \n", buff1[0], buff1[1], buff1[2], buff1[3], buff1[4], buff1[5]);
        printf("MAC Origem:  %x:%x:%x:%x:%x:%x \n", buff1[6], buff1[7], buff1[8], buff1[9], buff1[10], buff1[11]);
        printf("Ether type: 0%x%x\n", buff1[12], buff1[13]);
        printf("\n");

        sprintf(type, "0%x%x", buff1[12], buff1[13]);

        if (strcmp(type, "080") == 0) {
            p.ipv4++;
            dump(buff1, recv_length);
        }
        else if (strcmp(type, "086dd") == 0) {
            p.ipv6++;
            dump(buff1, recv_length);
        }
        else if (strcmp(type, "086") == 0) {
            p.arp++;
            dump(buff1, recv_length);
        }

        p.packet_count++;
        printf("\n");
    }
}
