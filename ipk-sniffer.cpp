/*
 * Author: Filip Brna, xbrnaf00
 * Projekt: IPK 2.projekt varianta ZETA (Sniffer)
 * datum: 23.4.2021
 */

// potrebne hlavickove subory
#include <iostream>
#include <string>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <ctime>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <linux/types.h>
#include <chrono>
#include <iomanip>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

// globalne premenne potrebne hlavne pri priradovani argumentov
bool i_bool = false;
bool p_bool = false;
bool tcp_bool = false;
bool udp_bool = false;
bool icmp_bool = false;
bool arp_bool = false;
bool n_bool = false;
bool print_interface = false;
int n_val = 1;
int p_val = -1;
std::string i_val;

// funkcia ktora, vypise napovedu, po vypisani napovedy sa ukonci s navratovym kodom 0.
void PrintHelp()
{
    std::cout << "-i <rozhranie>:           (povinny argument)\n\t\t\t  rozhranie je volitelny parameter,\n\t\t\t  ak nebude definovane vypise zoznam aktivnych rozhrani\n"
                 "-p <cislo portu>:         nastav cislo portu\n"
                 "-t alebo --tcp:           zobrazuje iba TCP pakety\n"
                 "-u alebo --udp:           zobrazuje iba UDP pakety\n"
                 "--icmp:                   zobrazuje iba ICMPv4 a ICMPv6 pakety\n"
                 "--arp:                    zobrazuje iba ARP pakety\n"
                 "----------------------------------------------------------------\n"
                 "ak nie je konkretny protokol specifikovany, vypisuju sa vsetky\n"
                 "-n <cislo>:               cislo - pocet paketov, ktore sa zobrazia, ak nie je argument zadany tak sa zobrazi jeden\n";
    exit(0);
}

// funkcia vypisujuca rozhrania, po vypisani rozhrani sa ukonci s navratovym kodom 0.
void printInterfaces()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    int i = 1;
    if (pcap_findalldevs(&interfaces, error_buffer) < 0)
    {
        printf("Error can't get a list of capture devices (function pcap_findalldevs)");
        exit(EXIT_FAILURE);
    }

    while (interfaces->next != NULL)
    {
        printf("%d: %s\n", i, interfaces->name);
        interfaces = interfaces->next;
        i++;
    }
    exit(0);
}

// https://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data/7776146#7776146
// funkcia vypise data zo sniffovaneho paketu
// offset vypísaných bajtov:  výpis bajtov hexa výpis bajtov ASCII (ak je znak nevypiastelny vypise sa ".")
void hexDump(const void *addr, const int len)
{
    int i;
    unsigned char buff[17];
    const unsigned char *pc = (const unsigned char *)addr;
    // kontrola dlzky
    if (len == 0)
    {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0)
    {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
        {
            if (i != 0)
                printf("  %s\n", buff);
            printf("%06x: ", i);
        }
        // vypise hex kod pre specificky charakter
        printf(" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0)
    {
        printf("   ");
        i++;
    }
    // vypise finalny ASCII buffer
    printf("  %s\n", buff);
}

// funkcia ktora osetruje argumenty s ktorymi je spustany sniffer
// nastavuje globalne premenne, ktore su potrebne pre neskorsie nastavovanie filtra
void ProcessArgs(int argc, char **argv)
{
    // bez argumentu vypise zoznam rozhrani
    if (argc == 1)
    {
        print_interface = true;
    }

    // ak je jeden argument zadany a nie je to -i (rozhrania)
    // ani --help (vypis napovedy), vrati chybovy navratovy kod
    if (argc == 2 && std::string(argv[1]) != "-i" && std::string(argv[1]) != "--help")
    {
        printf("Error invalid arguments\n");
        exit(EXIT_FAILURE);
    }

    // prechadzanie argumentov
    std::string argument;
    for (int i = 1; i < argc; i++)
    {
        argument = std::string(argv[i]);
        if (argument == "-i")
        {
            string next_arg;
            try
            {
                next_arg = std::string(argv[i + 1]);
            }
            catch (std::exception)
            {
                print_interface = true; // -i bez zadaneho rozhrania, bude nasledovat vypis rozhrani
                i_val = "";
                continue;
            }
            if (next_arg == "-t" || next_arg == "--tcp" || next_arg == "-u" || next_arg == "--udp" ||
                next_arg == "-p" || next_arg == "-n" || next_arg == "--icmp" || next_arg == "--arp")
            {

                print_interface = true;
            }
            else
            {
                i_val = std::string(argv[i + 1]); // -i so zadanym rohranim
                i_bool = true;
                i++;
                //std::cout << "I set to: " << i_val << std::endl;
            }
        }
        else if (argument == "--tcp" || argument == "-t")
        {
            tcp_bool = true; // zachytavanie TCP protokolov
        }
        else if (argument == "--udp" || argument == "-u")
        {
            udp_bool = true; // zachytavanie UDP protokolov
        }
        else if (argument == "-p")
        {
            try
            {
                p_val = std::stoi(argv[i + 1]); // -p so zadanym portom
                p_bool = true;
                i++;
                //std::cout << "P is set to: " << p_val << std::endl;
            }
            catch (std::exception)
            {
                printf("Error missing second part of -p \n"); // -p bez zadaneho portu, chybovy navratovy kod
                exit(EXIT_FAILURE);
            }
        }
        else if (argument == "-n")
        {
            try
            {
                n_val = std::stoi(argv[i + 1]); // -n so zadanym cislom (symbolizuje pocet paketov ktore vypise)
                n_bool = true;
                i++;
                //std::cout << "N is set to: " << n_val << std::endl;
            }
            catch (std::exception)
            {
                printf("Error missing second part of -n \n"); // -n bez zadaneho cisla, chybovy navratovy kod
                exit(EXIT_FAILURE);
            }
        }
        else if (argument == "--icmp") // zachytavanie ICMP protokolov
        {
            icmp_bool = true;
        }
        else if (argument == "--arp") // zachytavanie ARP protokolov
        {
            arp_bool = true;
        }
        else if (argument == "--help") // vypisanie napovedy
        {
            PrintHelp();
        }
        else // nezname argumenty, chybovy navratovy kod
        {
            printf("Error unvalid arg, for help run with argument --help\n");
            exit(EXIT_FAILURE);
        }
    }
    if (print_interface == true)
    {
        printInterfaces();
    }

    if (udp_bool == false && tcp_bool == false && icmp_bool == false && arp_bool == false)
    {
        udp_bool = true; // ak nebol zadany argument s kokretnymi protokolmi tak bude
        tcp_bool = true; // prebiehat sniffovanie nad vsetkymi moznymi (TCP, UDP, ICMP, ARP)
        icmp_bool = true;
        arp_bool = true;
    }
}

// Funkcia na zaklade hodnot z globalnych premien nastavi filter
std::string SetFilter()
{
    std::string filter = "";
    if (p_val == -1) // nastavenie filtru, nebol zadany argument -p s cislom portu
    {
        if (tcp_bool == true)
        {
            filter = filter + "tcp ||";
        }
        if (udp_bool == true)
        {
            filter = filter + " udp ||";
        }
        if (icmp_bool == true)
        {
            filter = filter + " icmp || icmp6 ||";
        }
        if (arp_bool == true)
        {
            filter = filter + " arp ||";
        }
    }
    else // nastavenie filtru, bol zadany argument -p s cislom portu
    {
        if (tcp_bool == true)
        {
            filter = filter + "(tcp port " + to_string(p_val) + ") ||";
        }
        if (udp_bool == true)
        {
            filter = filter + " (udp port " + to_string(p_val) + ") ||";
        }
        if (icmp_bool == true)
        {
            filter = filter + " icmp || icmp6 ||";
        }
        if (arp_bool == true)
        {
            filter = filter + " arp ||";
        }
    }
    filter = filter.substr(0, filter.size() - 2); // filter konci OR znakom "||", potreba "odstrihnut tieto znaky"
    //std::cout << "Filter set to: " << filter << std::endl;
    return filter;
}

// https://stackoverflow.com/questions/54325137/c-rfc3339-timestamp-with-milliseconds-using-stdchrono
// Funkcia na vypis casu podla formatu RFC3339
std::string now_rfc3339()
{
    const auto now = std::chrono::system_clock::now();
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    const auto c_now = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&c_now), "%FT%T") << '.' << std::setfill('0') << std::setw(3) << millis << "+02:00 ";
    return ss.str();
}

// https://dox.ipxe.org/ipv6_8c.html#a54a82d98c20b9b1ccc276df64cf36971
// Prekonvertuje IPv6 adresu do standartnej notacii
char *inet6_ntoa(const struct in6_addr *in)
{
    static char buf[41]; // ":xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
    char *out = buf;
    char *longest_start = NULL;
    char *start = NULL;
    int longest_len = 1;
    int len = 0;
    char *dest;
    unsigned int i;
    uint16_t value;

    // Naformátujte adresu a vyhlada najdlhšie poradie nul za ucelom zkratenia adresy
    for (i = 0; i < (sizeof(in->s6_addr16) /
                     sizeof(in->s6_addr16[0]));
         i++)
    {
        value = ntohs(in->s6_addr16[i]);
        if (value == 0)
        {
            if (len++ == 0)
                start = out;
            if (len > longest_len)
            {
                longest_start = start;
                longest_len = len;
            }
        }
        else
        {
            len = 0;
        }
        out += sprintf(out, ":%x", value);
    }

    // skrati najdlhsie poradie nul
    if (longest_start)
    {
        dest = strcpy((longest_start + 1),
                      (longest_start + (2 * longest_len)));
        if (dest[0] == '\0')
            dest[1] = '\0';
        dest[0] = ':';
    }
    return ((longest_start == buf) ? buf : (buf + 1));
}

// Funkcia v ktorej prebieha vsetka potrebna praca s paketom a protokolom
// rozdelenie podla paketov, protokolov a nasledne vypis paketu v spravnom formate
void print_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ip *iph;
    struct ip6_hdr *ip6h;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct icmphdr *icmph;
    struct arphdr *arph;
    struct ether_header *ethh;
    struct ether_addr mac_src;
    struct ether_addr mac_dst;
    std::string time;

    // ethernetova hlavicka
    ethh = (struct ether_header *)(packet);
    // funkcia na ulozenie casu do premmenej typu string vo formate RFC3339
    time = now_rfc3339();

    // switch, ktory pracuje na zaklade ethernetoveho typu
    switch (ntohs(ethh->ether_type))
    {
    case ETHERTYPE_IPV6: // case prisluchajuci IPv6 paketu
        ip6h = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        switch (ip6h->ip6_ctlun.ip6_un1.ip6_un1_nxt)  // ked uz mame rozdelene jednotlive pakety na Ipv6 pakety
        {                                             // nasleduje urcenie protokolu TCPv6, UDPv6, ICMPv6
        case 58:                                      //ICMPv6 Protocol
            printf("\n%s", time.data());              // spravny format vypisu, podobny tomu v aplikacii Wireshark
            printf("%s", inet6_ntoa(&ip6h->ip6_src)); // cas IPv6(src) > IPv6(dst), length dlzka
            printf(" > ");
            printf("%s", inet6_ntoa(&ip6h->ip6_dst));
            printf(", lenght %d bytes\n", header->len);
            hexDump(packet, header->len);
            break;

        case 6: //TCP IPv6 Protocol
            printf("TCP IPv6\n");
            /*
            tcph = (struct tcphdr *)(packet + (iph->ip_hl * 4) + sizeof(struct ethhdr));
            printf("\n%s", time.data());
            printf("%s : %u > ", inet_ntoa(iph->ip_src), ntohs(tcph->source));
            printf("%s : %u, lenght %d bytes\n", inet_ntoa(iph->ip_dst), ntohs(tcph->dest), header->len);
            hexDump(packet, header->len);*/
            break;

        case 17: //UDPv6 Protocol
            printf("UDP IPv6\n");
            /*
            udph = (struct udphdr *)(packet + (iph->ip_hl * 4) + sizeof(struct ethhdr));
            printf("\n%s", time.data());
            printf("%s : %u > ", inet_ntoa(iph->ip_src), ntohs(udph->source));
            printf("%s : %u, lenght %d bytes\n", inet_ntoa(iph->ip_dst), ntohs(udph->dest), header->len);
            hexDump(packet, header->len); */
            break;
        }
        break;
    case ETHERTYPE_IP: // case prisluchajuci IPv4 paketu
        iph = (struct ip *)(packet + sizeof(struct ether_header));
        switch (iph->ip_p)                                                                 // ked uz mame rozdelene jednotlive pakety na Ipv4 pakety
        {                                                                                  // nasleduje urcenie protokolu TCP, UDP, ICMP
        case 1:                                                                            //ICMP Protocol
            icmph = (struct icmphdr *)(packet + (iph->ip_hl * 4) + sizeof(struct ethhdr)); // spravny format vypisu, podobny tomu v aplikacii Wireshark
            printf("\n%s", time.data());                                                   // format vypisu: cas IP(src) > IP(dst), length dlzka
            printf("%s > ", inet_ntoa(iph->ip_src));
            printf("%s, lenght %d bytes\n", inet_ntoa(iph->ip_dst), header->len);
            hexDump(packet, header->len);
            break;

        case 6: //TCP Protocol
            tcph = (struct tcphdr *)(packet + (iph->ip_hl * 4) + sizeof(struct ethhdr));
            printf("\n%s", time.data());
            printf("%s : %u > ", inet_ntoa(iph->ip_src), ntohs(tcph->source)); // format vypisu: cas IP : port (src) > IP : port (dst), length dlzka
            printf("%s : %u, lenght %d bytes\n", inet_ntoa(iph->ip_dst), ntohs(tcph->dest), header->len);
            hexDump(packet, header->len);
            break;

        case 17: //UDP Protocol
            udph = (struct udphdr *)(packet + (iph->ip_hl * 4) + sizeof(struct ethhdr));
            printf("\n%s", time.data());
            printf("%s : %u > ", inet_ntoa(iph->ip_src), ntohs(udph->source)); // format vypisu: cas IP : port (src) > IP : port (dst), length dlzka
            printf("%s : %u, lenght %d bytes\n", inet_ntoa(iph->ip_dst), ntohs(udph->dest), header->len);
            hexDump(packet, header->len);
            break;
        }
        break;

    case ETHERTYPE_ARP: // protokol ARP
        arph = (struct arphdr *)(packet + sizeof(struct ethhdr));
        for (int i = 0; i < ETH_ALEN; i++) // naplnenie hodnot src a dst MAC adresy
        {
            mac_src.ether_addr_octet[i] = ethh->ether_shost[i];
            mac_dst.ether_addr_octet[i] = ethh->ether_dhost[i];
        }
        printf("\n%s", time.data());
        printf("%s > ", ether_ntoa(&mac_src));
        printf("%s, lenght %d bytes\n", ether_ntoa(&mac_dst), header->len); // format vypisu: cas MAC (src) > MAC (dst), length dlzka
        hexDump(packet, header->len);
        break;
    }
}

/*
 * Funkcia main na uvod vola funkciu na zpracovanie argumentov,
 * nasleduje nasatavenie filtra a samotne volania funkcii z pcap kniznice, ktore
 * su potrebne pre sniffovanie.
 */
int main(int argc, char **argv)
{
    ProcessArgs(argc, argv);          // nastavienie globalnych premien
    std::string filter = SetFilter(); // nastavenie filtra
    char errbuff[PCAP_ERRBUF_SIZE];
    const char *device = i_val.c_str();
    const u_char *packet;
    pcap_t *sd;
    struct bpf_program bpf_prog;
    bpf_u_int32 net = 0, mask = 0;

    // funkcia pcap_lookupdev nam nastavi sietove rozhranie
    device = pcap_lookupdev(errbuff);
    if (device == NULL)
    {
        printf("Error in pcap_lookupdev()\n");
        exit(EXIT_FAILURE);
    }

    // zistenie masky a IP adresy
    if (pcap_lookupnet(device, &net, &mask, errbuff) == -1)
    {
        printf("Error interface (function pcap_lookupnet)\n");
        exit(EXIT_FAILURE);
    }

    // otvorenie sniffing session v promiskuidnom mode
    sd = pcap_open_live(device, 65535, 1, 1000, errbuff);
    if (sd == NULL)
    {
        printf("Error not opened interface (function pcap_open_live)\n");
        exit(EXIT_FAILURE);
    }

    //skontrolujeme ci sme na ethernete
    if (pcap_datalink(sd) != DLT_EN10MB)
    {
        fprintf(stderr, "%s is not ethernet (function pcap_datalink)\n", device);
        exit(EXIT_FAILURE);
    }

    // kompilacia a nastavenie filtru
    if (mask)
    {
        if (pcap_compile(sd, &bpf_prog, filter.c_str(), 0, mask) == -1)
        {
            printf("Error not compiled filter (function pcap_compile)\n");
            exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(sd, &bpf_prog) == -1)
        {
            printf("Error not set filter (function pcap_setfilter)\n");
            exit(EXIT_FAILURE);
        }
    }

    // funkcia na zachytavanie packetov v pocte n_val
    pcap_loop(sd, n_val, print_packet, NULL);

    //uvolnenie zdrojov
    pcap_close(sd);

    return 0;
}