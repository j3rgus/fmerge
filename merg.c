/*  Merge pcap files into one file by timetamps
 *
 *  Copyright (C) 2013  Jerguš Lysý
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <pcap.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#define MAX_LEN_FILENAME    256

/* Globalna premmenna pre zachytanie chyb v ramci libpcap. */
char err[PCAP_ERRBUF_SIZE];

/* Pocet group */
unsigned long num_groups;

/* Struktura obsahuje informacie o jednom pakete. */
struct pkt_id {
    struct pcap_pkthdr hdr;  /* Pcap hlavicka paketu. */
    unsigned long ptr_data;  /* Ukazatel na data (paketu), kt. su ulozene v datovom priestore celeho pcap suboru, */
};

/* Struktura obsahuje infomracie o jednom pcap subore. */
struct pcap_id {
    char name[MAX_LEN_FILENAME];    /* Meno/cesta pcap suboru. */
    pcap_t *cap;                    /* pcap_t s ktorym je pcap subor parovany. */
    struct timeval start_tm;        /* Ts prveho paketu. */
    struct timeval end_tm;          /* Ts posledneho paketu. */
    unsigned long group_id;         /* ID grupy (pouzite v ramci mergovania). */
    unsigned long data_len;         /* Velkost vsetkych dat (paketov) */
    unsigned int pkt_num;           /* Pocet paketov. */
};

/*
 *  Funkcia `compare` je pomocna funkcia pre sort_pcaps, kt. vyzaduje qsort.
 */
int compare(const void *a, const void *b)
{
    int res;

    res = (*(struct pcap_id **)a)->start_tm.tv_sec - (*(struct pcap_id **)b)->start_tm.tv_sec;
    if (!res)
        res = (*(struct pcap_id **)a)->start_tm.tv_usec - (*(struct pcap_id **)b)->start_tm.tv_usec;
    return res;
}

/*
 *  Funkcia `pkt_compare` je pomocna funkcia pre sort_packets, kt. vyzaduje qsort.
 */
int pkt_compare(const void *a, const void *b)
{
    int res;

    res = ((struct pkt_id *)a)->hdr.ts.tv_sec - ((struct pkt_id *)b)->hdr.ts.tv_sec;
    if (!res)
        res = ((struct pkt_id *)a)->hdr.ts.tv_usec - ((struct pkt_id *)b)->hdr.ts.tv_usec;
    return res;
}

/*
 *  Funkcia `sort_pcaps` zoradi pole ukazatelov na strukturu pcap_id vzostupne
 *  podla ts prveho paketu.
 *  Ako parameter bere pole ukazatelov na pcap_id `p` a ich pocet `num`.
 *
 *  Pozn. na zoradenie vyuziva quicksort.
 */
void sort_pcaps(struct pcap_id **p, const int num)
{
    qsort(p, num, sizeof(struct pcap_id *), compare);
}

/*
 *  Funkcia `sort_packets` zoradi pole paketov vzostupne podla ts.
 *  Ako parameter bere pole paketov `p` a pocet paketov `num`.
 *
 *  Pozn. na zoradenie vyuziva quicksort.
 */
void sort_packets(struct pkt_id *p, const int num)
{
    qsort(p, num, sizeof(struct pkt_id), pkt_compare);
}

/*
 *  Funkcia `get_pcap_ts_num` precita ts z pcap suboru a nastavi v strukture pcap_id.
 *  Ako parameter bere ukazatel na pcap_id strukturu.
 *  Vrati 0 v pripade uspechu, 1 ak je otvorenie pcap suboru neuspesne.
 */
int get_pcap_ts_num(struct pcap_id *const p)
{
    struct pcap_pkthdr hdr;

    p->cap = pcap_open_offline(p->name, err);
    if (p->cap == NULL) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }

    /* Precitam prvu hlavicku pcap suboru. Ak je subor prazdny, tak nastavim cas na 0 a skoncim. */
    if (pcap_next(p->cap, &hdr) == NULL) {
        p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
        return 0;
    }

    /* Ak subor nie je prazdny, tak vyplnim strukturu pcap_id s nacitanymi udajmi. */
    p->start_tm = hdr.ts;
    p->data_len = hdr.caplen;
    p->pkt_num = 1;

    /* Citam pakety az na koniec suboru a zaznamenavam pocet vsetkych paketov a celkovu velkost dat. */
    while (pcap_next(p->cap, &hdr) != NULL) {
        p->data_len += hdr.caplen;
        p->pkt_num++;
    }

    /* Poznacim si ts posledneho paketu. */
    p->end_tm = hdr.ts;
    pcap_close(p->cap);
    return 0;
}


/*
 *  Funkcia `read_pcap_files` nacita vsetky pcap subory do pcap_id struktury.
 *  Ako parametre vezme pcap_id strukturu `p`, pole ukazatelov na mena suborov `file_names`
 *  a pocet tychto suborov `num`.
 *  V pripade uspechu vrati 0, v pripade neuspechu vrati 1 a vypise chybu.
 *
 *  Pozn. Maximalna dlzka vstupneho mena pre pcap subor je 255 znakov.
 */
int read_pcap_files(struct pcap_id **const p, char **file_names, const int num)
{
    int i, len, res;

    for (i = 0; i < num; i++) {
        len = strlen(file_names[i]);
        if (len > MAX_LEN_FILENAME) {
            fprintf(stderr, "Too long name(s)\n");
            return 1;
        }

        /* Nastavim meno/cestu pcap suboru v strukture pcap_id. */
        strncpy(p[i]->name, file_names[i], len);

        /* Vsetky struktury maju id grupy nastevene na 0. */
        p[i]->group_id = 0;

        /* Pre nastavenie ts struktury sluzi funkcia `get_pcap_ts_num`. */
        res = get_pcap_ts_num(p[i]);
        if (res)
            return 1;
    }
    return 0;
}

/*
 *  Funkcia `compare_ts` porovna dve casove znamky (timestamp).
 *  Parametre `a` a `b` oznacuju ts. Vrati rozdiel casov `a`-`b`.
 */
int compare_ts(const struct timeval *a, const struct timeval *b)
{
    int res;

    res = a->tv_sec - b->tv_sec;
    if (!res)
        res = a->tv_usec - b->tv_usec;
    return res;
}

/*
 *  Funkcia `group_pcaps` zaradi jednotlive pcap_id struktury do grup.
 *  Ako parametre berie pole ukazatelov na pcap_id `p` a pocet ukazatelov.
 *  Vrati 0 v pripade uspechu, 1 v pripade neuspechu.
 */
int group_pcaps(struct pcap_id **p, const int num, int print)
{
    int index = 0;
    int gr_id = 1;
    struct timeval last_tm = {0, 0};

    /* Vsetky polozky struktury, kt. nemaju nastaveny ts, resp. su prazdne vynechaj. */
    while (!p[index]->start_tm.tv_sec && (index < num))
        index++;

    /* Ak je pocet tychto struktur rovny celkovemu pocty, tak skonci. */
    if (index >= num) {
        return 1;
    }

    /* Cykli pokial je k dispozicii nejaky pcap subor (struktura pcap_id). */
    for (;;) {

        /* Strukturu zaradim do posledne zaznamenanej grupy. */
        p[index]->group_id = gr_id;

        /* Poznacim si doteraz najvyssi ts doteraz prehladavanych struktur. */
        last_tm = (compare_ts(&last_tm, &p[index]->end_tm) < 0) ? p[index]->end_tm : last_tm;
        if(++index >= num)
            break;

        /* Ak nasledujuca struktura sa neprekryva s posledne zaznamenanym ts, tak zvys grupu tejto struktury. */
        if (compare_ts(&last_tm, &p[index]->start_tm) <= 0)
            p[index]->group_id = ++gr_id;
    }
    num_groups = gr_id;
    if (print)
        printf("Number of groups: %lu\n", num_groups);
    return 0;
}

/*
 *  Funkcia `free_pcaps` uvolni pamat alokovanu pre `pcap_id` strukturu.
 *  Treba volat vzdy na koniec prace s touto strukturou.
 *  Ako parameter pozaduje pole ukazatelov na tuto strukturu `p` a pocet ukazatelov `num`.
 */
void free_pcaps(struct pcap_id **const p, const int num)
{
    int i;

    if (p == NULL)
        return;
    for (i = 0; i < num; i++)
        free(p[i]);
    free(p);
}

/*
 *  Funkcia `alloc_pcaps` alokuje pamat pre pcap subory.
 *  Ako parameter berie pocet alok. poloziek `num`.
 *  V pripade uspechu vrati pole struktur `pcap_id`, inak vrati NULL.
 */
struct pcap_id **alloc_pcaps(const int num)
{
    struct pcap_id **p;
    int i;

    p = malloc(num * sizeof(struct pcap_id *));
    if (p == NULL)
        return NULL;
    for (i = 0; i < num; i++) {
        p[i] = malloc(sizeof(struct pcap_id));
        if (p[i] == NULL)
            return NULL;
    }
    return p;
}

/*
 *  Funkcia `strip_payload` "oreze" paket o data.
 *  Ako parameter bere hlavicku pcap `hdr` a data samotneho paketu `pkt`.
 *  V pripade uspechu vrati 0, 1 ak je paket nepodporovaneho formatu alebo
 *  hlavicka nie je kompletna.
 *
 *  Pozn. funguje iba pre Ethernet UDP/IP a TCP/IP. Podla prislusneho zahlavia
 *  zmeni velkost zachyteneho paketu, kt je nasledne vypisany do dump suboru.
 */

int strip_payload(struct pcap_pkthdr *hdr, unsigned char *pkt, int print)
{
    unsigned char *packet = pkt;
    unsigned int capture_len = hdr->caplen;
    unsigned int ip_hdr_len;
    struct ip* ip;
    struct tcphdr *tcp;

    if (capture_len < sizeof(struct ether_header))
        return 1;

    packet += sizeof(struct ether_header);
    capture_len -= sizeof(struct ether_header);

    if (capture_len < sizeof(struct ip))
        return 1;

    ip = (struct ip *) packet;
    ip_hdr_len = ip->ip_hl * 4;

    if (capture_len < ip_hdr_len)
        return 1;

    packet += ip_hdr_len;
    capture_len -= ip_hdr_len;

    if (ip->ip_p == IPPROTO_UDP) {
        if (capture_len >= sizeof(struct udphdr))
            hdr->caplen = sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr);
    } else if (ip->ip_p == IPPROTO_TCP) {
        tcp = (struct tcphdr *) packet;
        if (capture_len >= sizeof(struct tcphdr))
            hdr->caplen = sizeof(struct ether_header) + ip_hdr_len + tcp->doff*4;
    } else {
        if (print)
            fprintf(stderr, "Packet %lu.%lu was not recognized as TCP/UDP - no data stripping is performed!\n", hdr->ts.tv_sec, hdr->ts.tv_usec);
        return 1;
    }
    return 0;
}

/*
 *  Funkcia `merge_pcaps` merguje vsetkyc vstupne pcap subory do jedneho vystupu.
 *  Ako parametre bere meno vystupneho suboru `out_name`, pole ukazatelov na
 *  strukturu pcap_id `p` a pocet pcap suborov `num`.
 *
 *  Pozn. Pokial je nastaveny prepinac -s, tak pakety su skratene o data.
 *  Funguje iba pri Ethernet - IP-TCP/UDP.
 */
int merge_pcaps(char *out_name, struct pcap_id **p, unsigned int num, int strip, int print, int f_sort)
{
    pcap_dumper_t *out_cap;
    struct pkt_id *pkts;
    unsigned long gr_data_len, gr_pkt_num, data_index, pkt_index;
    unsigned long index = 0;
    unsigned long gr_id = 1;
    unsigned long tmp_index, sort;
    const u_char *tmp_data;
    struct pcap_pkthdr tmp_hdr;
    u_char *mapped_data;
    time_t tm;

    /* Subory ktore nie su v ziadnej grupe vynechavam, tj. subory s nulovym ts. */
    while (p[index]->group_id == 0) index++;

    /* Otvorim vystupny subor, kt. je zalozeny na prvom vstupnom subore, tj. kopiruje hlavicku. */
    p[0]->cap = pcap_open_offline(p[0]->name, err);
    out_cap = pcap_dump_open(p[0]->cap, out_name);
    pcap_close(p[0]->cap);

    if (print) {
        time(&tm);
        printf("Merging started: %s", ctime(&tm));
    }

    /* Cylkim az pokial mam k dispozicii nejake data (pakety). */
    for (;;) {
        sort = 0;
        pkt_index = data_index = 0;     /* Indexy pouzite pre pristup k paketom/datam. */
        gr_data_len = gr_pkt_num = 0;   /* Oznacuju velkost dat a pocet vsetkych paketov v ramci jednej grupy. */

        /* V kazdej grupe si zistim velkost dat a pocet paketov. */
        for (tmp_index = index; (tmp_index < num) && (p[tmp_index]->group_id == gr_id); tmp_index++) {
            gr_data_len += p[tmp_index]->data_len;
            gr_pkt_num += p[tmp_index]->pkt_num;
        }

        /* Ak nie su k dispozicii ziadne data (pakety), tak koncim. */
        if (!gr_data_len)
            break;

        /* Zistim kolko pcap suborov je v rovnakej grupe. Ak viac ako jeden, je nutne sortovat. */
        if ((tmp_index - index) > 1)
            sort = 1;

        /* Alokujkem pamat pre pakety. */
        pkts = malloc(gr_pkt_num * sizeof(struct pkt_id));

        /* Alokujem pamat pre data. Kazdy paket ma svoj ukazatel do tohto datoveho priestoru na svoje data. */
        mapped_data = malloc(gr_data_len);

        if (!pkts || !mapped_data) {
            fprintf(stderr, "Memory size not enough large!\nProgram quits...!\n");
            exit(1);
        }

        /* Cyklim cez jednu (aktualnu) grupu. */
        while ((index < num) && (p[index]->group_id == gr_id)) {
            /* Otvorim subor ako pcap. */
            p[index]->cap = pcap_open_offline(p[index]->name, err);

            /* Cyklim cez vsetky pakety v jednom pcap subore. */
            while ((tmp_data = pcap_next(p[index]->cap, &tmp_hdr)) != NULL) {

                /* Ulozim hlavicku pcap paketu. */
                pkts[pkt_index].hdr = tmp_hdr;

                /* Do datovej oblasti zapisem data paketu. */
                memcpy(&mapped_data[data_index], tmp_data, tmp_hdr.caplen);

                /* Datovy index zaznamenam do konkretneho paketu. */
                pkts[pkt_index].ptr_data = data_index;

                /* Zvysim index paketu o 1 a index dat o velkost prave nacitanych dat paketu. */
                pkt_index++;
                data_index += tmp_hdr.caplen;
            }

            /* Zatvorim subor. */
            pcap_close(p[index]->cap);

            /* Zvisim index pcap suboru. */
            index++;
        }

        /* Sortuj ak je treba alebo je to vynutene. */
        if (sort || f_sort)
            sort_packets(pkts, gr_pkt_num);

        /* Vypisem vsetky pakety jednej grupy na vystup. */
        for (tmp_index = 0; tmp_index < gr_pkt_num; tmp_index++) {
            if (strip)
                strip_payload(&pkts[tmp_index].hdr, &mapped_data[pkts[tmp_index].ptr_data], print);
            pcap_dump((u_char *) out_cap, &pkts[tmp_index].hdr, &mapped_data[pkts[tmp_index].ptr_data]);
        }

        if (print) {
            time(&tm);
            printf("%s  Processed %lu of %lu groups\n",ctime(&tm), gr_id, num_groups);
        }

        /* Prejdem na novu grupu. */
        gr_id++;

        /* Uvolnim pamat pre dalsie spracovanie pcap suborov. */
        free(mapped_data);
        free(pkts);
    }
    pcap_dump_close(out_cap);
    if (print) {
        time(&tm);
        printf("\n\nMerging ended in %s",ctime(&tm));
    }
    return 0;
}

/*
 *  Funkcia `usage` vypise help na standartny chybovy vystup.
 */
void usage(void)
{
    fprintf(stderr, "merge 1.0.0\n\n");
    fprintf(stderr, "Usage: ./merge [-sp] -o out_filename [-i in_filename] [<infiles> ...]\n\n");
    fprintf(stderr, "-s                strips packet payload (works only for Ethernet-UDP/IP, TCP/IP)\n");
    fprintf(stderr, "-i <infile>       reading input pcaps from <filename>\n");
    fprintf(stderr, "-o <outfile>      set output filename to <outfile>\n");
    fprintf(stderr, "-f                force to sort packets\n");
    fprintf(stderr, "-p                print some futher information\n");
    fprintf(stderr, "-h                show this message\n\n");
    exit(1);
}

/*
 *  Funkcia `read_input_from_file` cita cesty vst. pcap sub. a uklada.
 *  Ako parametre berie meno suboru z kt. cita vstupy `filename` a
 *  pocet tychto suborov `num`.
 *  V pripade uspechu vrati alok. pamat s menami vst. suborov a nastavi
 *  num na pocet tycho suborov. V pripade neuspechu vrati NULL a `num`=0.
 *
 *  Pozn. struktura vstupneho suboru je, ze 1 riadok = 1 cesta pre pcap subor.
 */
char **read_input_from_file(char *filename, int *num)
{
    char **file_names;
    char tmp_line[MAX_LEN_FILENAME];
    FILE *fd;
    int i, number, fail = 0;
    size_t len;

    number = 0;

    fd = fopen(filename, "r");
    if (fd == 0) {
        fprintf(stderr, "Can't open input file: %s\n", filename);
        exit(1);
    }

    /* Najprv zistim kolko vst. pcapov budem ukladat. */
    while (fgets(tmp_line, MAX_LEN_FILENAME, fd) != NULL) {
        len = strlen(tmp_line);
        if (!len) {
            fail = 1;
        }
        number++;
    }

    if (!number || fail) {
        fclose(fd);
        return NULL;
    }

    file_names = malloc(number * sizeof(char *));
    if (file_names == NULL)
        exit(1);

    /* Vratim sa na zaciatok suboru tak, aby som vsetky subory mohol ulozit. */
    rewind(fd);

    /* Podla poctu tieto vstupy precitam znovu. */
    for (i = 0; i < number; i++) {
        fgets(tmp_line, MAX_LEN_FILENAME, fd);
        len = strlen(tmp_line);
        tmp_line[len-1] = 0;
        file_names[i] = strdup(tmp_line);
    }
    *num = number;
    fclose(fd);
    return file_names;
}

/*
 *  Funkcia `free_input_files` uvolni pamat alokovanu pre mena vstupnych suborov.
 *  Ako parametre berie ukazatel na vst. subory `files` a pocet suborov `num`.
 */
void free_input_files(char **files, int num)
{
    int i;

    for (i = 0; i < num; i++)
        free(files[i]);
    free(files);
}

int main(int argc, char **argv)
{
    struct pcap_id **caps;
    char **in_files = NULL;
    int num_caps;
    int opt;
    int file = 0, strip = 0, print = 0, f_sort = 0;
    char *out_filename = NULL;
    char *in_filename = NULL;

    while ((opt = getopt(argc, argv, "hpfi:so:")) != -1) {
        switch (opt) {
        case 'i':
            file = 1;
            in_filename = optarg;
            break;
        case 's':
            strip = 1;
            break;
        case 'f':
            f_sort = 1;
            break;
        case 'o':
            out_filename = optarg;
            break;
        case 'p':
            print = 1;
            break;
        case 'h':
        case '?':
            usage();
        }
    }
    if (!out_filename) {
        fprintf(stderr, "An output file must be set with -o.\n");
        return 1;
    }
    if (file && !in_filename) {
        fprintf(stderr, "You must specify an input file name!\n");
        return 1;
    }
    if (!file) {
        num_caps = argc - optind;
        in_files = &argv[optind];
    }
    else {
        in_files = read_input_from_file(in_filename, &num_caps);
    }
    if (!in_files || (num_caps < 1)) {
        fprintf(stderr, "Wrong or no pcap file!\n");
        return 1;
    }
    caps = alloc_pcaps(num_caps);
    if (caps == NULL)
        return 1;
    if (read_pcap_files(caps, in_files, num_caps)) {
        free_pcaps(caps, num_caps);
        return 1;
    }
    sort_pcaps(caps, num_caps);
    if (group_pcaps(caps, num_caps, print)) {
        fprintf(stderr, "There's no packet in pcap files!\n");
        free_pcaps(caps, num_caps);
        return 1;
    }
    merge_pcaps(out_filename, caps, num_caps, strip, print, f_sort);
    free_pcaps(caps, num_caps);
    if (file)
        free_input_files(in_files, num_caps);

    return 0;
}
