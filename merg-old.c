#include <pcap.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN_FILENAME    40

char err[PCAP_ERRBUF_SIZE];

struct pkt_id {
    struct pcap_pkthdr hdr;
    unsigned char *data;
};

struct pcap_id {
    char name[MAX_LEN_FILENAME];
    pcap_t *cap;
    struct timeval start_tm;
    struct timeval end_tm;
    int pkt_num;
    int group_id;
};

int compare(const void *a, const void *b)
{
    int res;

    res = (*(struct pcap_id **)a)->start_tm.tv_sec - (*(struct pcap_id **)b)->start_tm.tv_sec;
    if (!res)
        res = (*(struct pcap_id **)a)->start_tm.tv_usec - (*(struct pcap_id **)b)->start_tm.tv_usec;
    return res;
}

int pkt_compare(const void *a, const void *b)
{
    int res;

    res = (*(struct pkt_id **)a)->hdr.ts.tv_sec - (*(struct pkt_id **)b)->hdr.ts.tv_sec;
    if (!res)
        res = (*(struct pkt_id **)a)->hdr.ts.tv_usec - (*(struct pkt_id **)b)->hdr.ts.tv_usec;
    return res;
}

/* Sortuje ukazatele podla timestampu */
void sort_pcaps(struct pcap_id **p, const int num)
{
    qsort(p, num, sizeof(struct pcap_id *), compare);
}

void sort_packets(struct pkt_id **p, const int num)
{
    qsort(p, num, sizeof(struct pkt_id *), pkt_compare);
}

/*
*   Precita timestamp z prveho paketu zo suboru a ulozi
*   vrati 0 ak je vsetko OK
*/
int get_pcap_ts_num(struct pcap_id *const p)
{
    struct pcap_pkthdr hdr;

    p->cap = pcap_open_offline(p->name, err);
    if (p->cap == NULL) {
        fprintf(stderr, "%s:%s\n", p->name, err);
        return -1;
    }
    if (pcap_next(p->cap, &hdr) == NULL) {
        p->start_tm.tv_sec = p->start_tm.tv_usec = 0;
        return 0;
    }
    p->start_tm = hdr.ts;
    p->pkt_num = 1;
    while (pcap_next(p->cap, &hdr) != NULL)
        p->pkt_num++;
    p->end_tm = hdr.ts;
    pcap_close(p->cap);
    return 0;
}


/*
*   Vyplni meno, ts kazdej struktury
*   vrati 0 ak je vsetko OK
*/
int read_pcap_files(struct pcap_id **const p, char **file_names, const int num)
{
    int i, len, res;

    for (i = 0; i < num; i++) {
        len = strlen(file_names[i]);
        if (len > MAX_LEN_FILENAME) {
            fprintf(stderr, "Too long name(s)\n");
            return -1;
        }
        strncpy(p[i]->name, file_names[i], len);
        p[i]->group_id = 0;
        res = get_pcap_ts_num(p[i]);
        if (res)
            return -1;
    }
    return 0;
}

int compare_ts(const struct timeval *a, const struct timeval *b)
{
    int res;

    res = a->tv_sec - b->tv_sec;
    if (!res)
        res = a->tv_usec - b->tv_usec;
    return res;
}

/*
*   Vytvori grupy suborov, kt. sa prekrivaju
*   vrati 0 ak je OK, 1 ak ziadny subor nema grupu (su prazdne)
*/
int group_pcaps(struct pcap_id **p, const int num)
{
    int i = 0, gr_id = 1;
    struct timeval last_tm;

    while (!p[i]->start_tm.tv_sec && (i < num))
        i++;
    if (i >= num) {
        fprintf(stderr, "There's no packet in pcap files!\n");
        return 1;
    }
    for (;;) {
        if (p[i]->group_id == 0)
            p[i]->group_id = gr_id;
        last_tm = p[i]->end_tm;
        if(++i >= num)
            break;
        if (compare_ts(&last_tm, &p[i]->start_tm) <= 0)
            p[i]->group_id = ++gr_id;
    }
    return 0;
}

void free_pcaps(struct pcap_id **const p, const int num)
{
    int i;

    if (p == NULL)
        return;
    for (i = 0; i < num; i++)
        free(p[i]);
    free(p);
}

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

struct pkt_id **alloc_packets(int num)
{
    struct pkt_id **p;
    int i;

    p = malloc(num * sizeof(struct pkt_id *));
    if (p == NULL)
        return NULL;
    for (i = 0; i < num; i++) {
        p[i] = malloc(sizeof(struct pkt_id));
        if (p[i] == NULL)
            return NULL;
    }
    return p;
}

void free_packets(struct pkt_id **p, int num)
{
    int i;

    if (p == NULL)
        return;
    for (i = 0; i < num; i++) {
        if (p[i]->data != NULL)
            free(p[i]->data);
        free(p[i]);
    }
    free(p);
}

int merge_pcaps(char *out_name, struct pcap_id **p, int num)
{
    pcap_dumper_t *out_cap;
    struct pkt_id **pkts;
    int i = 0, j, gr_id = 1, sort;
    unsigned int sum, cnt;
    struct pcap_pkthdr tmp_hdr;
    const u_char *tmp_data;

    while (p[i]->group_id == 0) i++;

    p[0]->cap = pcap_open_offline(p[0]->name, err); // otvorim vystup (potrebujem sparovat s nejakym vstupom,
    out_cap = pcap_dump_open(p[0]->cap, out_name);  // tak som pouzil prvy cap)
    pcap_close(p[0]->cap);

    for (;;) {
        sum = cnt = sort = 0;
        for (j = i; (j < num) && (p[j]->group_id == gr_id); j++) {     //ziskam pocet paketov v grupe
            sum += p[j]->pkt_num;
        }
        if (!sum) break;        //ak nie je ziadny dalsi paket, tak koncim
        if ((j - i) > 1)        //zisti ci 1 grupa == viac subor
            sort = 1;
        pkts = alloc_packets(sum);
        for (; (i < num) && (p[i]->group_id == gr_id); i++) {      //precitam vsetky pakety zo vsetkych suborov v grupe
            p[i]->cap = pcap_open_offline(p[i]->name, err);
            while ((tmp_data = pcap_next(p[i]->cap, &tmp_hdr)) != NULL) {   //cita vestky pakety z 1 sub.
                pkts[cnt]->hdr = tmp_hdr;
                pkts[cnt]->data = malloc(tmp_hdr.caplen);
                memcpy(pkts[cnt]->data, tmp_data, tmp_hdr.caplen);
                cnt++;  //celkovy index paketov
            }
            pcap_close(p[i]->cap);
        }
        if (sort)
            sort_packets(pkts, sum);
        for (j = 0; j < sum; j++)
            pcap_dump((u_char *) out_cap, &pkts[j]->hdr, pkts[j]->data);
        pcap_dump_flush(out_cap);
        gr_id++;
        free_packets(pkts, sum);
    }
    pcap_dump_close(out_cap);
    return 0;
}

int main(int argc, char **argv)
{
    struct pcap_id **caps;
    int num_caps, i;

    if (argc < 2) {
        fprintf(stderr, "Need input files\n");
        return 1;
    }

    num_caps = argc - 1;
    caps = alloc_pcaps(num_caps);
    if (caps == NULL)
        return 1;
    if (read_pcap_files(caps, &argv[1], num_caps)) {
        free_pcaps(caps, num_caps);
        return 1;
    }
    sort_pcaps(caps, num_caps);
    if (group_pcaps(caps, num_caps)) {
        free_pcaps(caps, num_caps);
        return 1;
    }
    merge_pcaps("output", caps, num_caps);

//    for (i = 0; i < num_caps; i++) {
//        printf("---%s---\n", caps[i]->name);
//        printf("Number of packets: %d\n", caps[i]->pkt_num);
//        printf("group: %d\n", caps[i]->group_id);
//        printf("start_time:\n\tsek:%lu\n\tusek:%lu\n", caps[i]->start_tm.tv_sec, caps[i]->start_tm.tv_usec);
//        printf("end_time:\n\tsek:%lu\n\tusek:%lu\n\n", caps[i]->end_tm.tv_sec, caps[i]->end_tm.tv_usec);
//    }

    free_pcaps(caps, num_caps);

    return 0;
}
