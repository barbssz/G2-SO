#define _POSIX_C_SOURCE 200809L // Enable POSIX.1-2008
#define _XOPEN_SOURCE 700 

// KernelSim do TRAB2: gerencia processos Ax, fala com o InterController,
// envia syscalls de arquivos/diretórios para o SFSS via UDP e trata respostas.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "common.h"

#define true 1
#define false 0

// Probabilidades usadas pelo InterController
#define P1_PROB 10
#define P2_PROB 5

// Estruturas do kernel

typedef enum {
    READY,
    RUNNING,
    BLOCKED,
    TERMINATED
} ProcessState;

// PCB estendido com contadores por operação para depuração.
typedef struct {
    pid_t pid;
    char name[3];
    ProcessState state;
    int pc;
    int blocked_dev;
    int blocked_op;
    int count_read;
    int count_write;
    int count_add;
    int count_rem;
    int count_list;
    int alive;
    int count_d1;
    int count_d2;
} PCB;

// Fila circular simples usada para Ready, bloqueados em D1 e D2.
typedef struct {
    pid_t data[NUM_PROCS_APP];
    int head, tail, size;
} PIDQueue;

typedef struct {
    int type;
} IRQMsg;

typedef enum {
    APP_SYSCALL = 1,
    APP_TERMINATED = 2,
    APP_PROGRESS = 3
} AppMsgType;

typedef struct {
    int type;
    pid_t pid;
    int device;
    int op;
} AppMsg;

typedef enum {
    DEVICE_D1 = 0,
    DEVICE_D2 = 1
} Device;

typedef enum {
    IRQ_TIMESLICE = 0,
    IRQ_IO_D1 = 1,
    IRQ_IO_D2 = 2
} InterruptType;

// Configurações de comunicação
int irq_pipe[2];
int sys_pipe[2];
int sfss_sock = -1;
struct sockaddr_in sfss_addr;
socklen_t sfss_addrlen = 0;

// Estruturas globais
PCB pcb[NUM_PROCS_APP];
PIDQueue ready_q;
PIDQueue blocked_d1_q;
PIDQueue blocked_d2_q;
// Um canal de memória compartilhada por processo Ax.
SharedChannel *channels[NUM_PROCS_APP];
char shm_names[NUM_PROCS_APP][32];
// Estruturas para guardar a resposta do SFSS até o InterController liberar o device.
SFPMessage pending_responses[NUM_PROCS_APP];
int pending_ready[NUM_PROCS_APP];
Device pending_device[NUM_PROCS_APP];
FSOperation pending_operation[NUM_PROCS_APP];

int current_pid = -1;
int got_sigint = 0;

// Prefixos permitidos para paths individuais (A0 é reservado pro compartilhamento).
char *HOME_DIRS[NUM_PROCS_APP] = {"/A1", "/A2", "/A3", "/A4", "/A5"};

// Utilidades de filas
void q_init(PIDQueue *q){ q->head = q->tail = q->size = 0; }
int q_empty(PIDQueue *q){ return q->size == 0; }
int q_full(PIDQueue *q){ return q->size == NUM_PROCS_APP; }
int q_push(PIDQueue *q, pid_t v){
    if(q_full(q)) return false;
    q->data[q->tail] = v;
    q->tail = (q->tail + 1) % NUM_PROCS_APP;
    q->size++;
    return true;
}
pid_t q_pop(PIDQueue *q){
    if(q_empty(q)) return -1;
    pid_t v = q->data[q->head];
    q->head = (q->head + 1) % NUM_PROCS_APP;
    q->size--;
    return v;
}

// Funções auxiliares
int app_index_from_pid(pid_t p){
    for(int i=0;i<NUM_PROCS_APP;i++)
        if(pcb[i].pid == p)
            return i;
    return -1;
}

char* state_str(ProcessState s){
    switch(s){
        case READY: return "READY";
        case RUNNING: return "RUNNING";
        case BLOCKED: return "BLOCKED";
        case TERMINATED: return "TERMINATED";
    }
    return "?";
}

char* dev_str(Device d){
    return d == DEVICE_D1 ? "FILE" : "DIR";
}

char* fsop_str(FSOperation op){
    switch(op){
        case FS_READ: return "READ";
        case FS_WRITE: return "WRITE";
        case FS_ADD_DIR: return "ADD";
        case FS_REM_DIR: return "REM";
        case FS_LIST_DIR: return "LIST";
        default: return "NONE";
    }
}

Device op_device(FSOperation op){
    if(op == FS_READ || op == FS_WRITE)
        return DEVICE_D1;
    return DEVICE_D2;
}

sig_atomic_t waiting_sigcont = 0;

void sigint_handler(int sig){
    (void)sig;
    got_sigint = 1;
    waiting_sigcont = 0; // se estiver em pause, força sair
}

void sigusr_handler(int sig){
    if(sig == SIGCONT){
        waiting_sigcont = 0;
    }
}

void set_nonblock(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Mostra snapshot do escalonador quando usuario dá Ctrl+C.
void print_status_table(){
    printf("\n===== STATUS (Kernel PID = %d) =====\n", getpid());
    printf(" PID     | Name |   State   |  PC  | Blocked | Op   | R  W  A  Rm L | D1 | D2 |\n");
    printf("-------------------------------------------------------------------------------\n");
    for(int i=0;i<NUM_PROCS_APP;i++){
        PCB *p = &pcb[i];
        printf(" %-7d | %-4s | %-9s | %-4d | ", p->pid, p->name, state_str(p->state), p->pc);
        if(p->state == BLOCKED)
            printf("%-6s | %-4s | ", dev_str(p->blocked_dev), fsop_str((FSOperation)p->blocked_op));
        else
            printf("%-6s | %-4s | ", "-", "-");
        printf("%-2d %-2d %-2d %-3d %-2d | %-2d | %-2d |\n",
               p->count_read, p->count_write, p->count_add, p->count_rem, p->count_list,
               p->count_d1, p->count_d2);
    }
    printf(" ReadyQ=%d | BlockedF=%d | BlockedD=%d\n", ready_q.size, blocked_d1_q.size, blocked_d2_q.size);
    printf("================================\n\n");
}

// InterController: gera IRQ0 (timeslice) e IRQ1/2 de conclusão de I/O.
// Processo que gera as IRQs de timeslice e de conclusão de I/O.
void intercontroller_process(){
    close(irq_pipe[0]);
    close(sys_pipe[0]);
    close(sys_pipe[1]);
    srand((unsigned)time(NULL));
    IRQMsg m;
    while(1){
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = TIMESLICE_MS * 1000000L;
        nanosleep(&ts, NULL);
        m.type = IRQ_TIMESLICE;
        if(write(irq_pipe[1], &m, sizeof(m)) < 0)
            exit(0);
        if(rand()%100 < P1_PROB){
            m.type = IRQ_IO_D1;
            ssize_t sent = write(irq_pipe[1], &m, sizeof(m));
            (void)sent;
        }
        if(rand()%100 < P2_PROB){
            m.type = IRQ_IO_D2;
            ssize_t sent = write(irq_pipe[1], &m, sizeof(m));
            (void)sent;
        }
    }
}

// Shared memory --------------------------------------------------------------
// Cria segmentos compartilhados /trab2_ax_* para kernel+A?.
// Cria segmentos de memória compartilhada para cada Ax.
int init_shared_channels(){
    for(int i=0;i<NUM_PROCS_APP;i++){
        snprintf(shm_names[i], sizeof(shm_names[i]), "/trab2_ax_%d", i);
        int fd = shm_open(shm_names[i], O_CREAT | O_RDWR, 0666);
        if(fd < 0){ perror("shm_open"); return -1; }
        if(ftruncate(fd, sizeof(SharedChannel)) < 0){ perror("ftruncate"); return -1; }
        SharedChannel *ch = mmap(NULL, sizeof(SharedChannel), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if(ch == MAP_FAILED){ perror("mmap"); return -1; }
        close(fd);
        memset(ch, 0, sizeof(SharedChannel));
        channels[i] = ch;
    }
    return 0;
}

// Libera e remove os segmentos compartilhados.
void cleanup_shared_channels(){
    for(int i=0;i<NUM_PROCS_APP;i++){
        if(channels[i]) // se foi criado o segmento
            munmap(channels[i], sizeof(SharedChannel)); // desmapeia
        shm_unlink(shm_names[i]); // remove o segmento
    } 
}

// Comunicação com SFSS -------------------------------------------------------
// Abre o socket UDP e grava endereço do SFSS.
int sfss_connect(char *ip, int port){
    sfss_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sfss_sock < 0){ perror("socket"); return -1; }
    memset(&sfss_addr, 0, sizeof(sfss_addr));
    sfss_addr.sin_family = AF_INET;
    sfss_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, ip, &sfss_addr.sin_addr) <= 0){
        perror("inet_pton");
        return -1;
    }
    sfss_addrlen = sizeof(sfss_addr);
    return 0;
}

// Envia requisição SFP (UDP) e aguarda REPLY com timeout de 1s.
// Envia mensagem SFP e aguarda REPLY com timeout de 1s.
int sfss_request(SFPMessage *req, SFPMessage *resp){
    if(sfss_sock < 0) return -1;
    if(sendto(sfss_sock, req, sizeof(SFPMessage), 0, (struct sockaddr*)&sfss_addr, sfss_addrlen) < 0){
        perror("sendto");
        return -1;
    }
    fd_set set;
    FD_ZERO(&set);
    FD_SET(sfss_sock, &set);
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    int rv = select(sfss_sock+1, &set, NULL, NULL, &tv);
    if(rv <= 0){
        fprintf(stderr, "[Kernel] Timeout aguardando SFSS\n");
        return -1;
    }
    ssize_t n = recvfrom(sfss_sock, resp, sizeof(SFPMessage), 0, NULL, NULL);
    if(n < 0){ perror("recvfrom"); return -1; }
    return 0;
}

// Escalonamento --------------------------------------------------------------
// Copia resposta do SFSS para o canal do Ax indicado.
// Copia a resposta pendente para o canal do processo e marca pronta.
void deliver_response_to_app(int idx){
    SharedChannel *ch = channels[idx];
    memcpy(&ch->resp, &pending_responses[idx], sizeof(SFPMessage));
    ch->response_ready = 1;
    pending_ready[idx] = 0;
    pending_device[idx] = (Device)(-1);
}

// Desperta um processo bloqueado no device informado (casado pela resposta pendente).
// Desbloqueia um processo da fila de D1 ou D2 que já tem resposta pronta.
void finish_blocked_process(Device dev){
    PIDQueue *bq = (dev == DEVICE_D1) ? &blocked_d1_q : &blocked_d2_q;
    if(q_empty(bq))
        return;
    int attempts = bq->size;
    while(attempts-- > 0){
        pid_t pid = q_pop(bq);
        int idx = app_index_from_pid(pid);
        if(idx >= 0 && pending_ready[idx] && pending_device[idx] == dev){
            deliver_response_to_app(idx);
            pcb[idx].state = READY;
            pcb[idx].blocked_dev = -1;
            pcb[idx].blocked_op = -1;
            q_push(&ready_q, pid);
            printf("[Kernel] IRQ %s: desbloqueou %s\n", dev_str(dev), pcb[idx].name);
            return;
        }
        q_push(bq, pid);
    }
}

// Faz troca de contexto simples: para o atual e dá SIGCONT no próximo.
void switch_to(pid_t next_pid){
    int nidx = app_index_from_pid(next_pid);
    if(current_pid > 0){
        int idx = app_index_from_pid(current_pid);
        if(idx >= 0 && pcb[idx].state == RUNNING){
            kill(current_pid, SIGSTOP);
            pcb[idx].state = READY;
            q_push(&ready_q, current_pid);
        }
    }
    if(nidx >= 0 && pcb[nidx].state == READY){
        pcb[nidx].state = RUNNING;
        current_pid = next_pid;
        kill(next_pid, SIGCONT);
        printf("[Kernel] Executando %s\n", pcb[nidx].name);
    }
}

// Aplicações: nomes base usados para gerar syscalls de teste.
char *FILE_NAMES[] = {
    "relatorio.txt", "dados.bin", "memo.txt", "saida.log", "hist.bin"
};
char *DIR_NAMES[] = {
    "docs", "temp", "media", "proj", "draft"
};

int random_offset(){
    int offsets[] = {0, 16, 32, 48, 64, 80, 96};
    return offsets[rand() % (sizeof(offsets)/sizeof(offsets[0]))];
}

void random_payload(char *buf){
    for(int i=0;i<SFP_PAYLOAD_LEN;i++)
        buf[i] = 'A' + (rand()%26);
}

char* choose_home(int app_no){
    if(rand()%5 == 0)
        return "/A0";
    return HOME_DIRS[app_no];
}

// Preenche estrutura SFPMessage com parâmetros aleatórios válidos para Ax.
void prepare_syscall(int app_no, SharedChannel *ch, FSOperation op){
    memset(&ch->req, 0, sizeof(SFPMessage));
    ch->req.type = op;
    ch->req.owner = app_no + 1;
    ch->req.offset = 0;
    char *home = choose_home(app_no);
    if(op == FS_WRITE || op == FS_READ){
        char *fname = FILE_NAMES[rand()% (sizeof(FILE_NAMES)/sizeof(FILE_NAMES[0]))];
        snprintf(ch->req.path, sizeof(ch->req.path), "%s/%s", home, fname);
        ch->req.offset = random_offset();
        if(op == FS_WRITE){
            random_payload(ch->req.payload);
            ch->req.payload_len = SFP_PAYLOAD_LEN;
        }
    } else if(op == FS_ADD_DIR || op == FS_REM_DIR){
        char *dname = DIR_NAMES[rand()% (sizeof(DIR_NAMES)/sizeof(DIR_NAMES[0]))];
        snprintf(ch->req.path, sizeof(ch->req.path), "%s", home);
        snprintf(ch->req.name, sizeof(ch->req.name), "%s", dname);
    } else if(op == FS_LIST_DIR){
        snprintf(ch->req.path, sizeof(ch->req.path), "%s", home);
    }
    ch->request_ready = 1;
    ch->response_ready = 0;
}

// Prints simples só para acompanhar o que cada Ax recebeu do SFSS.
void report_response(int app_no, SharedChannel *ch){
    SFPMessage *resp = &ch->resp;
    if(resp->status < 0){
        printf("[A%d] syscall %s falhou (%d)\n", app_no+1, fsop_str(resp->type), resp->status);
        return;
    }
    switch(resp->type){
        case FS_READ:
            printf("[A%d] READ %s offset %d => %.16s\n", app_no+1, resp->path, resp->offset, resp->payload);
            break;
        case FS_WRITE:
            printf("[A%d] WRITE %s offset %d OK\n", app_no+1, resp->path, resp->offset);
            break;
        case FS_ADD_DIR:
            printf("[A%d] ADD dir %s/%s\n", app_no+1, resp->path, resp->name);
            break;
        case FS_REM_DIR:
            printf("[A%d] REM dir %s/%s\n", app_no+1, resp->path, resp->name);
            break;
        case FS_LIST_DIR:
            printf("[A%d] LIST %s (%d entradas)\n", app_no+1, resp->path, resp->entry_count);
            for(int i=0;i<resp->entry_count;i++)
                printf("    %s [%c]\n", resp->entries[i], resp->entry_is_dir[i] ? 'D' : 'F');
            break;
        default:
            break;
    }
}

// Loop principal de Ax: gera syscalls aleatórias e informa progresso.
void app_process(int app_no){
    close(irq_pipe[0]); close(irq_pipe[1]);
    close(sys_pipe[0]);
    srand((unsigned)time(NULL) ^ getpid());
    SharedChannel *ch = channels[app_no];
    int pc = 0;
    while(pc < MAX_ITERATIONS){
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000000 };
        nanosleep(&delay, NULL);
        if(rand()%100 < PROB_SYSCALL){
            FSOperation op;
            int r = rand()%5;
            switch(r){
                case 0: op = FS_WRITE; break;
                case 1: op = FS_READ; break;
                case 2: op = FS_ADD_DIR; break;
                case 3: op = FS_REM_DIR; break;
                default: op = FS_LIST_DIR; break;
            }
            prepare_syscall(app_no, ch, op);
            AppMsg msg = { .type = APP_SYSCALL, .pid = getpid(), .device = (int)op_device(op), .op = op };
            ssize_t ignored = write(sys_pipe[1], &msg, sizeof(msg));
            (void)ignored;
            kill(getpid(), SIGSTOP);
            if(ch->response_ready){
                report_response(app_no, ch);
                ch->response_ready = 0;
            }
        } else {
            pc++;
            AppMsg progress = { .type = APP_PROGRESS, .pid = getpid(), .op = pc };
            ssize_t ignored2 = write(sys_pipe[1], &progress, sizeof(progress));
            (void)ignored2;
        }
    }
    AppMsg done = { .type = APP_TERMINATED, .pid = getpid() };
    ssize_t ignored3 = write(sys_pipe[1], &done, sizeof(done));
    (void)ignored3;
    exit(0);
}

// Kernel ---------------------------------------------------------------------
// Kernel consome request_ready, envia ao SFSS, marca PCB como bloqueado e guarda a resposta.
void handle_syscall_msg(int idx, AppMsg *am){
    SharedChannel *ch = channels[idx];
    if(!ch->request_ready){
        fprintf(stderr, "[Kernel] Aviso: syscall de %s sem request_ready\n", pcb[idx].name);
        return;
    }
    SFPMessage req;
    memcpy(&req, &ch->req, sizeof(SFPMessage));
    req.type = am->op;
    req.owner = idx + 1;
    SFPMessage resp;
    if(sfss_request(&req, &resp) < 0){
        memset(&resp, 0, sizeof(resp));
        resp.type = req.type;
        resp.owner = req.owner;
        resp.status = -1;
        strncpy(resp.path, req.path, sizeof(resp.path));
        strncpy(resp.name, req.name, sizeof(resp.name));
    }
    pending_responses[idx] = resp;
    pending_ready[idx] = 1;
    pending_device[idx] = op_device((FSOperation)am->op);
    pending_operation[idx] = am->op;
    ch->request_ready = 0;

    pcb[idx].state = BLOCKED;
    pcb[idx].blocked_dev = pending_device[idx];
    pcb[idx].blocked_op = am->op;
    if(pending_device[idx] == DEVICE_D1){
        q_push(&blocked_d1_q, am->pid);
        pcb[idx].count_d1++;
        if(am->op == FS_READ) pcb[idx].count_read++;
        else if(am->op == FS_WRITE) pcb[idx].count_write++;
    } else {
        q_push(&blocked_d2_q, am->pid);
        pcb[idx].count_d2++;
        if(am->op == FS_ADD_DIR) pcb[idx].count_add++;
        else if(am->op == FS_REM_DIR) pcb[idx].count_rem++;
        else if(am->op == FS_LIST_DIR) pcb[idx].count_list++;
    }
    if(current_pid == am->pid)
        current_pid = -1;
    printf("[Kernel] %s fez %s em %s\n", pcb[idx].name, fsop_str((FSOperation)am->op),
           pending_device[idx] == DEVICE_D1 ? "FILE" : "DIR");
}

// ./kernelsim [ip] [porta] (padrão 127.0.0.1:27015) – sempre start SFSS antes.
int main(int argc, char **argv){
    char *server_ip = "127.0.0.1";
    int server_port = SFSS_DEFAULT_PORT;
    if(argc >= 2) server_ip = argv[1];
    if(argc >= 3) server_port = atoi(argv[2]);

    if(sfss_connect(server_ip, server_port) < 0)
        return 1;
    if(init_shared_channels() < 0)
        return 1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigusr_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGCONT, &sa, NULL);

    if(pipe(irq_pipe) < 0 || pipe(sys_pipe) < 0){
        perror("pipe");
        return 1;
    }

    set_nonblock(irq_pipe[0]);
    set_nonblock(sys_pipe[0]);

    pid_t ic_pid = fork();
    if(ic_pid < 0){ perror("fork"); return 1; }
    if(ic_pid == 0){ intercontroller_process(); exit(0); }
    close(irq_pipe[1]);

    q_init(&ready_q);
    q_init(&blocked_d1_q);
    q_init(&blocked_d2_q);
    memset(pending_ready, 0, sizeof(pending_ready));
    for(int i=0;i<NUM_PROCS_APP;i++) pending_device[i] = (Device)(-1);

    for(int i=0;i<NUM_PROCS_APP;i++){
        snprintf(pcb[i].name, sizeof(pcb[i].name), "A%d", i+1);
        pcb[i].state = READY;
        pcb[i].pc = 0;
        pcb[i].blocked_dev = -1;
        pcb[i].blocked_op = -1;
        pcb[i].count_read = pcb[i].count_write = 0;
        pcb[i].count_add = pcb[i].count_rem = pcb[i].count_list = 0;
        pcb[i].count_d1 = pcb[i].count_d2 = 0;
        pcb[i].alive = false;

        pid_t p = fork();
        if(p < 0){ perror("fork"); return 1; }
        if(p == 0){
            kill(getpid(), SIGSTOP);
            app_process(i);
            return 0;
        }
        pcb[i].pid = p;
        pcb[i].alive = true;
        q_push(&ready_q, p);
        printf("[Kernel] %s PID=%d pronto\n", pcb[i].name, p);
    }

    close(sys_pipe[1]);

    if(!q_empty(&ready_q)){
        pid_t first = q_pop(&ready_q);
        switch_to(first);
    }

    int apps_terminated = 0;
    fd_set rds;
    int nfds = (irq_pipe[0] > sys_pipe[0] ? irq_pipe[0] : sys_pipe[0]) + 1;

    while(1){
        if(apps_terminated >= NUM_PROCS_APP){
            printf("[Kernel] Todos os apps terminaram.\n");
            kill(ic_pid, SIGKILL);
            waitpid(ic_pid, NULL, 0);
            break;
        }
        if(got_sigint){
            got_sigint = 0;
            print_status_table();
            printf("[Kernel] Simulação pausada. Envie SIGCONT (fg ou kill -CONT <pid>) para retomar.\n");
            fflush(stdout);
            waiting_sigcont = 1;
            while(waiting_sigcont){
                pause();
            }
            waiting_sigcont = 0;
            continue;
        }

        FD_ZERO(&rds);
        FD_SET(irq_pipe[0], &rds);
        FD_SET(sys_pipe[0], &rds);
        int rv = select(nfds, &rds, NULL, NULL, NULL);
        if(rv < 0){
            if(errno == EINTR) continue;
            perror("select");
            break;
        }

        if(FD_ISSET(sys_pipe[0], &rds)){
            while(1){
                AppMsg am;
                int n = read(sys_pipe[0], &am, sizeof(am));
                if(n <= 0){
                    if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                int idx = app_index_from_pid(am.pid);
                if(idx < 0) continue;
                if(am.type == APP_SYSCALL){
                    handle_syscall_msg(idx, &am);
                } else if(am.type == APP_TERMINATED){
                    if(pcb[idx].state != TERMINATED){
                        pcb[idx].state = TERMINATED;
                        pcb[idx].alive = false;
                        if(current_pid == am.pid) current_pid = -1;
                        apps_terminated++;
                        printf("[Kernel] %s terminou.\n", pcb[idx].name);
                        if(!q_empty(&ready_q)){
                            pid_t next = q_pop(&ready_q);
                            switch_to(next);
                        }
                    }
                } else if(am.type == APP_PROGRESS){
                    pcb[idx].pc = am.op;
                }
            }
        }

        if(FD_ISSET(irq_pipe[0], &rds)){
            while(1){
                IRQMsg im;
                int n = read(irq_pipe[0], &im, sizeof(im));
                if(n <= 0){
                    if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                if(im.type == IRQ_TIMESLICE){
                    if(!q_empty(&ready_q)){
                        pid_t next = q_pop(&ready_q);
                        switch_to(next);
                    }
                } else if(im.type == IRQ_IO_D1){
                    finish_blocked_process(DEVICE_D1);
                } else if(im.type == IRQ_IO_D2){
                    finish_blocked_process(DEVICE_D2);
                }
            }
        }

        while(1){
            int status;
            pid_t w = waitpid(-1, &status, WNOHANG);
            if(w <= 0) break;
        }
    }

    for(int i=0;i<NUM_PROCS_APP;i++){
        if(pcb[i].alive){
            kill(pcb[i].pid, SIGKILL);
            waitpid(pcb[i].pid, NULL, 0);
        }
    }
    cleanup_shared_channels();
    if(sfss_sock >= 0) close(sfss_sock);
    return 0;
}
