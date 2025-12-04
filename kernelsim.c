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
#define P2_PROB 8

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
} PCB;

// Fila circular simples usada para Ready, bloqueados em D1 e D2.
typedef struct {
    pid_t data[NUM_PROCS_APP];
    int head, tail, size;
} PIDQueue;

// Struct para mensagens de IRQ do InterController.
typedef struct {
    int type;
} IRQMsg;

// Mensagens enviadas por Ax para o kernel.
typedef enum {
    APP_SYSCALL = 1,
    APP_TERMINATED = 2,
    APP_PROGRESS = 3
} AppMsgType;

// Struct de mensagem de Ax para o kernel.
typedef struct {
    int type;
    pid_t pid;
    int device;
    int op;
} AppMsg;

// Dispositivos (agora representam FILE e DIR).
typedef enum {
    DEVICE_D1 = 0,
    DEVICE_D2 = 1
} Device;

// Tipos de IRQs geradas pelo InterController.
typedef enum {
    IRQ_TIMESLICE = 0,
    IRQ_IO_D1 = 1,
    IRQ_IO_D2 = 2
} InterruptType;

// Configurações de comunicação
int irq_pipe[2]; // pipe para IRQs do InterController
int sys_pipe[2];// pipe para mensagens de Ax para o kernel
int sfss_sock = -1; // socket UDP para o SFSS
struct sockaddr_in sfss_addr; // endereço do SFSS
socklen_t sfss_addrlen = 0; // tamanho do endereço do SFSS

// Estruturas globais
PCB pcb[NUM_PROCS_APP];
PIDQueue ready_q;
PIDQueue blocked_d1_q;
PIDQueue blocked_d2_q;
// Um canal de memória compartilhada por processo Ax.
SharedChannel *channels[NUM_PROCS_APP]; // ponteiros para canais
char shm_names[NUM_PROCS_APP][32]; // nomes dos segmentos shm
// Estruturas para guardar a resposta do SFSS até o InterController liberar o device.
SFPMessage pending_responses[NUM_PROCS_APP]; // respostas pendentes
int pending_ready[NUM_PROCS_APP]; // 1 se resposta pronta
Device pending_device[NUM_PROCS_APP]; // device da resposta pendente
FSOperation pending_operation[NUM_PROCS_APP]; // operação da resposta pendente

int current_pid = -1; // PID do processo atualmente em execução
int got_sigint = 0; // flag para indicar SIGINT recebido

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

// Retorna o índice do app (0..4) a partir do PID.
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

// Retorna o device associado à operação de sistema( no caso, FILE ou DIR).
Device op_device(FSOperation op){
    if(op == FS_READ || op == FS_WRITE)
        return DEVICE_D1;
    return DEVICE_D2;
}

int waiting_sigcont = 0; // flag para indicar espera por SIGCONT

// Handlers de sinais
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

// setar o pipe como non-blocking
void set_nonblock(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Mostra snapshot do escalonador quando usuario dá Ctrl+C.
void print_status_table(){
    printf("\n===== STATUS (Kernel PID = %d) =====\n", getpid());
    printf(" PID     | Name |   State   |  PC  | Blocked | Op   | R  W  A  Rm L |\n");
    printf("-------------------------------------------------------------------\n");
    for(int i=0;i<NUM_PROCS_APP;i++){
        PCB *p = &pcb[i];
        printf(" %-7d | %-4s | %-9s | %-4d | ", p->pid, p->name, state_str(p->state), p->pc);
        if(p->state == BLOCKED)
            printf("%-6s | %-4s | ", dev_str(p->blocked_dev), fsop_str((FSOperation)p->blocked_op));
        else
            printf("%-6s | %-4s | ", "-", "-");
        printf("%-2d %-2d %-2d %-3d %-2d |\n",
               p->count_read, p->count_write, p->count_add, p->count_rem, p->count_list);
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
        snprintf(shm_names[i], sizeof(shm_names[i]), "/trab2_ax_%d", i); // nome de shm
        int fd = shm_open(shm_names[i], O_CREAT | O_RDWR, 0666); // cria shm

        if(fd < 0){ perror("shm_open"); return -1; } // erro ao criar shm

        if(ftruncate(fd, sizeof(SharedChannel)) < 0){ perror("ftruncate"); return -1; } // erro ao setar tamanho

        SharedChannel *ch = mmap(NULL, sizeof(SharedChannel), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // mapear shm

        if(ch == MAP_FAILED){ perror("mmap"); return -1; } // erro ao mapear

        close(fd);
        memset(ch, 0, sizeof(SharedChannel)); // inicializa a estrutura
        channels[i] = ch;
    }
    return 0;
}

// Libera e remove os segmentos compartilhados. Éusada quando o kernel termina.
void cleanup_shared_channels(){
    for(int i=0;i<NUM_PROCS_APP;i++){
        if(channels[i]) // se foi criado o segmento
            munmap(channels[i], sizeof(SharedChannel)); // desmapeia
        shm_unlink(shm_names[i]); // remove o segmento
    } 
}

// Comunicação com SFSS -------------------------------------------------------
// Abre o socket UDP e grava endereço do SFSS. Usada quando o kernel faz start.
int sfss_connect(char *ip, int port){
    sfss_sock = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket

    if(sfss_sock < 0){ perror("socket"); return -1; } // erro ao criar socket

    memset(&sfss_addr, 0, sizeof(sfss_addr)); // inicializa endereço
    sfss_addr.sin_family = AF_INET; // variavel que armazena o endereço do SFSS
    sfss_addr.sin_port = htons(port); // porta do SFSS
    if(inet_pton(AF_INET, ip, &sfss_addr.sin_addr) <= 0){ // erro ao converter IP
        perror("inet_pton");
        return -1;
    }
    sfss_addrlen = sizeof(sfss_addr); // tamanho do endereço
    return 0;
}

// Envia requisição SFP (UDP) para o server e aguarda REPLY com timeout de 1s.
// Envia mensagem SFP e aguarda REPLY com timeout de 1s.
int sfss_request(SFPMessage *req, SFPMessage *resp){
    if(sfss_sock < 0) return -1; // socket não aberto

    if(sendto(sfss_sock, req, sizeof(SFPMessage), 0, (struct sockaddr*)&sfss_addr, sfss_addrlen) < 0){// erro ao enviar
        perror("sendto");
        return -1;
    }

    fd_set set; // aguarda resposta com timeout
    FD_ZERO(&set); // inicializa conjunto de descritores
    FD_SET(sfss_sock, &set); // adiciona socket ao conjunto
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 }; // timeout de 1 segundo

    int rv = select(sfss_sock+1, &set, NULL, NULL, &tv); //aguarda dados vindos do SFSS
    if(rv <= 0){ // timeout ou erro
        fprintf(stderr, "[Kernel] Timeout aguardando SFSS\n");
        return -1;
    }
    ssize_t n = recvfrom(sfss_sock, resp, sizeof(SFPMessage), 0, NULL, NULL); // recebe resposta
    if(n < 0){ perror("recvfrom"); return -1; } // erro ao receber
    return 0;
}

// Escalonamento --------------------------------------------------------------
// Copia resposta do SFSS para o canal do Ax indicado.
// Copia a resposta pendente para o canal do processo e marca pronta.
void deliver_response_to_app(int idx){
    SharedChannel *ch = channels[idx]; // canal do app idx
    memcpy(&ch->resp, &pending_responses[idx], sizeof(SFPMessage)); // copia resposta para o canal
    ch->response_ready = 1; // marca resposta como pronta
    pending_ready[idx] = 0; // limpa flag de resposta pendente
    pending_device[idx] = (Device)(-1); // limpa device pendente
}

// Desperta um processo bloqueado no device informado (casado pela resposta pendente).
// Desbloqueia um processo da fila de D1 ou D2 que já tem resposta pronta.(FILE ou DIR)
//Usada quando chega IRQ de I/O.
void finish_blocked_process(Device dev){
    PIDQueue *bq = (dev == DEVICE_D1) ? &blocked_d1_q : &blocked_d2_q; // fila de bloqueados
    if(q_empty(bq)) // se nao houver nenhum processo bloqueado, retorna 
        return;
    int attempts = bq->size; // número de processos bloqueados na fila
    while(attempts-- > 0){ // enquanto houver processos bloqueados
        pid_t pid = q_pop(bq); // remove o processo da fila
        int idx = app_index_from_pid(pid); // obtém o índice do processo
        if(idx >= 0 && pending_ready[idx] && pending_device[idx] == dev){
            deliver_response_to_app(idx);
            pcb[idx].state = READY; // seta o processo desbloqueado como READY
            pcb[idx].blocked_dev = -1;
            pcb[idx].blocked_op = -1;
            q_push(&ready_q, pid); // adiciona o processo à fila de prontos
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
// Preenche buffer com payload aleatório (A-Z). Payload é um conceito que representa dados lidos ou escritos.
void random_payload(char *buf){
    for(int i=0;i<SFP_PAYLOAD_LEN;i++)
        buf[i] = 'A' + (rand()%26);
}

// Escolhe aleatoriamente entre /A0 e o diretório home do app, de acordo com o numero do app.
char* choose_home(int app_no){
    if(rand()%5 == 0)
        return "/A0";
    return HOME_DIRS[app_no];
}

// Preenche estrutura SFPMessage com parâmetros aleatórios válidos para Ax.
//Usada quando um processo Ax gera uma syscall e o kernel deve preparar a mensagem da struct SharedChannel.
void prepare_syscall(int app_no, SharedChannel *ch, FSOperation op){
    memset(&ch->req, 0, sizeof(SFPMessage)); // limpa a requisição vinida do Ax
    ch->req.type = op; 
    ch->req.owner = app_no + 1;
    ch->req.offset = 0;
    char *home = choose_home(app_no);
    if(op == FS_WRITE || op == FS_READ){
        char *fname = FILE_NAMES[rand()% (sizeof(FILE_NAMES)/sizeof(FILE_NAMES[0]))]; // escolhe nome de arquivo
        snprintf(ch->req.path, sizeof(ch->req.path), "%s/%s", home, fname); // monta o path completo
        ch->req.offset = random_offset(); // seta offset aleatório
        if(op == FS_WRITE){
            random_payload(ch->req.payload); // preenche payload aleatório
            ch->req.payload_len = SFP_PAYLOAD_LEN; // seta tamanho do payload
        }
    } else if(op == FS_ADD_DIR || op == FS_REM_DIR){
        char *dname = DIR_NAMES[rand()% (sizeof(DIR_NAMES)/sizeof(DIR_NAMES[0]))]; // escolhe nome de diretório
        snprintf(ch->req.path, sizeof(ch->req.path), "%s", home); // monta o path do diretório pai
        snprintf(ch->req.name, sizeof(ch->req.name), "%s", dname); // seta o nome do novo subdiretório
    } else if(op == FS_LIST_DIR){
        snprintf(ch->req.path, sizeof(ch->req.path), "%s", home); // monta o path do diretório a listar
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
            prepare_syscall(app_no, ch, op); // preenche o shared channel com a syscall
            AppMsg msg = { .type = APP_SYSCALL, .pid = getpid(), .device = (int)op_device(op), .op = op };
            int ignored = write(sys_pipe[1], &msg, sizeof(msg)); // envia syscall ao kernel
            kill(getpid(), SIGSTOP);
            if(ch->response_ready){// verifica se o kernel enviou alguma resposta
                report_response(app_no, ch); // mostra o resultado da syscall
                ch->response_ready = 0;// limpa flag de resposta pronta
            }
        } else {
            pc++;
            AppMsg progress = { .type = APP_PROGRESS, .pid = getpid(), .op = pc };
            int ignored2 = write(sys_pipe[1], &progress, sizeof(progress));
    
        }
    }
    AppMsg done = { .type = APP_TERMINATED, .pid = getpid() };
    int ignored3 = write(sys_pipe[1], &done, sizeof(done));
    exit(0);
}

// Kernel ---------------------------------------------------------------------
// Kernel consome request_ready, envia ao SFSS, marca PCB como bloqueado e guarda a resposta.
//É usada quando 'um processo Ax faz uma syscall, e então o kernel deve tratar essa syscall.
void handle_syscall_msg(int idx, AppMsg *am){
    SharedChannel *ch = channels[idx]; // pega  shared channel a partir do índice
    if(!ch->request_ready){ // se request_ready não estiver setado, avisa e retorna
        fprintf(stderr, "[Kernel] Aviso: syscall de %s sem request_ready\n", pcb[idx].name); // printa aviso
        return;
    }
    SFPMessage req;
    memcpy(&req, &ch->req, sizeof(SFPMessage)); // copia a requisição do canal para a variável req
    req.type = am->op;
    req.owner = idx + 1;
    SFPMessage resp;
    if(sfss_request(&req, &resp) < 0){ // envia a requisição ao SFSS e aguarda resposta
        memset(&resp, 0, sizeof(resp)); // em caso de erro, prepara resposta de falha
        resp.type = req.type; // copia os campos relevantes
        resp.owner = req.owner;
        resp.status = -1;
        strncpy(resp.path, req.path, sizeof(resp.path));
        strncpy(resp.name, req.name, sizeof(resp.name));
    }
    pending_responses[idx] = resp; // guarda a resposta pendente
    pending_ready[idx] = 1;
    pending_device[idx] = op_device((FSOperation)am->op);
    pending_operation[idx] = am->op;
    ch->request_ready = 0;

    pcb[idx].state = BLOCKED; // marca o processo como BLOCKED
    pcb[idx].blocked_dev = pending_device[idx]; 
    pcb[idx].blocked_op = am->op; // 
    if(pending_device[idx] == DEVICE_D1){ // se  for FILE
        q_push(&blocked_d1_q, am->pid); // adiciona à fila de bloqueados em D1
        if(am->op == FS_READ) pcb[idx].count_read++; // incrementa contador de leitura ou escrita
        else if(am->op == FS_WRITE) pcb[idx].count_write++;
    } else {
        q_push(&blocked_d2_q, am->pid); // adiciona à fila de bloqueados em D2(DIR)
        if(am->op == FS_ADD_DIR) pcb[idx].count_add++; // incrementa contador de add, rem ou list
        else if(am->op == FS_REM_DIR) pcb[idx].count_rem++;
        else if(am->op == FS_LIST_DIR) pcb[idx].count_list++;
    }
    if(current_pid == am->pid) // limpa o current_pid se for o processo atual
        current_pid = -1;
    printf("[Kernel] %s fez %s em %s\n", pcb[idx].name, fsop_str((FSOperation)am->op),
           pending_device[idx] == DEVICE_D1 ? "FILE" : "DIR");
}

// ./kernelsim [ip] [porta] (padrão 127.0.0.1:27015) – sempre start SFSS antes.
int main(int argc, char **argv){
    char *server_ip = "127.0.0.1"; // IP padrão do SFSS
    int server_port = SFSS_DEFAULT_PORT; // porta padrão do SFSS
    if(argc >= 2) server_ip = argv[1]; // pega IP do SFSS dos argumentos
    if(argc >= 3) server_port = atoi(argv[2]); // pega porta do SFSS dos argumentos

    if(sfss_connect(server_ip, server_port) < 0) // se conectar ao SFSS falhar, retorna 1
        return 1;
    if(init_shared_channels() < 0) // se a inicializacao dos shared channels falhar, retorna  1
        return 1;

    struct sigaction sa;// configura handlers de sinais
    memset(&sa, 0, sizeof(sa)); // configura handler para SIGINT
    sa.sa_handler = sigint_handler; // handler de SIGINT
    sigemptyset(&sa.sa_mask); // mascara vazia
    sa.sa_flags = SA_RESTART; // reinicia syscalls interrompidas
    sigaction(SIGINT, &sa, NULL); // aplica handler de SIGINT

    memset(&sa, 0, sizeof(sa)); // configura handler para SIGUSR1 e SIGCONT
    sa.sa_handler = sigusr_handler; // handler de SIGUSR1 e SIGCONT
    sigemptyset(&sa.sa_mask); // mascara vazia
    sa.sa_flags = SA_RESTART; // reinicia syscalls interrompidas
    sigaction(SIGUSR1, &sa, NULL); // aplica handler de SIGUSR1
    sigaction(SIGCONT, &sa, NULL); // aplica handler de SIGCONT

    if(pipe(irq_pipe) < 0 || pipe(sys_pipe) < 0){ // erro ao criar pipes
        perror("pipe");
        return 1;
    }

    set_nonblock(irq_pipe[0]); // setar os pipes como nao bloqueantes. 
    set_nonblock(sys_pipe[0]);

    pid_t ic_pid = fork(); // cria processo InterController
    if(ic_pid < 0){ perror("fork"); return 1; }
    if(ic_pid == 0){ intercontroller_process(); exit(0); }
    close(irq_pipe[1]);

    q_init(&ready_q);
    q_init(&blocked_d1_q);
    q_init(&blocked_d2_q);
    memset(pending_ready, 0, sizeof(pending_ready)); // inicializa arrays de respostas pendentes
    for(int i=0;i<NUM_PROCS_APP;i++) pending_device[i] = (Device)(-1); // inicializa arrays de devices pendentes

    for(int i=0;i<NUM_PROCS_APP;i++){
        snprintf(pcb[i].name, sizeof(pcb[i].name), "A%d", i+1); // inicializa PCBs
        pcb[i].state = READY;
        pcb[i].pc = 0;
        pcb[i].blocked_dev = -1;
        pcb[i].blocked_op = -1;
        pcb[i].count_read = pcb[i].count_write = 0;
        pcb[i].count_add = pcb[i].count_rem = pcb[i].count_list = 0;
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

    if(!q_empty(&ready_q)){ // inicia o primeiro processo
        pid_t first = q_pop(&ready_q);
        switch_to(first);
    }

    int apps_terminated = 0;
    fd_set rds; // conjunto de descritores para select
    int nfds = (irq_pipe[0] > sys_pipe[0] ? irq_pipe[0] : sys_pipe[0]) + 1; // nfds para select

    while(1){
        if(apps_terminated >= NUM_PROCS_APP){ // se todos os apps terminaram, sai do loop
            printf("[Kernel] Todos os apps terminaram.\n");
            kill(ic_pid, SIGKILL);
            waitpid(ic_pid, NULL, 0);
            break;
        }
        if(got_sigint){ // tratador de SIGINT: pausa a simulação e mostra status
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

        FD_ZERO(&rds); // prepara conjunto de descritores para select
        FD_SET(irq_pipe[0], &rds); // adiciona pipe de IRQs como nao bloqueantes
        FD_SET(sys_pipe[0], &rds); // adiciona pipe de syscalls como nao bloqueantes
        int rv = select(nfds, &rds, NULL, NULL, NULL);
        if(rv < 0){
            if(errno == EINTR) continue; // se select foi interrompido por sinal, reinicia
            perror("select");
            break;
        }

        if(FD_ISSET(sys_pipe[0], &rds)){ // se houver dados no pipe de syscalls
            while(1){
                AppMsg am;
                int n = read(sys_pipe[0], &am, sizeof(am)); // lê mensagem do pipe 
                if(n <= 0){
                    if(errno == EAGAIN || errno == EWOULDBLOCK) break; // se não houver mais dados, sai do loop
                    break; // erro ao ler
                }
                int idx = app_index_from_pid(am.pid); // obtém o índice do app a partir do PID
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

        if(FD_ISSET(irq_pipe[0], &rds)){ // se houver dados no pipe de IRQs
            while(1){
                IRQMsg im;
                int n = read(irq_pipe[0], &im, sizeof(im)); // lê mensagem do pipe
                if(n <= 0){
                    if(errno == EAGAIN || errno == EWOULDBLOCK) break; // se não houver mais dados, sai do loop
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

        while(1){ // limpa processos zumbis
            int status;
            pid_t w = waitpid(-1, &status, WNOHANG);
            if(w <= 0) break;
        }
    }

    for(int i=0;i<NUM_PROCS_APP;i++){ // acaba com os processos se algum ainda estiver vivo
        if(pcb[i].alive){
            kill(pcb[i].pid, SIGKILL);
            waitpid(pcb[i].pid, NULL, 0);
        }
    }
    cleanup_shared_channels(); // limpa segmentos de memória compartilhada(shared channels entre processos e Kernel)
    if(sfss_sock >= 0) close(sfss_sock); // fecha socket UDP
    return 0;
}
