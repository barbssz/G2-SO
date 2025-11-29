#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

// Parâmetros globais compartilhados pelos binários do TRAB2.
#define NUM_PROCS_APP 5
#define MAX_ITERATIONS 30
#define TIMESLICE_MS 500
#define PROB_SYSCALL 20

#define SFSS_DEFAULT_PORT 27015
#define SFSS_DEFAULT_ROOT "SFS-root-dir"

#define SFP_PAYLOAD_LEN 16
#define SFP_MAX_PATH 256
#define SFP_MAX_NAME 32
#define SFP_MAX_ENTRIES 40

// Tipos de operações de sistema de arquivos
typedef enum {
    FS_NONE = 0,
    FS_READ = 1,
    FS_WRITE = 2,
    FS_ADD_DIR = 3,
    FS_REM_DIR = 4,
    FS_LIST_DIR = 5
} FSOperation;

// Mensagem enviada entre KernelSim e SFSS
// Também utilizada em memória compartilhada entre KernelSim e os processos Ax.
// Estrutura de mensagem que trafega entre kernel e SFSS (REQ/REP).
typedef struct {
    int type;                // FSOperation
    int owner;               // Processo que requisitou (1..5) ou 0 para /A0
    int offset;              // Offset múltiplo de 16 bytes para READ/WRITE
    int payload_len;         // Bytes válidos em payload
    int status;              // 0 sucesso, negativo em caso de erro
    int entry_count;         // Usado em LIST_DIR (quantidade de nomes retornados)
    char path[SFP_MAX_PATH]; // Caminho alvo (arquivo ou diretório)
    char name[SFP_MAX_NAME]; // Nome auxiliar (novo subdir, etc)
    char payload[SFP_PAYLOAD_LEN];
    char entries[SFP_MAX_ENTRIES][SFP_MAX_NAME];
    int entry_is_dir[SFP_MAX_ENTRIES]; // 1 se diretório, 0 se arquivo
} SFPMessage;

// Canal kernel <-> Ax: request_ready é setado pelo Ax, response_ready pelo kernel.
typedef struct {
    int request_ready;
    int response_ready;
    SFPMessage req;
    SFPMessage resp;
} SharedChannel;

#endif // COMMON_H
