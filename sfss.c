#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "common.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

char root_dir[PATH_MAX];

// Verifica se o owner do pedido pode acessar o prefixo do caminho (/A0 ou /A<owner>).
int path_allowed(SFPMessage *msg, char *path){ // path é o caminho relativo começando com '/'
    if(msg->owner < 0 || msg->owner > NUM_PROCS_APP) // owner inválido(owner é 0..NUM_PROCS_APP)
        return 0;
    // Owner 0: apenas /A0 ou /A0/...
    if(msg->owner == 0){ // se owner é 0
        if(strncmp(path, "/A0", 3) != 0) return 0; // faz match com /A0
        // precisa terminar ou ter barra na sequência 
        if(path[3] == '\0' || path[3] == '/') // se for /A0 ou /A0/...
            return 1;
        return 0;
    }
    // Owners 1..NUM_PROCS_APP: caminho deve começar com /A<owner> e terminar ou ter '/'
    char expected[6]; // /A<num>
    snprintf(expected, sizeof(expected), "/A%d", msg->owner); // monta /A<owner>
    size_t plen = strlen(expected); // comprimento do prefixo esperado
    if(strncmp(path, expected, plen) != 0) // faz match com /A<owner>
        return 0;
    if(path[plen] == '\0' || path[plen] == '/') // se for /A<owner> ou /A<owner>/...
        return 1; // permitido
    return 0;
}

// Cria diretório se não existir.
int ensure_dir(char *path){ // path absoluto
    struct stat st; // estrutura de informações do arquivo
    if(stat(path, &st) == 0){ // existe
        if(S_ISDIR(st.st_mode)) return 0; // já é diretório
        return -ENOTDIR; // existe mas não é diretório
    }
    if(mkdir(path, 0775) < 0 && errno != EEXIST) //     cria diretório
        return -errno; // erro ao criar
    return 0;
}

// Prepara SFS-root-dir com A0..A5.
int ensure_root_structure(char *root){ // path absoluto
    if(ensure_dir(root) < 0) // cria diretório raiz
        return -1; // erro ao criar
    char buf[PATH_MAX]; // buffer temporário
    for(int i=0;i<=NUM_PROCS_APP;i++){ // cria /A0 a /A5
        size_t len = strlen(root); // comprimento do path raiz
        if(len + 4 >= sizeof(buf)) // verifica tamanho do buffer
            continue;
        snprintf(buf, sizeof(buf), "%s/A%d", root, i); // monta path completo
        ensure_dir(buf); // cria diretório
    }
    return 0;
}

int has_invalid(char *s){ // verifica se string tem caracteres inválidos
    if(!s) return 1;// string nula
    for(char *p=s; *p; ++p){ // percorre a string
        if(*p == '\\') return 1;// barra invertida não é permitida
    }
    if(strstr(s, "..")) return 1; // não permite diretórios pai
    return 0;
}

// Monta caminho absoluto a partir do prefixo raiz.
int build_path(char *rel, char *out, size_t out_len){ // rel é o caminho relativo começando com '/'
    if(!rel || rel[0] != '/' || has_invalid(rel)) // verifica validade do caminho
        return -EINVAL; // caminho inválido
    if(snprintf(out, out_len, "%s%s", root_dir, rel) >= (int)out_len) // monta caminho absoluto
        return -ENAMETOOLONG; // caminho muito longo
    return 0; 
}

//Função que garante que todos os diretórios pai existem.
int ensure_parent_dirs(char *path){ // path absoluto
    char tmp[PATH_MAX]; // buffer temporário
    strncpy(tmp, path, sizeof(tmp)); // copia o path
    tmp[PATH_MAX-1] = '\0';
    char *p = strrchr(tmp, '/');
    if(!p || p == tmp)
        return 0;
    *p = '\0';
    for(char *c = tmp + 1; *c; ++c){
        if(*c == '/'){
            *c = '\0';
            mkdir(tmp, 0775);
            *c = '/';
        }
    }
    mkdir(tmp, 0775);
    return 0;
}

// Escreve 16 bytes (payload) no offset indicado, criando arquivo se preciso.
int handle_write(SFPMessage *msg){ // msg contém os dados da requisição
    char abs_path[PATH_MAX]; // buffer para caminho absoluto
    int rv = build_path(msg->path, abs_path, sizeof(abs_path)); // monta caminho absoluto
    if(rv < 0) return rv; // caminho inválido
    if(msg->owner < 1 || msg->owner > NUM_PROCS_APP) return -EACCES; // owner inválido
    if(!path_allowed(msg, msg->path)) return -EACCES; // verifica permissão
    if(msg->offset % SFP_PAYLOAD_LEN != 0) return -EINVAL; // offset inválido

    ensure_parent_dirs(abs_path);
    FILE *f = fopen(abs_path, "r+b"); // tenta abrir para leitura/escrita
    if(!f) f = fopen(abs_path, "w+b"); // se não existir, cria novo arquivo

    if(!f) // erro ao abrir/criar arquivo
        return -errno; // retorna erro

    if(fseek(f, 0, SEEK_END) < 0){ // vai para o fim do arquivo, se der erro, ele fecha o arquivo e retorna o erro
        fclose(f); 
        return -errno;
     }

    long current = ftell(f); // obtém o tamanho atual do arquivo
    if(current < 0){ fclose(f); return -errno; } // erro ao obter tamanho
    if(msg->offset > current){ // se offset é maior que o tamanho atual, preenche com espaços
        long diff = msg->offset - current; // diferença a preencher
        while(diff-- > 0) fputc(' ', f); // preenche com espaços
    }

    if(fseek(f, msg->offset, SEEK_SET) < 0){ fclose(f); return -errno; } // vai para o offset desejado
    if(fwrite(msg->payload, 1, SFP_PAYLOAD_LEN, f) != SFP_PAYLOAD_LEN){ fclose(f); return -EIO; } // erro ao escrever
    fclose(f); // fecha o arquivo
    msg->payload_len = SFP_PAYLOAD_LEN; // seta tamanho do payload escrito
    return 0;
}

// Lê 16 bytes a partir do offset.
int handle_read(SFPMessage *msg){
    char abs_path[PATH_MAX]; // buffer para caminho absoluto
    int rv = build_path(msg->path, abs_path, sizeof(abs_path)); // monta caminho absoluto
    if(rv < 0) 
        return rv;
    if(msg->owner < 1 || msg->owner > NUM_PROCS_APP) return -EACCES; // se  owner inválido, então erro
    if(!path_allowed(msg, msg->path)) return -EACCES; // se o caminho não for permitido, então erro
    if(msg->offset % SFP_PAYLOAD_LEN != 0) return -EINVAL; // se offset inválido, então erro


    FILE *f = fopen(abs_path, "rb"); // abre arquivo para leitura
    if(!f) return -errno; // se nao existir, erro ao abrir
    if(fseek(f, 0, SEEK_END) < 0){ // se der erro ao ir para o fim do arquivo
        fclose(f);// fecha
        return -errno; 
    } // Vai para o fim do arquivo
    long size = ftell(f);

    if(size < 0){ fclose(f); 
        return -errno; } // Erro ao obter tamanho

    if(msg->offset >= size){
        fclose(f); 
        return -ERANGE; } // Offset além do tamanho do arquivo
    if(fseek(f, msg->offset, SEEK_SET) < 0){ // Vai para o offset desejado. Se der erro, fecha e retorna erro
        fclose(f); // Erro ao buscar
        return -errno; 
    }
    size_t n = fread(msg->payload, 1, SFP_PAYLOAD_LEN, f); // Lê até 16 bytes do arquivo
    fclose(f); // Fecha o arquivo
    msg->payload_len = (int)n; // Define o tamanho do payload lido
    if(n == 0) 
        return -EIO; // Erro de leitura
    if(n < SFP_PAYLOAD_LEN) // se leu menos que 16 bytes, preenche o resto com espaços
        memset(msg->payload + n, ' ', SFP_PAYLOAD_LEN - n);
    return 0;
}

// Cria subdiretório.
int handle_add_dir(SFPMessage *msg){
    if(has_invalid(msg->name)) return -EINVAL; // nome inválido
    char parent[PATH_MAX]; // buffer para caminho do diretório pai
    if(build_path(msg->path, parent, sizeof(parent)) < 0) // se caminho inválido, retorna erro
        return -EINVAL;
    if(!path_allowed(msg, msg->path)) return -EACCES; // verifica permissão. se caminho nao for permitido, erro
    if(msg->owner < 1 || msg->owner > NUM_PROCS_APP) return -EACCES; 
    char target[PATH_MAX]; // buffer para caminho do novo subdiretório
    if(snprintf(target, sizeof(target), "%s/%s", parent, msg->name) >= (int)sizeof(target)) // se caminho muito longo, retorna erro
        return -ENAMETOOLONG;
    ensure_dir(parent); // garante que o diretório pai existe
    if(mkdir(target, 0775) < 0 && errno != EEXIST) // cria o novo subdiretório
        return -errno;
    return 0;
}

// Remove subdiretório.
int handle_rem_dir(SFPMessage *msg){
    if(has_invalid(msg->name)) return -EINVAL; // se nome inválido, retorna erro
    char parent[PATH_MAX]; // buffer para caminho do diretório pai
    if(build_path(msg->path, parent, sizeof(parent)) < 0) // se caminho inválido do diretorio que contém o subdiretório, retorna erro
        return -EINVAL;
    char target[PATH_MAX]; // buffer para caminho do subdiretório a ser removido
    if(snprintf(target, sizeof(target), "%s/%s", parent, msg->name) >= (int)sizeof(target)) // se caminho muito longo, retorna erro
        return -ENAMETOOLONG; // caminho muito longo
    if(msg->owner < 1 || msg->owner > NUM_PROCS_APP) return -EACCES; // se owner inválido, retorna erro
    if(!path_allowed(msg, msg->path)) return -EACCES; // se o caminho não for permitido, retorna erro
    struct stat st;
    if(stat(target, &st) < 0) // se não existir, retorna erro
        return -errno;
    int rv;
    if(S_ISDIR(st.st_mode)) // se for diretório, usa rmdir
        rv = rmdir(target);
    else // se nao, usa unlink para remover arquivo
        rv = unlink(target);
    if(rv < 0) // se der erro ao remover, retorna erro
        return -errno;
    return 0;
}

// Lista arquivos/subdirs no diretório alvo.
int handle_list_dir(SFPMessage *msg){
    char abs_path[PATH_MAX]; // buffer para caminho absoluto
    if(build_path(msg->path, abs_path, sizeof(abs_path)) < 0) // se caminho inválido, retorna erro
        return -EINVAL;
    if(msg->owner < 1 || msg->owner > NUM_PROCS_APP) return -EACCES; // se owner inválido, retorna erro
    if(!path_allowed(msg, msg->path)) return -EACCES; // se o caminho não for permitido, retorna erro
    DIR *dir = opendir(abs_path); // abre o diretório
    if(!dir) return -errno; // se não existir, retorna erro
    struct dirent *ent; // estrutura para ler entradas do diretório
    int count = 0; // contador de entradas lidas
    memset(msg->entries, 0, sizeof(msg->entries)); // faz limpeza das entradas
    memset(msg->entry_is_dir, 0, sizeof(msg->entry_is_dir)); // faz limpeza dos flags de diretório
    while((ent = readdir(dir)) != NULL && count < SFP_MAX_ENTRIES){ // lê entradas até o máximo permitido
        if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) // ignora . e ..
            continue;
        char entry_path[PATH_MAX]; // buffer para caminho completo da entrada
        size_t base_len = strnlen(abs_path, sizeof(abs_path)); // comprimento do caminho base
        size_t name_len = strnlen(ent->d_name, sizeof(ent->d_name)); // comprimento do nome da entrada
        if(base_len + 1 + name_len + 1 >= sizeof(entry_path)) // verifica tamanho do buffer. se for muito longo, ignora 
            continue;
        strncpy(msg->entries[count], ent->d_name, SFP_MAX_NAME-1); // copia o nome da entrada
        msg->entries[count][SFP_MAX_NAME-1] = '\0'; // garante terminação nula
        memcpy(entry_path, abs_path, base_len); // monta o caminho completo da entrada
        entry_path[base_len] = '/'; // adiciona barra
        memcpy(entry_path + base_len + 1, ent->d_name, name_len); // adiciona o nome da entrada
        entry_path[base_len + 1 + name_len] = '\0'; // terminação nula
        struct stat st; // estrutura para informações do arquivo
        if(stat(entry_path, &st) == 0 && S_ISDIR(st.st_mode)) // verifica se é diretório
            msg->entry_is_dir[count] = 1; // marca como diretório
        else // se não, marca como arquivo
            msg->entry_is_dir[count] = 0;
        count++;
    }
    closedir(dir); // fecha o diretório
    msg->entry_count = count;
    if(count >= SFP_MAX_ENTRIES) // se excedeu o máximo de entradas, retorna erro
        return -EOVERFLOW;
    return 0;
}

// Decide a operação solicitada e despacha para o handler correto.
void handle_request(SFPMessage *msg){
    int status = -EINVAL;
    switch(msg->type){
        case FS_READ: status = handle_read(msg); break;
        case FS_WRITE: status = handle_write(msg); break;
        case FS_ADD_DIR: status = handle_add_dir(msg); break;
        case FS_REM_DIR: status = handle_rem_dir(msg); break;
        case FS_LIST_DIR: status = handle_list_dir(msg); break;
        default: status = -EINVAL; break;
    }
    msg->status = status;
}

int main(int argc, char **argv){
    int port = SFSS_DEFAULT_PORT; // porta padrão
    char *root = SFSS_DEFAULT_ROOT; // diretório raiz padrão
    if(argc >= 2) port = atoi(argv[1]); // se porta for fornecida, usa ela
    if(argc >= 3) root = argv[2]; // se diretório raiz for fornecido, usa ele
    snprintf(root_dir, sizeof(root_dir), "%s", root); // copia diretório raiz para variável global
    if(ensure_root_structure(root_dir) < 0){ // prepara estrutura de diretórios
        fprintf(stderr, "Falha ao preparar diretorio raiz %s\n", root_dir); // erro ao preparar diretório raiz
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0); // cria socket UDP
    if(sock < 0){ perror("socket"); return 1; }

    struct sockaddr_in addr; // estrutura de endereço
    memset(&addr, 0, sizeof(addr)); // limpa a estrutura
    addr.sin_family = AF_INET; // família IPv4
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // aceita conexões em qualquer interface
    addr.sin_port = htons(port); // define a porta

    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){ // associa o socket à porta
        perror("bind"); // erro ao bind
        return 1;
    }

    printf("[SFSS] Servidor iniciado em porta %d, raiz %s, pid = %d\n", port, root_dir, getpid());

    while(1){
        struct sockaddr_in client; // endereço do cliente
        socklen_t clen = sizeof(client); // tamanho do endereço do cliente
        SFPMessage msg; // mensagem recebida
        ssize_t n = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&client, &clen); // recebe mensagem
        if(n < 0){ // erro ao receber
            perror("recvfrom");
            continue;
        }
        handle_request(&msg); // processa a requisição
        sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&client, clen);// envia resposta
    }

    close(sock);
    return 0;
}
