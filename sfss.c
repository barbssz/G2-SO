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

// Cria diretório se não existir.
int ensure_dir(char *path){
    struct stat st;
    if(stat(path, &st) == 0){
        if(S_ISDIR(st.st_mode)) return 0;
        return -ENOTDIR;
    }
    if(mkdir(path, 0775) < 0 && errno != EEXIST)
        return -errno;
    return 0;
}

// Prepara SFS-root-dir com A0..A5.
int ensure_root_structure(char *root){
    if(ensure_dir(root) < 0)
        return -1;
    char buf[PATH_MAX];
    for(int i=0;i<=NUM_PROCS_APP;i++){
        size_t len = strlen(root);
        if(len + 4 >= sizeof(buf))
            continue;
        snprintf(buf, sizeof(buf), "%s/A%d", root, i);
        ensure_dir(buf);
    }
    return 0;
}

int has_invalid(char *s){
    if(!s) return 1;
    for(char *p=s; *p; ++p){
        if(*p == '\\') return 1;
    }
    if(strstr(s, "..")) return 1;
    return 0;
}

// Monta caminho absoluto a partir do prefixo raiz.
int build_path(char *rel, char *out, size_t out_len){
    if(!rel || rel[0] != '/' || has_invalid(rel))
        return -EINVAL;
    if(snprintf(out, out_len, "%s%s", root_dir, rel) >= (int)out_len)
        return -ENAMETOOLONG;
    return 0;
}

int ensure_parent_dirs(char *path){
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp));
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
int handle_write(SFPMessage *msg){
    char abs_path[PATH_MAX];
    int rv = build_path(msg->path, abs_path, sizeof(abs_path));
    if(rv < 0) return rv;

    ensure_parent_dirs(abs_path);
    FILE *f = fopen(abs_path, "r+b");
    if(!f) f = fopen(abs_path, "w+b");

    if(!f) 
        return -errno;

    if(fseek(f, 0, SEEK_END) < 0){ 
        fclose(f); 
        return -errno;
     }

    long current = ftell(f);
    if(current < 0){ fclose(f); return -errno; }
    if(msg->offset > current){
        long diff = msg->offset - current;
        while(diff-- > 0) fputc(' ', f);
    }

    if(fseek(f, msg->offset, SEEK_SET) < 0){ fclose(f); return -errno; }
    if(fwrite(msg->payload, 1, SFP_PAYLOAD_LEN, f) != SFP_PAYLOAD_LEN){ fclose(f); return -EIO; }
    fclose(f);
    msg->payload_len = SFP_PAYLOAD_LEN;
    return 0;
}

// Lê 16 bytes a partir do offset.
int handle_read(SFPMessage *msg){
    char abs_path[PATH_MAX];
    int rv = build_path(msg->path, abs_path, sizeof(abs_path));
    if(rv < 0) 
        return rv;


    FILE *f = fopen(abs_path, "rb");
    if(!f) return -errno;
    if(fseek(f, 0, SEEK_END) < 0){ 
        fclose(f);
        return -errno; 
    } // Vai para o fim do arquivo
    long size = ftell(f);

    if(size < 0){ fclose(f); 
        return -errno; } // Erro ao obter tamanho

    if(msg->offset >= size){
        fclose(f); 
        return -ERANGE; } // Offset além do tamanho do arquivo
    if(fseek(f, msg->offset, SEEK_SET) < 0){ // Vai para o offset desejado
        fclose(f); // Erro ao buscar
        return -errno; 
    }
    size_t n = fread(msg->payload, 1, SFP_PAYLOAD_LEN, f);
    fclose(f);
    msg->payload_len = (int)n;
    if(n == 0) 
        return -EIO; // Erro de leitura
    if(n < SFP_PAYLOAD_LEN) // se leu menos que 16 bytes, preenche o resto com espaços
        memset(msg->payload + n, ' ', SFP_PAYLOAD_LEN - n);
    return 0;
}

// Cria subdiretório.
int handle_add_dir(SFPMessage *msg){
    if(has_invalid(msg->name)) return -EINVAL;
    char parent[PATH_MAX];
    if(build_path(msg->path, parent, sizeof(parent)) < 0)
        return -EINVAL;
    char target[PATH_MAX];
    if(snprintf(target, sizeof(target), "%s/%s", parent, msg->name) >= (int)sizeof(target))
        return -ENAMETOOLONG;
    ensure_dir(parent);
    if(mkdir(target, 0775) < 0 && errno != EEXIST)
        return -errno;
    return 0;
}

// Remove subdiretório.
int handle_rem_dir(SFPMessage *msg){
    if(has_invalid(msg->name)) return -EINVAL;
    char parent[PATH_MAX];
    if(build_path(msg->path, parent, sizeof(parent)) < 0)
        return -EINVAL;
    char target[PATH_MAX];
    if(snprintf(target, sizeof(target), "%s/%s", parent, msg->name) >= (int)sizeof(target))
        return -ENAMETOOLONG;
    if(rmdir(target) < 0)
        return -errno;
    return 0;
}

// Lista arquivos/subdirs no diretório alvo.
int handle_list_dir(SFPMessage *msg){
    char abs_path[PATH_MAX];
    if(build_path(msg->path, abs_path, sizeof(abs_path)) < 0)
        return -EINVAL;
    DIR *dir = opendir(abs_path);
    if(!dir) return -errno;
    struct dirent *ent;
    int count = 0;
    while((ent = readdir(dir)) != NULL && count < SFP_MAX_ENTRIES){
        if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char entry_path[PATH_MAX];
        size_t base_len = strnlen(abs_path, sizeof(abs_path));
        size_t name_len = strnlen(ent->d_name, sizeof(ent->d_name));
        if(base_len + 1 + name_len + 1 >= sizeof(entry_path))
            continue;
        strncpy(msg->entries[count], ent->d_name, SFP_MAX_NAME-1);
        msg->entries[count][SFP_MAX_NAME-1] = '\0';
        memcpy(entry_path, abs_path, base_len);
        entry_path[base_len] = '/';
        memcpy(entry_path + base_len + 1, ent->d_name, name_len);
        entry_path[base_len + 1 + name_len] = '\0';
        struct stat st;
        if(stat(entry_path, &st) == 0 && S_ISDIR(st.st_mode))
            msg->entry_is_dir[count] = 1;
        else
            msg->entry_is_dir[count] = 0;
        count++;
    }
    closedir(dir);
    msg->entry_count = count;
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
    int port = SFSS_DEFAULT_PORT;
    char *root = SFSS_DEFAULT_ROOT;
    if(argc >= 2) port = atoi(argv[1]);
    if(argc >= 3) root = argv[2];
    snprintf(root_dir, sizeof(root_dir), "%s", root);
    if(ensure_root_structure(root_dir) < 0){
        fprintf(stderr, "Falha ao preparar diretorio raiz %s\n", root_dir);
        return 1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0){ perror("socket"); return 1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
        perror("bind");
        return 1;
    }

    printf("[SFSS] Servidor iniciado em porta %d, raiz %s, pid = %d\n", port, root_dir, getpid());

    while(1){
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        SFPMessage msg;
        ssize_t n = recvfrom(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&client, &clen);
        if(n < 0){
            perror("recvfrom");
            continue;
        }
        handle_request(&msg);
        sendto(sock, &msg, sizeof(msg), 0, (struct sockaddr*)&client, clen);
    }

    close(sock);
    return 0;
}
