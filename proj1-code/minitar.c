#include "minitar.h"

#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_TRAILING_BLOCKS 2
#define MAX_MSG_LEN 128
#define BLOCK_SIZE 512

// Constants for tar compatibility information
#define MAGIC "ustar"

// Constants to represent different file types
// We'll only use regular files in this project
#define REGTYPE '0'
#define DIRTYPE '5'

/*
 * Helper function to compute the checksum of a tar header block
 * Performs a simple sum over all bytes in the header in accordance with POSIX
 * standard for tar file structure.
 */
void compute_checksum(tar_header *header) {
    // Have to initially set header's checksum to "all blanks"
    memset(header->chksum, ' ', 8);
    unsigned sum = 0;
    char *bytes = (char *) header;
    for (int i = 0; i < sizeof(tar_header); i++) {
        sum += bytes[i];
    }
    snprintf(header->chksum, 8, "%07o", sum);
}

/*
 * Populates a tar header block pointed to by 'header' with metadata about
 * the file identified by 'file_name'.
 * Returns 0 on success or -1 if an error occurs
 */
int fill_tar_header(tar_header *header, const char *file_name) {
    memset(header, 0, sizeof(tar_header));
    char err_msg[MAX_MSG_LEN];
    struct stat stat_buf;
    // stat is a system call to inspect file metadata
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    strncpy(header->name, file_name, 100);    // Name of the file, null-terminated string
    snprintf(header->mode, 8, "%07o",
             stat_buf.st_mode & 07777);    // Permissions for file, 0-padded octal

    snprintf(header->uid, 8, "%07o", stat_buf.st_uid);    // Owner ID of the file, 0-padded octal
    struct passwd *pwd = getpwuid(stat_buf.st_uid);       // Look up name corresponding to owner ID
    if (pwd == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up owner name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->uname, pwd->pw_name, 32);    // Owner name of the file, null-terminated string

    snprintf(header->gid, 8, "%07o", stat_buf.st_gid);    // Group ID of the file, 0-padded octal
    struct group *grp = getgrgid(stat_buf.st_gid);        // Look up name corresponding to group ID
    if (grp == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up group name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->gname, grp->gr_name, 32);    // Group name of the file, null-terminated string

    snprintf(header->size, 12, "%011o",
             (unsigned) stat_buf.st_size);    // File size, 0-padded octal
    snprintf(header->mtime, 12, "%011o",
             (unsigned) stat_buf.st_mtime);    // Modification time, 0-padded octal
    header->typeflag = REGTYPE;                // File type, always regular file in this project
    strncpy(header->magic, MAGIC, 6);          // Special, standardized sequence of bytes
    memcpy(header->version, "00", 2);          // A bit weird, sidesteps null termination
    snprintf(header->devmajor, 8, "%07o",
             major(stat_buf.st_dev));    // Major device number, 0-padded octal
    snprintf(header->devminor, 8, "%07o",
             minor(stat_buf.st_dev));    // Minor device number, 0-padded octal

    compute_checksum(header);
    return 0;
}

/*
 * Removes 'nbytes' bytes from the file identified by 'file_name'
 * Returns 0 upon success, -1 upon error
 * Note: This function uses lower-level I/O syscalls (not stdio), which we'll learn about later
 */
int remove_trailing_bytes(const char *file_name, size_t nbytes) {
    char err_msg[MAX_MSG_LEN];

    struct stat stat_buf;
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    off_t file_size = stat_buf.st_size;
    if (nbytes > file_size) {
        file_size = 0;
    } else {
        file_size -= nbytes;
    }

    if (truncate(file_name, file_size) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to truncate file %s", file_name);
        perror(err_msg);
        return -1;
    }
    return 0;
}

int create_archive(const char *archive_name, const file_list_t *files) {
    // Checking whether archive_name and files contain the valid value
    if (archive_name == NULL || files == NULL || files->head == NULL || files->size == 0) {
        return -1;
    }

    // Creating a new archive
    FILE *archive = fopen(archive_name, "w");
    // Checking whether the archive is successfully created
    if (archive == NULL) {
        perror("archive open");
        return -1;
    }
    // Create visual space for header
    tar_header *header = malloc(sizeof(tar_header));
    // Checking whether the space has created
    if (header == NULL) {
        perror("malloc");
        fclose(archive);
        return -1;
    }
    // Save files's head into current
    node_t *current = files->head;
    for (size_t i = 0; i < files->size; i++) {
        char *file_name = current->name;
        // Checking whethe it is a valid node. If not, give out the error message, free the header
        // and, and stop the program. if(file_name == NULL){
        //     perror("err_msg");
        //     free(header);
        //     fclose(archive);
        //     return -1;
        // }
        // //
        if (fill_tar_header(header, file_name) != 0) {
            free(header);
            fclose(archive);
            return -1;
        }
        if (fwrite(header, 1, sizeof(tar_header), archive) != sizeof(tar_header)) {
            perror("fwrite header");
            free(header);
            fclose(archive);
            return -1;
        }
        FILE *file = fopen(file_name, "r");
        if (!file) {
            perror("file open");
            free(header);
            fclose(archive);
            return -1;
        }
        char buffer[BLOCK_SIZE];
        size_t total = 0;
        size_t nums_of_bytes = fread(buffer, 1, sizeof(buffer), file);
        while (nums_of_bytes > 0) {
            if (fwrite(buffer, 1, nums_of_bytes, archive) != nums_of_bytes) {
                perror("fwrite");
                free(header);
                fclose(archive);
                fclose(file);
                return -1;
            }
            total += nums_of_bytes;
            nums_of_bytes = fread(buffer, 1, sizeof(buffer), file);
        }
        if (fclose(file) != 0) {
            perror("fclose archive");
            free(header);
            fclose(archive);
            return -1;
        }
        size_t padding = (BLOCK_SIZE - (total % BLOCK_SIZE)) % BLOCK_SIZE;
        if (padding != 0) {
            char Z[BLOCK_SIZE] = {0};
            if (fwrite(Z, 1, padding, archive) != padding) {
                perror("fwrite padding");
                free(header);
                fclose(archive);
                return -1;
            }
        }
        current = current->next;
    }
    char footer[2 * BLOCK_SIZE] = {0};
    if (fwrite(footer, 1, sizeof(footer), archive) != 2 * BLOCK_SIZE) {
        perror("fwrite footer");
        free(header);
        fclose(archive);
        return -1;
    }
    free(header);
    if (fclose(archive) != 0) {
        perror("fclose archive");
        return -1;
    }
    return 0;
}

int append_files_to_archive(const char *archive_name, const file_list_t *files) {
    //
    if (archive_name == NULL || files == NULL || files->head == NULL || files->size == 0) {
        return -1;
    }
    if (remove_trailing_bytes(archive_name, 1024) != 0) {
        return -1;
    }
    FILE *archive = fopen(archive_name, "a");
    if (archive == NULL) {
        perror("archive fopen");
        return -1;
    }
    tar_header *header = malloc(sizeof(tar_header));
    if (header == NULL) {
        perror("malloc");
        fclose(archive);
        return -1;
    }
    node_t *current = files->head;
    for (size_t i = 0; i < files->size; i++) {
        char *file_name = current->name;
        if (file_name == NULL) {
            perror("err_msg");
            free(header);
            fclose(archive);
            return -1;
        }
        if (fill_tar_header(header, file_name) != 0) {
            free(header);
            fclose(archive);
            return -1;
        }
        if (fwrite(header, 1, sizeof(tar_header), archive) != sizeof(tar_header)) {
            perror("fwrite header");
            free(header);
            fclose(archive);
            return -1;
        }
        FILE *file = fopen(file_name, "r");
        if (!file) {
            perror("file open");
            free(header);
            fclose(archive);
            return -1;
        }
        char buffer[BLOCK_SIZE];
        size_t total = 0;
        size_t nums_of_bytes = fread(buffer, 1, sizeof(buffer), file);
        while (nums_of_bytes > 0) {
            if (fwrite(buffer, 1, nums_of_bytes, archive) != nums_of_bytes) {
                perror("fwrite");
                free(header);
                fclose(archive);
                fclose(file);
                return -1;
            }
            total += nums_of_bytes;
            nums_of_bytes = fread(buffer, 1, sizeof(buffer), file);
        }
        if (fclose(file) != 0) {
            perror("fclose archive");
            free(header);
            fclose(archive);
            return -1;
        }
        size_t padding = (BLOCK_SIZE - (total % BLOCK_SIZE)) % BLOCK_SIZE;
        if (padding != 0) {
            char Z[BLOCK_SIZE] = {0};
            if (fwrite(Z, 1, padding, archive) != padding) {
                perror("fwrite padding");
                free(header);
                fclose(archive);
                return -1;
            }
        }
        current = current->next;
    }
    char footer[2 * BLOCK_SIZE] = {0};
    if (fwrite(footer, 1, sizeof(footer), archive) != 2 * BLOCK_SIZE) {
        perror("fwrite footer");
        free(header);
        fclose(archive);
        return -1;
    }
    free(header);
    if (fclose(archive) != 0) {
        perror("fclose archive");
        return -1;
    }
    return 0;
}

int get_archive_file_list(const char *archive_name, file_list_t *files) {
    if (archive_name == NULL || files == NULL) {
        perror("Invalid input");
        return -1;
    }

    //Reset the file list in case some potential problem
    files->head = NULL;
    files->size = 0;

    // Open archive as reding mode
    FILE *archive = fopen(archive_name, "rb");
    if (!archive) {
        perror("Unable to read archive");
        return -1;
    }

    // Make a tar_header to store the information in header
    tar_header *header;

    node_t *trackingNode = NULL;

    while (1) {
        size_t n = fread(&header, 1, sizeof(tar_header), archive);
        if (n != 512) {
            perror("File read");
            fclose(archive);
            return -1;
        }

        size_t tmpSum = 0;
        for (size_t i = 0; i < 512; i++) {
            if (((char *) header)[i] != '0' &&
                ((char *) header)[i] != '\0') {    // I'm not sure which 0 we use for padding
                tmpSum = 1;
                break;
            }
        }

        // Check whether we reach the footer of the archive
        if (tmpSum == 0) {
            break;
        }

        // Create a new node to save the information of the list
        node_t *curNode = malloc(sizeof(node_t));
        if (!curNode) {
            perror("malloc node");
            fclose(archive);
            return -1;
        }

        // Setup the curNode to be prepared for append
        strncpy(curNode->name, header->name, sizeof(curNode->name) - 1);
        curNode->name[sizeof(curNode->name) - 1] = '\0';
        curNode->next = NULL;

        // Find the correct position for curNode, then update the trackingNode
        if (files->head == NULL) {
            files->head = curNode;
        } else {
            trackingNode->next = curNode;
        }

        trackingNode = curNode;
        files->size++;

        // For far the pointer should jump to the starter of next header
        long jump = ((strtol(header->size, NULL, 8) / 512) + 1) * 512;
        if (fseek(archive, jump, SEEK_CUR) != 0) {
            perror("fseek");
            fclose(archive);
            node_t *delNode = files->head;
            node_t *temp;
            while (delNode != NULL) {
                temp = delNode;
                delNode = delNode->next;
                free(temp);
            }
            return -1;
        }
    }

    fclose(archive);
    return 0;
}

int extract_files_from_archive(const char *archive_name) {
    // error checking for Null pointer
    if (archive_name == NULL){
        perror("bad input");
        return -1;
    }
    FILE *archive = fopen(archive_name, "r");
    if (archive == NULL){
        perror("fopen archive");
        return -1;
    }
    tar_header header;
    while (1){
        size_t n_bytes = fread(&header, 1, sizeof(tar_header), archive);
        if (n_bytes != sizeof(tar_header)){
            perror("File read");
            fclose(archive);
            return -1;
        }
        int zero = 1;
        //Loop for every 512 bytes and find whether it is the first 512 bytes footer
        for (size_t i = 0; i < sizeof(tar_header); i++){
            if (((char *)&header)[i] != 0){
                zero = 0;
                break;
            }
        }
        if(zero == 0){
            char zero_block[512];
            fread(zero_block, 1, 512, archive);//Read the second 512 bytes footer
            break;
        }
        char file_name[100];
        memcpy(file_name, header.name, 100);
        char file_size[12];
        memcpy(file_size, header.size, 12);
        FILE* output_file = fopen(file_name, "w");
        if(output_file == NULL){
            perror("fopen output_file");
            fclose(archive);
            return -1;
        }
        unsigned long nums = (unsigned long)file_size;
        char buffer[1024];
        size_t capacity = sizeof buffer;
        while(nums > 0){
            size_t part = (nums > capacity)? capacity : (size_t)nums;
            size_t n = fread(buffer, 1, part, archive);
            if(n != part){
                perror("fread archive");
                fclose(output_file);
                fclose(archive);
                return -1;
            }
            if(fwrite(buffer, 1, n, output_file) != n){
                perror("fwrite output_file");
                fclose(output_file);
                fclose(archive);
                return -1;
            }
            n_bytes -= n;
        }
        if(fclose(output_file) != 0){
            perror("fclose output_file");
            fclose(archive);
            return -1;
        }
        size_t padding = (BLOCK_SIZE - ((unsigned long)file_size % BLOCK_SIZE)) % BLOCK_SIZE;
        if(padding != 0){
            if(fseek(archive, padding, SEEK_CUR) != 0){
                perror("fseek");
                fclose(archive);
                return -1;
            }
        }
    }
    if(fclose(archive) != 0){
        perror("fclose output_file");
        return -1;
    }
    return 0;
}
