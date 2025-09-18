#include <stdio.h>
#include <string.h>

#include "file_list.h"
#include "minitar.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s -c|a|t|u|x -f ARCHIVE [FILE...]\n", argv[0]);
        return 0;
    }

    file_list_t files;
    file_list_init(&files);

    // TODO: Parse command-line arguments and invoke functions from 'minitar.h'
    // to execute archive operations
    const char *op = argv[1];
    const char *archive = NULL;
    int first_file_idx = 0;
    int rc;
    if (strcmp(op, "-c") == 0 && argc >= 5 && strcmp(argv[2], "-f") == 0) {
        archive = argv[3];
        first_file_idx = 4;
        for (int i = first_file_idx; i < argc; ++i) {
            file_list_add(&files, argv[i]);
        }

        rc = create_archive(archive, &files);
        if (rc != 0) {
            perror("create_archive");
            return 1;
        }
    } else if (strcmp(op, "-a") == 0 && argc >= 5 && strcmp(argv[2], "-f") == 0) {
        archive = argv[3];
        first_file_idx = 4;
        for (int i = first_file_idx; i < argc; ++i) {
            file_list_add(&files, argv[i]);
        }

        rc = append_files_to_archive(archive, &files);
        if (rc != 0) {
            perror("create_archive");
            return 1;
        }
    } else if (strcmp(op, "-x") == 0 && argc == 4 && strcmp(argv[2], "-f") == 0) {
        archive = argv[3];
        rc = extract_files_from_archive(archive);
        if (rc != 0) {
            perror("create_archive");
            return 1;
        }
    }
    else {
        fprintf(stderr, "Unsupported op. Try: %s c ARCHIVE [FILE...]\n", argv[0]);
        return 1;
    }
    file_list_clear(&files);
    return 0;
}
