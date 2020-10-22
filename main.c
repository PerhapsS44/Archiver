// 312CA_Saraev_Stefan_Tema3
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define CMD_LEN 512
union record {
  char charptr[CMD_LEN];
  struct header {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char linkflag;
    char linkname[100];
    char magic[8];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
  } header;
};

// Aici calculez Unix time stamp
long int convert_time(char *date, char *time) {
  struct tm tm;
  char *part;
  long int ut = 0;
  // Am inteles ca asta de mai jos nu poate fi folosita (cica cu e in C99)
  // strptime(date, "%Y-%m-%d", &tm);
  part = strtok(date, "-");
  tm.tm_year = atoi(part) - 1900;
  part = strtok(NULL, "-");
  tm.tm_mon = atoi(part) - 1;
  part = strtok(NULL, "-");
  tm.tm_mday = atoi(part);

  part = strtok(time, ":.");
  tm.tm_hour = atoi(part);
  part = strtok(NULL, ":.");
  tm.tm_min = atoi(part);
  part = strtok(NULL, ":.");
  tm.tm_sec = atoi(part);
  tm.tm_isdst = -1;

  ut = (long)mktime(&tm);
  return ut;
}

/*
 * Functia aceasta am scris-o pentru a-mi converti numerele in baza 8 si a le
 * scrie in header, in stringurile respective type spune cati bytes are stringul
 * in care voi scrie a este numarul pe care il convertesc b este stringul in
 * care scriu
 */
void itoa_m(int type, int a, char *b) {
  int k, i = 0;
  if (type == 7) { // pt stringuri cu 8 bytes
    k = 6;
    // umplu primii k+1 bytes cu '0'
    for (i = 0; i < k + 1; i++) {
      b[i] = '0';
    }
    b[7] = 0;
  } else if (type == 12) { // pt stringuri cu 12 bytes
    k = 10;
    for (i = 0; i < k + 1; i++) {
      b[i] = '0';
    }
  }
  i = 0;
  while (a > 0) {
    b[k - i] = a % 8 + (int)'0';
    a /= 8;
    i++;
  }
}
// Aici convertesc din octal in decimal pentru 'list' si 'extract'
long int otod(char *a) {
  long int r = 0;
  int i;
  for (i = 0; a[i] != 0; i++) {
    r += (a[10 - i] - '0') * (1 << (3 * i));
  }
  return r;
}

// Calculez reprezentarea permisiunilor
void mode(char *perm, char m[8]) {
  int i;
  for (i = 0; i < 7; i++) {
    m[i] = '0';
  }
  if (perm[1] != '-')
    m[4] += 4;
  if (perm[2] != '-')
    m[4] += 2;
  if (perm[3] != '-')
    m[4] += 1;
  if (perm[4] != '-')
    m[5] += 4;
  if (perm[5] != '-')
    m[5] += 2;
  if (perm[6] != '-')
    m[5] += 1;
  if (perm[7] != '-')
    m[6] += 4;
  if (perm[8] != '-')
    m[6] += 2;
  if (perm[9] != '-')
    m[6] += 1;
}

// Aici creez headerul
union record create_header(char *fname, char *perm, int uid, int gid, int size,
                           long int mtime, char *user, char *group) {
  union record uh;
  unsigned long int chksum = 0;
  int i;
  // umplu header-ul de 0-uri
  for (i = 0; i < CMD_LEN; i++) {
    uh.charptr[i] = 0;
  }
  // Populez headerul
  strcpy(uh.header.name, fname);
  mode(perm, uh.header.mode);
  itoa_m(7, uid, uh.header.uid);
  itoa_m(7, gid, uh.header.gid);
  itoa_m(12, size, uh.header.size);
  itoa_m(12, mtime, uh.header.mtime);
  // uh.header.linkflag = '0'  // Nu se specifica in enunt ce fel de 0
  strcpy(uh.header.magic, "GNUtar ");
  strcpy(uh.header.uname, user);
  strcpy(uh.header.gname, group);

  strcpy(uh.header.chksum, "        "); // pt asta am pierdut 5 ore :))((((
  for (i = 0; i < CMD_LEN; i++) {
    chksum += uh.charptr[i];
  }
  itoa_m(7, chksum, uh.header.chksum);
  return uh;
}

// Aici creez arhiva
void create(char *par1, char *par2) {
  FILE *files = fopen("files.txt", "r");
  FILE *arch = fopen(par1, "wb");
  FILE *binfile, *usermap;
  char perm[20], user[20], group[20], date[40], time[40], pref[10], fname[100],
      datablocks[CMD_LEN], *datablockd, *token_users, fisier[300];
  int n_links, size, uid, gid, i, j, no_blocks, rest;
  long int unixtime;
  union record h;
  // Citeste din fisierul files.txt pana ajungi la final
  do {
    fscanf(files, " %s %d %s %s %d %s %s %s %s ", perm, &n_links, user, group,
           &size, date, time, pref, fname);
    strcpy(fisier, par2);
    strcat(fisier, fname);
    usermap = fopen("usermap.txt", "r");
    // Citeste din usermap.txt pana gasesti userul cautat
    do {
      fgets(h.charptr, CMD_LEN, usermap);
      token_users = strtok(h.charptr, ":");
      if (strcmp(token_users, user) == 0) {
        token_users = strtok(NULL, ":"); // x
        token_users = strtok(NULL, ":"); // uid
        uid = atoi(token_users);
        token_users = strtok(NULL, ":"); // gid
        gid = atoi(token_users);
        break;
      }
    } while (!feof(usermap));
    fclose(usermap);

    unixtime = convert_time(date, time);
    h = create_header(fname, perm, uid, gid, size, unixtime, user, group);
    fwrite(&h, sizeof(union record), 1, arch);
    if ((binfile = fopen(fisier, "rb")) != NULL) {
      // Calculez cate blocuri de 512 se afla in fisierul meu
      no_blocks = size / CMD_LEN;
      rest = size % CMD_LEN;
      // Scriu blocurile de 512 ca atare
      for (i = 0; i < no_blocks; i++) {
        fread(datablocks, sizeof(char), CMD_LEN, binfile);
        fwrite(datablocks, sizeof(char), CMD_LEN, arch);
      }
      // Scriu ce a mai ramas din fisier, daca a mai ramas ceva
      if (rest > 0) {
        datablockd = (char *)malloc(rest * sizeof(char));
        fread(datablockd, sizeof(char), rest, binfile);
        fwrite(datablockd, sizeof(char), rest, arch);
        free(datablockd);
        datablockd = (char *)calloc((CMD_LEN - rest), sizeof(char));
        fwrite(datablockd, sizeof(char), (CMD_LEN - rest), arch);
        free(datablockd);
      }
      fclose(binfile);
    } else {
      printf("> Failed!\n");
      fclose(arch);
      fclose(files);
      break;
    }
  } while (!feof(files));
  // Adaug la final un bloc de 512 de 0-uri
  for (j = 0; j < CMD_LEN; j++) {
    datablocks[j] = 0;
  }
  fwrite(datablocks, sizeof(char), CMD_LEN, arch);
  fclose(arch);
  fclose(files);
  printf("> Done!\n");
}

// Aici afisez continutul arhivei
void list(char *par1) {
  FILE *arch = fopen(par1, "rb");
  if (arch == NULL) {
    printf("> File not found!\n");
    return;
  }
  union record block;
  fread(block.charptr, sizeof(char), CMD_LEN, arch);
  // Citesc headerul, afisez numele fisierului si sar pana la urmatorul header,
  // pana ajung la blocul de 0-uri
  do {
    if (otod(block.header.size) > 0) {
      fseek(arch, ((otod(block.header.size) / CMD_LEN) + 1) * CMD_LEN,
            SEEK_CUR);
    }
    printf("> %s\n", block.header.name);
    fread(block.charptr, sizeof(char), CMD_LEN, arch);
  } while (strcmp(block.header.name, "") > 0);
  fclose(arch);
}

// Aici dezarhivez fisierele
void extract(char *par1, char *par2) {
  FILE *arch = fopen(par2, "rb");
  FILE *f;
  char name[100], found = 0;
  long int size;
  union record block;
  fread(block.charptr, sizeof(char), CMD_LEN, arch);
  // Citesc headerul si creez fisierele din arhiva, dupa care scriu in ele
  // continutul, fara sa trec si 0-urile
  while ((found == 0) && strcmp(block.header.name, "") > 0) {
    if (strcmp(block.header.name, par1) == 0) {
      found = 1;
      name[0] = 0;
      strcat(name, "extracted_");
      strcat(name, par1);
      f = fopen(name, "wb");
      size = otod(block.header.size); // convertesc din octal in decimal
      for (int i = 0; i < size / CMD_LEN; i++) {
        fread(block.charptr, sizeof(char), CMD_LEN, arch);
        fwrite(block.charptr, sizeof(char), CMD_LEN, f);
      }
      if (size % CMD_LEN != 0) {
        fread(block.charptr, sizeof(char), size % CMD_LEN, arch);
        fwrite(block.charptr, sizeof(char), size % CMD_LEN, f);
      }
      fclose(f);
      printf("> File extraxted!\n");
      break;
    }
    if (otod(block.header.size) > 0) {
      fseek(arch, ((otod(block.header.size) / CMD_LEN) + 1) * CMD_LEN,
            SEEK_CUR);
    }
    fread(block.charptr, sizeof(char), CMD_LEN, arch);
  }
  if (!found) {
    printf("> File not found!\n");
  }
  fclose(arch);
}

// Aici compar comenzile date la stdin cu regulile date in enunt
int ruleaza_comanda(char com[CMD_LEN]) {
  char temp[CMD_LEN], *token, *par1, *par2;
  strcpy(temp, com);
  token = strtok(temp, " \n\0");
  if (strcmp(token, "exit") == 0) {
    return -1;
  } else if (strcmp(token, "create") == 0) {
    par1 = strtok(NULL, " \n\0");
    if (par1 == NULL) {
      printf("> Wrong command!\n");
      return 0;
    }
    par2 = strtok(NULL, " \n\0");
    if (par2 == NULL) {
      printf("> Wrong command!\n");
      return 0;
    }
    create(par1, par2);
  } else if (strcmp(token, "list") == 0) {
    par1 = strtok(NULL, " \n\0");
    if (par1 == NULL) {
      printf("> Wrong command!\n");
      return 0;
    }
    list(par1);
  } else if (strcmp(token, "extract") == 0) {
    par1 = strtok(NULL, " \n\0");
    if (par1 == NULL) {
      printf("> Wrong command!\n");
      return 0;
    }
    par2 = strtok(NULL, " \n\0");
    if (par2 == NULL) {
      printf("> Wrong command!\n");
      return 0;
    }
    extract(par1, par2);
  } else {
    printf("> Wrong command!\n");
  }
  return 0;
}

int main() {
  char comanda[CMD_LEN];
  do {
    fgets(comanda, CMD_LEN, stdin);
    comanda[strlen(comanda) - 1] = '\0';
  } while (ruleaza_comanda(comanda) != -1);
  return 0;
}
