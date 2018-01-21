// common includes
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdalign.h>

#include "disadiff.h"
#include "types.h"

#define BUFFER_SIZE (64*1024*1024)
#define GET_DPFS_BIT(b, lvl) (((((u32*) lvl)[b >> 5]) >> (31 - (b % 32))) & 1)


bool readDpfsLvl3(DifiStruct* difis, u8* partition, u8* buffer, u32 offset, u32 size) {
    DpfsDescriptor* dpfs = &(difis->dpfs);
    
    u8* lvl1 = partition + dpfs->offset_lvl1;
    if (difis->difi.dpfs_lvl1_selector) lvl1 += dpfs->size_lvl1;
    for (u32 i = 0; i < size; i++) {
        u32 idx_lvl2 = (offset+i) >> dpfs->log_lvl3;
        u32 idx_lvl1 = (idx_lvl2 >> 3) >> dpfs->log_lvl2;
        
        u8* lvl2 = partition + dpfs->offset_lvl2;
        if (GET_DPFS_BIT(idx_lvl1, lvl1)) lvl2 += dpfs->size_lvl2;
        
        u8* lvl3 = partition + dpfs->offset_lvl3;
        if (GET_DPFS_BIT(idx_lvl2, lvl2)) lvl3 += dpfs->size_lvl3;
        
        buffer[i] = lvl3[offset + i];
    }
    
    return true;
}

int main(int argc, char** argv) {
    u8* buffer_in = (u8*) malloc(BUFFER_SIZE);
    u8* buffer_out = (u8*) malloc(BUFFER_SIZE>>1);
    char* path_in = argv[1];
    char* path_out = argv[2];
    FILE* fp;
    
    printf("%s v0.0.1\n\n", *argv);
    if (argc < 3) {
        printf("ERROR, input/output not given\n");
        return 1;
    }
    
    printf("Loading %s... ", path_in);
    fp = fopen(path_in, "rb");
    if (!fp) return 1;
    u32 fsize = fread(buffer_in, 1, BUFFER_SIZE, fp);
    fclose(fp);
    printf("%u kiB\n", fsize / 1024);
    if (!fsize) return 1;
    
    DiffHeader* diff = (DiffHeader*) (buffer_in + 0x100);
    printf("DIFF magic: %.4s\n", diff->magic);
    if (strncmp((char*) diff->magic, "DIFF", 4) != 0) return 1;
    printf ("partition offset: %08X\n", (u32) diff->offset_partition);
    printf ("partition size: %u kiB\n", (u32) diff->size_partition / 1024);
    
    printf ("active table: %u\n", diff->active_table);
    u32 offset_difi = (diff->active_table) ? diff->offset_table1 : diff->offset_table0;
    printf ("active table offset: %08X\n", offset_difi);
    
    DifiStruct* difis = (DifiStruct*) (buffer_in + offset_difi);
    printf("DIFI magic: %.4s\n", difis->difi.magic);
    printf("IVFC magic: %.4s\n", difis->ivfc.magic);
    printf("DPFS magic: %.4s\n", difis->dpfs.magic);
    
    printf("DPFS lvl1: %08X / %u byte / preselected: %u\n",
        (u32) difis->dpfs.offset_lvl1, (u32) difis->dpfs.size_lvl1, (u32) difis->difi.dpfs_lvl1_selector);
    printf("DPFS lvl2: %08X / %u byte / %u byte\n",
        (u32) difis->dpfs.offset_lvl2, (u32) difis->dpfs.size_lvl2, 1 << difis->dpfs.log_lvl2);
    printf("DPFS lvl3: %08X / %u byte / %u byte\n",
        (u32) difis->dpfs.offset_lvl3, (u32) difis->dpfs.size_lvl3, 1 << difis->dpfs.log_lvl3);
    printf("IVFC lvl4 offset: %08X\n", (u32) difis->ivfc.offset_lvl4);
    printf("IVFC lvl4 size: %u kiB\n", (u32) difis->ivfc.size_lvl4 / 1024);
    
    u8* partition = buffer_in + diff->offset_partition;
    readDpfsLvl3(difis, partition, buffer_out,
        difis->ivfc.offset_lvl4, difis->ivfc.size_lvl4);
        
    printf("Writing %s... ", path_out);
    fp = fopen(path_out, "wb");
    if (!fp) return 1;
    fsize = fwrite(buffer_out, 1, difis->ivfc.size_lvl4, fp);
    fclose(fp);
    printf("%u kiB\n", fsize / 1024);
    
    if (argc > 3) {
        char* path_cmp = argv[3];
        printf("Comparing %s... ", path_cmp);
        fp = fopen(path_cmp, "rb");
        if (!fp) return 1;
        if (fread(buffer_in, 1, difis->ivfc.size_lvl4, fp) != fsize) return 1;
        fclose(fp);
        for (u32 i = 0; i < fsize; i++) {
            if ((buffer_in[i] != 0xDD) && (buffer_in[i] != buffer_out[i])) {
                printf("MISMATCH (%08X)!\n", i);
                return 1;
            }
        }
        printf("OK!\n");
    }
    
    return 0;
}

