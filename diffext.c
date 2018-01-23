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
#define GET_DPFS_BIT(b, lvl) (((((u32*) (void*) lvl)[b >> 5]) >> (31 - (b % 32))) & 1)


u32 readIvfcLvl4Old(u8* output, const u8* data, const DisaDiffReaderInfo* info, u32 offset, u32 size) {
    // data: full DISA/DIFF file in memory
    // offset: offset inside IVFC lvl4
    
    // sanity checks
    if (offset > info->size_ivfc_lvl4) return 0;
    else if (offset + size > info->size_ivfc_lvl4) size = info->size_ivfc_lvl4 - offset;
    
    // quick reading in case of external IVFC lvl4
    if (info->ivfc_use_extlvl4) {
        u8* data_lvl4 = (u8*) data + info->offset_ivfc_lvl4;
        memcpy(output, data_lvl4 + offset, size);
    }
    
    // full reading below
    u32 offset_in_lvl3 = info->offset_ivfc_lvl4 + offset;
    
    u8* lvl1 = (u8*) data + info->offset_dpfs_lvl1;
    if (info->dpfs_lvl1_selector) lvl1 += info->size_dpfs_lvl1;
    
    for (u32 i = 0; i < size; i++) {
        // idx_lvl2 & idx_lvl1 are bit offsets
        u32 idx_lvl2 = (offset_in_lvl3 + i) >> info->log_dpfs_lvl3;
        u32 idx_lvl1 = (idx_lvl2 >> 3) >> info->log_dpfs_lvl2;
        
        u8* lvl2 = (u8*) data + info->offset_dpfs_lvl2;
        if (GET_DPFS_BIT(idx_lvl1, lvl1)) lvl2 += info->size_dpfs_lvl2;
        
        u8* lvl3 = (u8*) data + info->offset_dpfs_lvl3;
        if (GET_DPFS_BIT(idx_lvl2, lvl2)) lvl3 += info->size_dpfs_lvl3;
        
        u8* data_lvl4 = lvl3 + info->offset_ivfc_lvl4;
        output[i] = data_lvl4[offset + i];
    }
    
    return size;
}

u32 readIvfcLvl4(u8* output, const u8* data, const DisaDiffReaderInfo* info, u32 offset, u32 size) {
    // data: full DISA/DIFF file in memory
    // offset: offset inside IVFC lvl4
    
    // sanity checks - offset & size
    if (offset > info->size_ivfc_lvl4) return 0;
    else if (offset + size > info->size_ivfc_lvl4) size = info->size_ivfc_lvl4 - offset;
    
    // quick reading in case of external IVFC lvl4
    if (info->ivfc_use_extlvl4) {
        u8* data_lvl4 = (u8*) data + info->offset_ivfc_lvl4;
        memcpy(output, data_lvl4 + offset, size);
        return size;
    } else if (!info->dpfs_lvl2_cache) return 0;
    
    // full reading in standard case
    const u32 offset_start = info->offset_ivfc_lvl4 + offset;
    const u32 offset_end = offset_start + size;
    const u8* lvl2 = info->dpfs_lvl2_cache;
    const u8* lvl3_0 = (u8*) data + info->offset_dpfs_lvl3;
    const u8* lvl3_1 = lvl3_0 + info->size_dpfs_lvl3;
    const u32 log_lvl3 = info->log_dpfs_lvl3;
    
    u32 read_start = offset_start;
    u32 read_end = read_start;
    u32 bit_state = 0;
    
    // full reading below
    while (read_start < offset_end) {
        // read bits until bit_state does not match
        // idx_lvl2 is a bit offset
        u32 idx_lvl2 = read_end >> log_lvl3;
        if (GET_DPFS_BIT(idx_lvl2, lvl2) == bit_state) {
            read_end = (idx_lvl2+1) << log_lvl3;
            if (read_end >= offset_end) read_end = offset_end;
            else continue;
        }
        // read data if there is any
        if (read_start < read_end) {
            const u8* lvl3 = bit_state ? lvl3_1 : lvl3_0;
            memcpy(output + (read_start - offset_start), lvl3 + read_start, read_end - read_start);
            read_start = read_end;
        }
        // flip the bit_state
        bit_state = ~bit_state & 0x1;
    }
    
    return size;
}

bool buildDpfsLvl2Cache(DisaDiffReaderInfo* info, const void* data, u8* cache, u32 cache_size) {
    const u32 min_cache_bits = (info->size_dpfs_lvl3 + (1 << info->log_dpfs_lvl3) - 1) >> info->log_dpfs_lvl3;
    const u32 min_cache_size = ((min_cache_bits + 31) >> (3 + 2)) << 2;
    const u8* lvl1 = (u8*) data + info->offset_dpfs_lvl1 + ((info->dpfs_lvl1_selector) ? info->size_dpfs_lvl1 : 0);
    const u8* lvl2_0 = (u8*) data + info->offset_dpfs_lvl2;
    const u8* lvl2_1 = lvl2_0 + info->size_dpfs_lvl2;
    
    // safety
    if (info->ivfc_use_extlvl4 ||
        (cache_size < min_cache_size) ||
        (min_cache_size > info->size_dpfs_lvl2) ||
        (min_cache_size > (info->size_dpfs_lvl1 << (3 + info->log_dpfs_lvl2))))
        return false;
    
    // copy full lvl2_0 to cache
    memcpy(cache, lvl2_0, min_cache_size);
    
    // cherry-pick lvl2_1
    u32 log_lvl2 = info->log_dpfs_lvl2;
    for (u32 i = 0; (i << (3 + log_lvl2)) < min_cache_size; i += 4) {
        u32 dword = *(u32*) (void*) (lvl1 + i);
        for (u32 b = 0; b < 32; b++) {
            if ((dword >> (31 - b)) & 1) {
                u32 offset = ((i << 3) + b) << log_lvl2;
                memcpy(cache + offset, lvl2_1 + offset, 1 << log_lvl2);
            }
        }
    }
    
    info->dpfs_lvl2_cache = cache;
    return true;
}

bool getDisaDiffReaderInfo(DisaDiffReaderInfo* info, void* data, u32 data_size, bool partitionB) {
    const u8 disa_magic[] = { DISA_MAGIC };
    const u8 diff_magic[] = { DIFF_MAGIC };
    const u8 ivfc_magic[] = { IVFC_MAGIC };
    const u8 dpfs_magic[] = { DPFS_MAGIC };
    const u8 difi_magic[] = { DIFI_MAGIC };
    
    memset(info, 0x00, sizeof(DisaDiffReaderInfo));
    void* header = (void*) (((u8*) data) + 0x100);
    if (data_size < 0x200) return false;
    
    // DISA/DIFF header: find partition offset & size and DIFI descriptor
    u32 offset_partition = 0;
    u32 size_partition = 0;
    u32 offset_difi = 0;
    if (memcmp(header, disa_magic, 8) == 0) { // DISA file
        DisaHeader* disa = (DisaHeader*) header;
        offset_difi = (disa->active_table) ? disa->offset_table1 : disa->offset_table0;
        if (!partitionB) {
            offset_partition = (u32) disa->offset_partitionA;
            size_partition = (u32) disa->size_partitionA;
            offset_difi += (u32) disa->offset_descA;
        } else {
            if (disa->n_partitions != 2) return false;
            offset_partition = (u32) disa->offset_partitionB;
            size_partition = (u32) disa->size_partitionB;
            offset_difi += (u32) disa->offset_descB;
        }
    } else if (memcmp(header, diff_magic, 8) == 0) { // DIFF file
        if (partitionB) return false;
        DiffHeader* diff = (DiffHeader*) header;
        offset_partition = (u32) diff->offset_partition;
        size_partition = (u32) diff->size_partition;
        offset_difi = (diff->active_table) ? diff->offset_table1 : diff->offset_table0;
    }
    
    // check the output so far
    if (!offset_difi || (offset_difi + sizeof(DifiStruct) > data_size) ||
        (offset_partition + size_partition > data_size))
        return false;
    DifiStruct* difis = (DifiStruct*) (void*) (((u8*) data) + offset_difi);
    if ((memcmp(difis->difi.magic, difi_magic, 8) != 0) ||
        (memcmp(difis->ivfc.magic, ivfc_magic, 8) != 0) ||
        (memcmp(difis->dpfs.magic, dpfs_magic, 8) != 0))
        return false;
    
    // check & get data from DIFI header
    DifiHeader* difi = &(difis->difi);
    if ((difi->offset_ivfc != sizeof(DifiHeader)) ||
        (difi->size_ivfc != sizeof(IvfcDescriptor)) ||
        (difi->offset_dpfs != difi->offset_ivfc + difi->size_ivfc) ||
        (difi->size_dpfs != sizeof(DpfsDescriptor)) ||
        (difi->offset_hash != difi->offset_dpfs + difi->size_dpfs) ||
        (difi->size_hash < 0x20))
        return false;
    info->dpfs_lvl1_selector = difi->dpfs_lvl1_selector;
    info->ivfc_use_extlvl4 = difi->ivfc_use_extlvl4;
    info->offset_ivfc_lvl4 = (u32) (offset_partition + difi->ivfc_offset_extlvl4);
    
    // check & get data from DPFS descriptor
    DpfsDescriptor* dpfs = &(difis->dpfs);
    if ((dpfs->offset_lvl1 + dpfs->size_lvl1 > dpfs->offset_lvl2) ||
        (dpfs->offset_lvl2 + dpfs->size_lvl2 > dpfs->offset_lvl3) ||
        (dpfs->offset_lvl3 + dpfs->size_lvl3 > size_partition) ||
        (2 > dpfs->log_lvl2) || (dpfs->log_lvl2 > dpfs->log_lvl3) ||
        !dpfs->size_lvl1 || !dpfs->size_lvl2 || !dpfs->size_lvl3)
        return false;
    info->offset_dpfs_lvl1 = (u32) (offset_partition + dpfs->offset_lvl1);
    info->offset_dpfs_lvl2 = (u32) (offset_partition + dpfs->offset_lvl2);
    info->offset_dpfs_lvl3 = (u32) (offset_partition + dpfs->offset_lvl3);
    info->size_dpfs_lvl1 = (u32) dpfs->size_lvl1;
    info->size_dpfs_lvl2 = (u32) dpfs->size_lvl2;
    info->size_dpfs_lvl3 = (u32) dpfs->size_lvl3;
    info->log_dpfs_lvl2 = (u32) dpfs->log_lvl2;
    info->log_dpfs_lvl3 = (u32) dpfs->log_lvl3;
        
    // check & get data from IVFC descriptor
    IvfcDescriptor* ivfc = &(difis->ivfc);
    if ((ivfc->size_hash != difi->size_hash) ||
        (ivfc->size_ivfc != sizeof(IvfcDescriptor)) ||
        (ivfc->offset_lvl1 + ivfc->size_lvl1 > ivfc->offset_lvl2) ||
        (ivfc->offset_lvl2 + ivfc->size_lvl2 > ivfc->offset_lvl3) ||
        (ivfc->offset_lvl3 + ivfc->size_lvl3 > dpfs->size_lvl3))
        return false;
    if (!info->ivfc_use_extlvl4) {
        if ((ivfc->offset_lvl3 + ivfc->size_lvl3 > ivfc->offset_lvl4) ||
            (ivfc->offset_lvl4 + ivfc->size_lvl4 > dpfs->size_lvl3))
            return false;
        info->offset_ivfc_lvl4 = (u32) ivfc->offset_lvl4;
    } else if (info->offset_ivfc_lvl4 + ivfc->size_lvl4 > offset_partition + size_partition) {
        return false;
    }
    info->size_ivfc_lvl4 = (u32) ivfc->size_lvl4;
    
    return true;
}

int main(int argc, char** argv) {
    u8* buffer_in = (u8*) malloc(BUFFER_SIZE);
    u8* buffer_out = (u8*) malloc(BUFFER_SIZE>>1);
    u8* cache_lvl2 = (u8*) malloc(BUFFER_SIZE>>3);
    char* path_in = argv[1];
    char* path_out = argv[2];
    FILE* fp;
    
    printf("%s v0.0.2\n\n", *argv);
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
        
    printf("Read DISA/DIFF container... ");
    DisaDiffReaderInfo info;
    if (!getDisaDiffReaderInfo(&info, buffer_in, fsize, false)) return 1;
    printf("OK\n");
    
    printf("DPFS lvl1: 0x%08X byte @ 0x%08X / presel: %u\n", info.size_dpfs_lvl1, info.offset_dpfs_lvl1, (u32) info.dpfs_lvl1_selector);
    printf("DPFS lvl2: 0x%08X byte @ 0x%08X / blocks: %u\n", info.size_dpfs_lvl2, info.offset_dpfs_lvl2, 1 << info.log_dpfs_lvl2);
    printf("DPFS lvl3: 0x%08X byte @ 0x%08X / blocks: %u\n", info.size_dpfs_lvl3, info.offset_dpfs_lvl3, 1 << info.log_dpfs_lvl3);
    printf("IVFC lvl4: 0x%08X byte @ 0x%08X / %sternal\n", info.size_ivfc_lvl4, info.offset_ivfc_lvl4, (info.ivfc_use_extlvl4) ? "ex" : "in");
    
    printf("Build DPFS lvl2 cache... ");
    if (!buildDpfsLvl2Cache(&info, buffer_in, cache_lvl2, BUFFER_SIZE>>3)) return 1;
    printf("OK\n");
    
    printf("Read IVFC lvl4... ");
    if (!readIvfcLvl4(buffer_out, buffer_in, &info, 0, info.size_ivfc_lvl4)) return 1;
    printf("%u kiB\n", info.size_ivfc_lvl4 / 1024);
        
    printf("Writing %s... ", path_out);
    fp = fopen(path_out, "wb");
    if (!fp) return 1;
    fsize = fwrite(buffer_out, 1, info.size_ivfc_lvl4, fp);
    fclose(fp);
    printf("%u kiB\n", fsize / 1024);
    
    if (argc > 3) {
        char* path_cmp = argv[3];
        printf("Comparing %s... ", path_cmp);
        fp = fopen(path_cmp, "rb");
        if (!fp) return 1;
        if (fread(buffer_in, 1, info.size_ivfc_lvl4, fp) != fsize) return 1;
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

