/* SPDX-License-Identifier: GPL-3.0-or-later
 * Native bounded recognition using the documented on-disk structures and
 * the pinned Linux v6.12 format reference. No kernel, libc or tool backend.
 * Recognition is not evidence of a safe mounted namespace or mutation.
 */
#include <infiltratr/filesystem_module_v2.h>
static inline uint32_t le16(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8);}
static inline uint32_t le32(const uint8_t *p){return le16(p)|(le16(p+2)<<16);}
static inline uint64_t le64(const uint8_t *p){return le32(p)|((uint64_t)le32(p+4)<<32);}
static inline int equal(const uint8_t *a,const uint8_t *b,uint32_t n){
 for(uint32_t i=0;i<n;i++)if(a[i]!=b[i])return 0;
 return 1;
}
static inline uint32_t crc32(uint32_t c,const uint8_t *p,uint32_t n){
 while(n--){c^=*p++;for(unsigned i=0;i<8u;i++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return c;
}
static int read_bytes(const IfsFsHostRuntimeV2 *h,uint64_t off,void *p,uint32_t n){
 if(off>h->volume_bytes||n>h->volume_bytes-off)return IFS_FS_NOT_FOUND;
 return ifs_fs_host_read_bytes_v2(h,off,p,n);
}


#define FIXED 752u
#define MAX_BYTES (32u*1024u*1024u)
static const uint8_t magic[16]={0xc6,0x85,0x73,0xf6,0x66,0xce,0x90,0xa9,0xd9,0x6a,0x60,0xcf,0x80,0x3d,0xf7,0xef};
static const uint8_t old_magic[16]={0xc6,0x85,0x73,0xf6,0x4e,0x1a,0x45,0xca,0x82,0x65,0xf5,0x7f,0x48,0xba,0x6d,0x81};
static int has_magic(const uint8_t *p){return equal(p,magic,16)||equal(p,old_magic,16);}
static int nonzero(const uint8_t *p,unsigned n){while(n--)if(*p++)return 1;return 0;}
static int layout_valid(const uint8_t *p,uint64_t sectors)
{
    if(!has_magic(p))return IFS_FS_NOT_FOUND;
    if(p[16]!=0u)return IFS_FS_UNSUPPORTED;
    if(p[17]>16u||p[17]<1u||!p[18]||p[18]>61u)return IFS_FS_CORRUPT;
    uint64_t reserve=UINT64_C(1)<<p[17],end=8;
    for(unsigned i=0;i<p[18];i++){
        uint64_t off=le64(p+24+8u*i);
        if(off<end||off>=sectors||reserve>sectors-off)return IFS_FS_CORRUPT;
        end=off+reserve;
    }
    return IFS_FS_OK;
}
/* CRC algorithms are the native BCH_CSUM crc32c[_nonzero] and
 * crc64[_nonzero] definitions; seed and final XOR depend on the type.
 * A MAC, xxhash or checksum-free superblock is not accepted by this reader. */
static uint64_t checksum(unsigned type,const uint8_t *p,uint32_t n)
{
    if(type==1u||type==5u){
        uint32_t c=type==1u?UINT32_MAX:0u;
        while(n--){c^=*p++;for(unsigned j=0;j<8;j++)c=(c>>1)^((0u-(c&1u))&0x82f63b78u);}
        return type==1u?c^UINT32_MAX:c;
    }
    uint64_t c=type==2u?UINT64_MAX:0u;
    while(n--){c^=(uint64_t)*p++<<56;for(unsigned j=0;j<8;j++)c=(c<<1)^((UINT64_C(0)-(c>>63))&UINT64_C(0x42f0e1eba9ea3693));}
    return type==2u?c^UINT64_MAX:c;
}
static int member(const uint8_t *p,uint64_t sectors,unsigned block)
{
    uint64_t buckets=le64(p+16);uint32_t first=le16(p+24),size=le16(p+26);
    return nonzero(p,16)&&buckets>=64u&&buckets<2147483584u&&first<buckets&&
        size>=block&&!(size&(size-1u))&&buckets<=sectors/size;
}
typedef struct {uint8_t uuid[16],user[16];uint64_t seq;uint32_t version;} Identity;
static int copy(const IfsFsHostRuntimeV2 *h,const uint8_t *layout,uint64_t off,Identity *id)
{
    uint8_t fixed[FIXED];int rc=read_bytes(h,off*512u,fixed,sizeof(fixed));if(rc)return rc;
    if(!has_magic(fixed+24))return IFS_FS_NOT_FOUND;
    uint32_t version=le16(fixed+16),minimum=le16(fixed+18),words=le32(fixed+124),block=le16(fixed+120);
    if(version<9u||version>1037u||minimum>version||minimum<9u)return IFS_FS_UNSUPPORTED;
    if(fixed[122]!=0u||fixed[123]!=1u)return IFS_FS_UNSUPPORTED;
    if(!nonzero(fixed+40,16)||!nonzero(fixed+56,16)||le64(fixed+104)!=off||
       !block||block>128u||(block&(block-1u))||!equal(fixed+240,layout,512))
        return IFS_FS_CORRUPT;
    unsigned ctype=(unsigned)((le64(fixed+144)>>2)&63u);
    if(ctype!=1u&&ctype!=2u&&ctype!=5u&&ctype!=6u)return IFS_FS_UNSUPPORTED;
    uint64_t bytes=FIXED+(uint64_t)words*8u,limit=(UINT64_C(512)<<layout[17]);
    if(!words||bytes>MAX_BYTES||bytes>limit||bytes>h->volume_bytes-off*512u)return IFS_FS_CORRUPT;
    uint8_t *p=h->allocate(h->context,(size_t)bytes);if(!p)return IFS_FS_NO_MEMORY;
    rc=read_bytes(h,off*512u,p,(uint32_t)bytes);
    if(rc)goto done;
    if(!equal(fixed,p,FIXED)||le64(p+8)||checksum(ctype,p+16,(uint32_t)bytes-16u)!=le64(p)){rc=IFS_FS_CORRUPT;goto done;}
    uint32_t seen=0;int members=0;
    for(uint64_t at=FIXED;at<bytes;){
        if(bytes-at<8u){rc=IFS_FS_CORRUPT;goto done;}
        uint64_t n=(uint64_t)le32(p+at)*8u;unsigned type=le32(p+at+4);
        if(n<8u||n>bytes-at){rc=IFS_FS_CORRUPT;goto done;}
        if(type>14u){rc=IFS_FS_UNSUPPORTED;goto done;}
        if(seen&(1u<<type)){rc=IFS_FS_CORRUPT;goto done;}seen|=1u<<type;
        if(type==1u){
            if(n<64u||!member(p+at+8,h->volume_bytes/512u,block)){rc=IFS_FS_CORRUPT;goto done;}
            members=1;
        }else if(type==11u){
            unsigned size=n>=16u?le16(p+at+8):0u;
            if(size<56u||size>n-16u||!member(p+at+16,h->volume_bytes/512u,block)){rc=IFS_FS_CORRUPT;goto done;}
            members=1;
        }
        at+=n;
    }
    if(!members){rc=IFS_FS_CORRUPT;goto done;}
    for(unsigned i=0;i<16u;i++){id->uuid[i]=p[40+i];id->user[i]=p[56+i];}
    id->seq=le64(p+112);id->version=version;rc=IFS_FS_OK;
done:
    h->release(h->context,p);return rc;
}
static int identify(const IfsFsHostRuntimeV2 *h,uint32_t *variant)
{
    uint8_t layout[512];int rc=read_bytes(h,3584,layout,512);if(rc)return rc;
    rc=layout_valid(layout,h->volume_bytes/512u);if(rc)return rc;
    Identity best;int have=0,fail=IFS_FS_CORRUPT;
    for(unsigned i=0;i<layout[18];i++){
        Identity now;rc=copy(h,layout,le64(layout+24+i*8u),&now);
        if(rc){if(rc==IFS_FS_IO_ERROR||rc==IFS_FS_NO_MEMORY||rc==IFS_FS_UNSUPPORTED)fail=rc;continue;}
        if(have&&(!equal(best.uuid,now.uuid,16)||!equal(best.user,now.user,16)))return IFS_FS_CORRUPT;
        if(!have||now.seq>best.seq){best=now;have=1;}
    }
    if(!have)return fail;
    /* A coherent checksum-valid member superblock is recognition only.
     * B-tree roots, snapshots, journal replay and generation validation
     * are prerequisites to mount; they are not advertised here. */
    *variant=best.version;return IFS_FS_OK;
}
static int probe(const IfsFsHostRuntimeV2 *h,uint32_t *variant){
 if(!variant||!ifs_fs_host_v2_valid(h))return IFS_FS_INVALID;
 *variant=0;
 if(h->volume_bytes%h->logical_sector_bytes)return IFS_FS_INVALID;
 return identify(h,variant);
}
static const IfsFsCoreOpsV2 core={
 .header={IFS_FS_GROUP_ABI_V2,sizeof(IfsFsCoreOpsV2),IFS_FS_GROUP_CORE,0,IFS_FS_CORE_PROBE},.probe=probe
};
static const IfsFsGroupHeaderV2 *query(uint32_t id,uint32_t min,uint32_t max){
 return id==IFS_FS_GROUP_CORE&&min<=2u&&max>=2u?&core.header:NULL;
}
static const IfsFsModuleApiV2 api={
 .abi_version=2,.structure_bytes=sizeof(IfsFsModuleApiV2),.format_id="bcachefs",
#ifdef IFS_FREESTANDING
 .runtime_profiles=IFS_FS_PROFILE_FREESTANDING,
#else
 .runtime_profiles=IFS_FS_PROFILE_HOSTED,
#endif
 .group_mask=IFS_FS_GROUP_BIT(IFS_FS_GROUP_CORE),.query_group=query
};
__attribute__((visibility("default"))) const IfsFsModuleApiV2 *infiltrator_filesystem_api_v2(void){return &api;}
