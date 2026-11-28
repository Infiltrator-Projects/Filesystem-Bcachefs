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
/* Journal bucket lists are relative to the selected member, not the
 * backing image's apparent capacity. Decode both published encodings
 * and reject overlap, overflow and reserved-bucket references. */
static int journal_buckets(const uint8_t *p,uint64_t n,unsigned type,
                           uint64_t first,uint64_t buckets)
{
    unsigned stride=type==0u?8u:16u;
    if(n<8u||(n-8u)%stride)return IFS_FS_CORRUPT;
    /* Bound quadratic overlap checking on unusually large journals.
     * This is an explicit unsupported recognition profile, not a pass. */
    if((n-8u)/stride>65536u)return IFS_FS_UNSUPPORTED;
    for(uint64_t at=8;at<n;at+=stride){
        uint64_t a=le64(p+at),count=type==0u?1u:le64(p+at+8);
        if(a<first||a>=buckets||!count||count>buckets-a)return IFS_FS_CORRUPT;
        for(uint64_t prior=8;prior<at;prior+=stride){
            uint64_t b=le64(p+prior),len=type==0u?1u:le64(p+prior+8);
            if(a<b+len&&b<a+count)return IFS_FS_CORRUPT;
        }
    }
    return 0;
}

/* Native little-endian bkey positions: the on-disk packed integer
 * starts at its most significant bit, walking towards the three-byte
 * record prefix. Field bases and widths must fit the unpacked types. */
typedef struct {uint64_t inode,offset,snapshot;} Position;
static Position position(const uint8_t*p){
    Position k={le64(p+12),le64(p+4),le32(p)};return k;
}
static int compare(Position a,Position b){
    if(a.inode!=b.inode)return a.inode<b.inode?-1:1;
    if(a.offset!=b.offset)return a.offset<b.offset?-1:1;
    if(a.snapshot!=b.snapshot)return a.snapshot<b.snapshot?-1:1;
    return 0;
}
static int format_valid(const uint8_t*f){
    static const unsigned width[6]={64,64,32,32,32,64};
    unsigned bits=24;
    if(f[1]!=6u)return IFS_FS_CORRUPT;
    for(unsigned j=0;j<6;j++){
        unsigned n=f[2+j];uint64_t base=le64(f+8+8u*j);
        uint64_t max=width[j]==64?UINT64_MAX:UINT32_MAX;
        if(n>width[j]||base>max)return IFS_FS_CORRUPT;
        uint64_t mask=n==64?UINT64_MAX:n?(UINT64_C(1)<<n)-1u:0u;
        if(mask>max-base)return IFS_FS_CORRUPT;
        bits+=n;
    }
    return f[0]==(bits+63u)/64u?0:IFS_FS_CORRUPT;
}
static int key_position(const uint8_t*f,const uint8_t*k,unsigned words,Position*out){
    unsigned fmt=k[1]&127u;
    if(fmt==1u){
        if(words<5u)return IFS_FS_CORRUPT;
        *out=position(k+20);return 0;
    }
    if(fmt)return IFS_FS_UNSUPPORTED;
    if(words<f[0])return IFS_FS_CORRUPT;
    unsigned bit=f[0]*64u;
    uint64_t fields[6];
    for(unsigned j=0;j<6;j++){
        uint64_t n=0;
        for(unsigned i=0;i<f[2+j];i++){
            if(bit<=24u)return IFS_FS_CORRUPT;
            bit--;n=(n<<1)|((k[bit/8u]>>(bit%8u))&1u);
        }
        fields[j]=le64(f+8+j*8u)+n;
    }
    out->inode=fields[0];out->offset=fields[1];out->snapshot=fields[2];return 0;
}
static int key_set(const uint8_t*f,const uint8_t*p,uint32_t bytes,Position lo,Position hi){
    Position prev=lo;unsigned seen=0;
    for(unsigned at=0;at<bytes;){
        unsigned words=p[at],n=words*8u;
        if(!words||n>bytes-at)return IFS_FS_CORRUPT;
        Position k;int rc=key_position(f,p+at,words,&k);if(rc)return rc;
        if(compare(k,lo)<0||compare(k,hi)>0||(seen&&compare(k,prev)<=0))return IFS_FS_CORRUPT;
        prev=k;seen=1;at+=n;
    }
    return 0;
}
/* Check the actual root-node records reachable from a clean-section
 * pointer. This is structural verification, not a recovered tree:
 * overlapping updates across bsets, blacklists and bucket generation
 * ownership still require separate validation before a mount. */
static int root_node(const IfsFsHostRuntimeV2*h,const uint8_t*uuid,
                     uint64_t sector,unsigned tree,unsigned level,
                     uint32_t node_sectors,uint32_t block_sectors,
                     uint32_t written,uint64_t seq,uint64_t committed){
    if(!node_sectors||node_sectors>2048u||node_sectors%block_sectors||
       sector%block_sectors||written>node_sectors||
       (written&&written%block_sectors))return IFS_FS_UNSUPPORTED;
    uint32_t bytes=(written?written:node_sectors)*512u;
    uint8_t*p=h->allocate(h->context,bytes);if(!p)return IFS_FS_NO_MEMORY;
    int rc=read_bytes(h,sector*512u,p,bytes);if(rc)goto done;
    if(bytes<160u||le64(p+16)!=(le64(uuid)^UINT64_C(0x90135c78b99e07f5))||
       !le64(p+136)||(seq&&le64(p+136)!=seq)){rc=IFS_FS_CORRUPT;goto done;}
    uint64_t flags=le64(p+24);
    unsigned id=(unsigned)((flags&15u)|(((flags>>9)&65535u)<<4));
    if(id!=tree||((flags>>4)&15u)!=level){rc=IFS_FS_CORRUPT;goto done;}
    Position lo=position(p+32),hi=position(p+52);
    if(compare(lo,hi)>0){rc=IFS_FS_CORRUPT;goto done;}
    rc=format_valid(p+80);if(rc)goto done;
    uint32_t at=0,align=block_sectors*512u;
    uint64_t setseq=le64(p+136);
    while(at<bytes){
        unsigned head=at?16u:136u;
        if(bytes-at<head+24u){rc=IFS_FS_CORRUPT;goto done;}
        const uint8_t*b=p+at,*s=b+head;
        if(le64(s)!=setseq){
            if(!written&&at)break;
            rc=IFS_FS_CORRUPT;goto done;
        }
        uint32_t fl=le32(s+16),n=le16(s+22)*8u;
        unsigned type=fl&15u,ver=le16(s+20);
        if((fl&48u)||!(type==1u||type==2u||type==5u||type==6u)||
           ver<9u||ver>1037u){rc=IFS_FS_UNSUPPORTED;goto done;}
        if((fl>>16)!=at/512u||le64(s+8)>committed||n>bytes-at-head-24u){
            rc=IFS_FS_CORRUPT;goto done;
        }
        uint32_t len=head+24u+n;
        if(le64(b+8)||checksum(type,b+16,len-16u)!=le64(b)){rc=IFS_FS_CORRUPT;goto done;}
        rc=key_set(p+80,s+24,n,lo,hi);if(rc)goto done;
        uint32_t step=(len+align-1u)/align*align;
        if(step>bytes-at){rc=IFS_FS_CORRUPT;goto done;}
        at+=step;
    }
    rc=0;
done:
    h->release(h->context,p);return rc;
}

/* The clean section consists of journal-entry headers with lengths
 * measured in payload words (unlike the superblock field length,
 * which includes its own header). Root keys must be exactly one
 * current, unpacked pointer key. Bounds do not establish committed
 * root visibility: journal recovery and node checksum validation
 * remain mandatory before mounting or returning any file data. */
static int clean_records(const IfsFsHostRuntimeV2*h,const uint8_t*uuid,const uint8_t*p,uint64_t n,int big_endian,
                         uint64_t first,uint64_t buckets,uint32_t bucket_size,uint32_t block_size,uint32_t node_sectors)
{
    if(n<24u)return IFS_FS_CORRUPT;
    if(big_endian)return IFS_FS_UNSUPPORTED;
    uint64_t roots=0;
    for(uint64_t at=24;at<n;){
        if(n-at<8u)return IFS_FS_CORRUPT;
        const uint8_t *e=p+at;
        unsigned words=le16(e),type=e[4],id=e[2],level=e[3];
        uint64_t bytes=(uint64_t)words*8u+8u;
        if(bytes>n-at)return IFS_FS_CORRUPT;
        if(type>12u)return IFS_FS_UNSUPPORTED;
        if(type==1u){
            if(id>=21u||level>=16u)return IFS_FS_UNSUPPORTED;
            if((roots&(UINT64_C(1)<<id))||words<6u||words>255u||e[8]!=words||
               (e[9]&127u)!=1u)return IFS_FS_CORRUPT;
            roots|=UINT64_C(1)<<id;
            unsigned keytype=e[10],ptr_at;
            if(keytype==5u)ptr_at=5u;
            else if(keytype==18u)ptr_at=10u;
            else return IFS_FS_UNSUPPORTED;
            if(words<=ptr_at)return IFS_FS_CORRUPT;
            if(words!=ptr_at+1u)return IFS_FS_UNSUPPORTED;
            const uint8_t *k=e+8;
            uint64_t ptr=le64(k+ptr_at*8u);
            /* Extent pointers use the low set bit as the type tag.
             * The single device is index zero; reject cached/unwritten
             * metadata and pointers outside its declared bucket space. */
            if((ptr&15u)!=1u||((ptr>>48)&255u)!=0u)return IFS_FS_CORRUPT;
            uint64_t sector=(ptr>>4)&UINT64_C(0xfffffffffff);
            if(sector/bucket_size<first||sector/bucket_size>=buckets)return IFS_FS_CORRUPT;
            unsigned written=keytype==18u?le16(k+56):0u;
            if(!node_sectors||node_sectors>bucket_size-sector%bucket_size||written>node_sectors)return IFS_FS_CORRUPT;
            int rc=root_node(h,uuid,sector,id,level,node_sectors,block_size,written,keytype==18u?le64(k+48):0u,le64(p+16));
            if(rc)return rc;
        }else if(type==3u&&words!=1u)return IFS_FS_CORRUPT;
        else if(type==4u&&(words!=2u||le64(e+8)>le64(e+16)))return IFS_FS_CORRUPT;
        at+=bytes;
    }
    return 0;
}
typedef struct {uint8_t uuid[16],user[16],member_uuid[16];uint64_t seq,buckets;uint32_t version,bucket_size,first;} Identity;
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
    uint32_t seen=0;const uint8_t *m=NULL,*journal=NULL,*clean=NULL;uint64_t journal_n=0,clean_n=0;unsigned journal_type=0;
    for(uint64_t at=FIXED;at<bytes;){
        if(bytes-at<8u){rc=IFS_FS_CORRUPT;goto done;}
        uint64_t n=(uint64_t)le32(p+at)*8u;unsigned type=le32(p+at+4);
        if(n<8u||n>bytes-at){rc=IFS_FS_CORRUPT;goto done;}
        if(type>14u){rc=IFS_FS_UNSUPPORTED;goto done;}
        if(seen&(1u<<type)){rc=IFS_FS_CORRUPT;goto done;}seen|=1u<<type;
        if(type==1u){
            if(n<64u||!member(p+at+8,h->volume_bytes/512u,block)){rc=IFS_FS_CORRUPT;goto done;}
            if(m&&!equal(m,p+at+8,28)){rc=IFS_FS_CORRUPT;goto done;}
            m=p+at+8;
        }else if(type==11u){
            unsigned size=n>=16u?le16(p+at+8):0u;
            if(size<56u||size>n-16u||!member(p+at+16,h->volume_bytes/512u,block)){rc=IFS_FS_CORRUPT;goto done;}
            if(m&&!equal(m,p+at+16,28)){rc=IFS_FS_CORRUPT;goto done;}
            m=p+at+16;
        }else if(type==0u||type==9u){
            if(journal){rc=IFS_FS_UNSUPPORTED;goto done;}
            journal=p+at;journal_n=n;journal_type=type;
        }else if(type==6u){clean=p+at;clean_n=n;}
        at+=n;
    }
    if(!m){rc=IFS_FS_CORRUPT;goto done;}
    uint64_t buckets=le64(m+16);uint32_t first=le16(m+24),bucket_size=le16(m+26);
    if(journal){rc=journal_buckets(journal,journal_n,journal_type,first,buckets);if(rc)goto done;}
    uint64_t flags=le64(p+144);
    if((flags&3u)==3u&&!clean){rc=IFS_FS_CORRUPT;goto done;}
    if(clean){rc=clean_records(h,p+40,clean,clean_n,(flags>>62)&1u,first,buckets,bucket_size,block,(uint32_t)((flags>>12)&65535u));if(rc)goto done;}
    for(unsigned i=0;i<16u;i++){id->uuid[i]=p[40+i];id->user[i]=p[56+i];id->member_uuid[i]=m[i];}
    id->buckets=buckets;id->first=first;id->bucket_size=bucket_size;
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
        if(have&&(!equal(best.uuid,now.uuid,16)||!equal(best.user,now.user,16)||!equal(best.member_uuid,now.member_uuid,16)||best.buckets!=now.buckets||best.bucket_size!=now.bucket_size||best.first!=now.first))return IFS_FS_CORRUPT;
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
