/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include <infiltratr/filesystem_module_v2.h>
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define SIZE (268435456u)
static uint8_t *image;
struct context{int fd,fail;uint32_t sector,allocs;uint64_t bytes;};
static int rd(void *p,uint64_t off,void *out,uint32_t n){
 struct context *c=p;assert(n&&n<=4096u&&!(off%c->sector)&&!(n%c->sector)&&off<=c->bytes&&n<=c->bytes-off);
 if(c->fail)return -1;
 if(c->fd>=0)return pread(c->fd,out,n,(off_t)off)==(ssize_t)n?0:-1;
 memcpy(out,image+off,n);return 0;
}
static void *allocate(void *p,size_t n){struct context*c=p;void *m=malloc(n);if(m)c->allocs++;return m;}
static void release(void *p,void *m){struct context*c=p;assert(m&&c->allocs);c->allocs--;free(m);}
static inline void put16(uint8_t*p,uint32_t n){p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);}
static inline void put32(uint8_t*p,uint32_t n){put16(p,n);put16(p+2,n>>16);}
static inline void put64(uint8_t*p,uint64_t n){put32(p,(uint32_t)n);put32(p+4,(uint32_t)(n>>32));}
static inline uint32_t crc32(uint32_t c,const uint8_t*p,uint32_t n){
 while(n--){c^=*p++;for(unsigned i=0;i<8u;i++)c=(c>>1)^((0u-(c&1u))&0xedb88320u);}return c;
}


static uint32_t crc32c(uint32_t c,const uint8_t*p,uint32_t n){
 while(n--){c^=*p++;for(unsigned i=0;i<8u;i++)c=(c>>1)^((0u-(c&1u))&0x82f63b78u);}return c;
}
static void fixture(void){
 static const uint8_t magic[16]={0xc6,0x85,0x73,0xf6,0x66,0xce,0x90,0xa9,0xd9,0x6a,0x60,0xcf,0x80,0x3d,0xf7,0xef};
 uint8_t *layout=image+3584;memcpy(layout,magic,16);layout[17]=7;layout[18]=2;
 put64(layout+24,8);put64(layout+32,256);
 uint8_t *p=image+4096;put16(p+16,1037);put16(p+18,1024);memcpy(p+24,magic,16);
 p[40]=1;p[56]=2;put64(p+104,8);put64(p+112,1);put16(p+120,8);p[123]=1;
 put32(p+124,8);put64(p+144,4);memcpy(p+240,layout,512);
 put32(p+752,8);put32(p+756,1);p[760]=9;put64(p+776,SIZE/512/256);put16(p+784,1);put16(p+786,256);
 put32(p,crc32c(0xffffffffu,p+16,800)^0xffffffffu);
 uint8_t *q=image+256u*512u;memcpy(q,p,816);put64(q+104,256);put64(q+112,2);
 put32(q,crc32c(0xffffffffu,q+16,800)^0xffffffffu);
}
static void corrupt(void){image[4096+756]^=1;image[256u*512u+756]^=1;}
static void absent(void){image[3584]=0;}
static void expect(const IfsFsCoreOpsV2 *core,IfsFsHostRuntimeV2*h,struct context*c,int want){
 uint32_t v=99;int rc=core->probe(h,&v);
 if(rc!=want)fprintf(stderr,"expected %d got %d at sector %u\n",want,rc,c->sector);
 assert(rc==want&&(!rc?v!=0:v==0)&&!c->allocs);
}
int main(int argc,char **argv){
 assert(argc==2||argc==3);void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);assert(lib);
 IfsFsModuleApiEntryV2 get=(IfsFsModuleApiEntryV2)dlsym(lib,IFS_FS_COMMON_EXPORT_V2);assert(get);
 const IfsFsModuleApiV2*a=get();assert(ifs_fs_api_v2_valid(a,"bcachefs"));
 const IfsFsCoreOpsV2*core=(const void*)ifs_fs_group_v2(a,IFS_FS_GROUP_CORE);
 assert(core&&core->header.capabilities==IFS_FS_CORE_PROBE&&!core->mount&&!core->write&&!ifs_fs_group_v2(a,IFS_FS_GROUP_DEFRAG));
 struct context c={.fd=-1,.bytes=SIZE};
 if(argc==3){struct stat st;c.fd=open(argv[2],O_RDONLY);assert(c.fd>=0&&!fstat(c.fd,&st)&&st.st_size>0);c.bytes=(uint64_t)st.st_size;}
 else {image=calloc(1,SIZE);assert(image);}
 IfsFsHostRuntimeV2 h={.abi_version=2,.structure_bytes=sizeof(h),.capabilities=IFS_FS_HOST_READ_ONLY,.volume_bytes=c.bytes,.maximum_transfer_bytes=4096,.context=&c,.read_at=rd,.allocate=allocate,.release=release};
 for(c.sector=512;c.sector<=4096;c.sector*=8){
  h.logical_sector_bytes=h.physical_sector_bytes=c.sector;
  if(argc==3){expect(core,&h,&c,IFS_FS_OK);continue;}
  memset(image,0,SIZE);fixture();expect(core,&h,&c,IFS_FS_OK);
  c.fail=1;expect(core,&h,&c,IFS_FS_IO_ERROR);c.fail=0;
  corrupt();expect(core,&h,&c,IFS_FS_CORRUPT);
  memset(image,0,SIZE);fixture();absent();expect(core,&h,&c,IFS_FS_NOT_FOUND);
 }
 if(c.fd>=0)assert(!close(c.fd));
 free(image);assert(!dlclose(lib));
 puts("Bcachefs native recognition, bounded reads and corruption refusal PASS");return 0;
}
