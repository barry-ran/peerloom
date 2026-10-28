#define _POSIX_C_SOURCE 200809L
#include "device_sdk.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

typedef struct host {
    uint64_t sdk, connection, revision;
    char config[16384], snapshot[16384], incoming[64];
    unsigned online, messages, saves, shutdown, flood_completions;
    uint64_t completions[128]; uint32_t statuses[128]; unsigned count;
} host;
static host hosts[2];
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static const unsigned char message[] = {0, 255, 1, 2, 3, 0};
static const char *value(const char *json, const char *key) {
    const char *p = strstr(json,key); assert(p); return p + strlen(key);
}
static void callback(uint64_t context, const dp_event *event) {
    assert(context < 2 && event->abi_version == 1 && event->struct_size >= sizeof(dp_event)); host *h = &hosts[context];
    pthread_mutex_lock(&mutex);
    assert(!h->shutdown);
    char json[16385]; assert(event->payload_len < sizeof(json));
    if (event->payload_len) memcpy(json,event->payload,event->payload_len);
    json[event->payload_len] = 0;
    switch (event->kind) {
    case DP_EVENT_STORAGE_REQUEST: {
        if (strstr(json,"\"operation\":\"load\"")) {
            assert(dp_storage_complete(h->sdk,event->request_id,DP_OK,(const uint8_t *)h->snapshot,strlen(h->snapshot)) == DP_OK);
        } else if (strstr(json,"\"operation\":\"save\"")) {
            uint64_t expected = strtoull(value(json,"\"expected_revision\":"),NULL,10);
            assert(expected == h->revision); /* host's atomic CAS under mutex */
            const char *identity = value(json,"\"identity\":");
            const char *end = strchr(identity,'}'); assert(end && *identity == '{');
            size_t length = (size_t)(end-identity+1); assert(length < 4096);
            char object[4096]; memcpy(object,identity,length); object[length] = 0;
            ++h->revision;
            assert(snprintf(h->snapshot,sizeof(h->snapshot),"{\"revision\":%llu,\"identity\":%s}",(unsigned long long)h->revision,object) > 0);
            char reply[80]; snprintf(reply,sizeof(reply),"{\"revision\":%llu}",(unsigned long long)h->revision);
            assert(dp_storage_complete(h->sdk,event->request_id,DP_OK,(const uint8_t *)reply,strlen(reply)) == DP_OK);
            ++h->saves;
        } else assert(!"unexpected store operation");
        break;
    }
    case DP_EVENT_COMPLETE:
        if(event->status==DP_INVALID_ARGUMENT){++h->flood_completions;break;}
        assert(h->count < 128);
        for (unsigned i=0;i<h->count;++i) assert(h->completions[i]!=event->request_id);
        h->completions[h->count]=event->request_id; h->statuses[h->count++]=event->status;
        break;
    case DP_EVENT_ONLINE: ++h->online; break;
    case DP_EVENT_OFFLINE: break;
    case DP_EVENT_INCOMING: {
        const char *id=value(json,"\"session_id\":\"");
        assert(strlen(id)>=36 && id[36]=='"'); memcpy(h->incoming,id,36); h->incoming[36]=0;
        break;
    }
    case DP_EVENT_CONNECTION_READY: h->connection=event->connection; assert(h->connection); break;
    case DP_EVENT_MESSAGE:
        assert(event->payload_len==sizeof(message) && !memcmp(event->payload,message,sizeof(message)));
        ++h->messages; break;
    case DP_EVENT_CONNECTION_CLOSED: break;
    case DP_EVENT_SHUTDOWN: ++h->shutdown; break;
    default: assert(!"unexpected SDK event");
    }
    assert(dp_sdk_release(h->sdk)==DP_BUSY); /* includes final callback reentry */
    pthread_cond_broadcast(&changed); pthread_mutex_unlock(&mutex);
}
static void wait_count(unsigned *value,unsigned minimum) {
    struct timespec until; clock_gettime(CLOCK_REALTIME,&until); until.tv_sec+=45;
    pthread_mutex_lock(&mutex);
    while (*value<minimum) assert(!pthread_cond_timedwait(&changed,&mutex,&until));
    pthread_mutex_unlock(&mutex);
}
static void complete(host *h,uint64_t id) {
    struct timespec until; clock_gettime(CLOCK_REALTIME,&until); until.tv_sec+=45;
    pthread_mutex_lock(&mutex);
    for (;;) {
        for (unsigned i=0;i<h->count;++i) if(h->completions[i]==id) { assert(h->statuses[i]==DP_OK); pthread_mutex_unlock(&mutex); return; }
        assert(!pthread_cond_timedwait(&changed,&mutex,&until));
    }
}
static uint64_t submit(host *h,uint32_t kind,uint64_t connection,const void *data,size_t len) {
    uint64_t id; assert(dp_sdk_submit(h->sdk,kind,connection,data,len,&id)==DP_OK && id); return id;
}
static void *flood(void *unused) {
    (void)unused;
    struct timespec start;clock_gettime(CLOCK_MONOTONIC,&start);
    for (;;) {
        pthread_mutex_lock(&mutex);unsigned received=hosts[0].messages;pthread_mutex_unlock(&mutex);
        if(received) return NULL;
        uint64_t id;uint32_t status=dp_sdk_submit(hosts[0].sdk,DP_OP_RESPOND,0,(const uint8_t *)"{}",2,&id);
        assert(status==DP_OK||status==DP_BUFFER_FULL);
        struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);assert(now.tv_sec-start.tv_sec<45);
    }
}
static void line(FILE *f,char *out,size_t size) {
    assert(fgets(out,(int)size,f)); size_t n=strlen(out); assert(n&&out[n-1]=='\n');out[n-1]=0;
}
int main(void) {
    const char *path=getenv("TEST_C_PAIR_INPUT");assert(path);
    struct stat st;assert(!stat(path,&st) && (st.st_mode&0777)==0600);
    FILE *f=fopen(path,"r");assert(f);
    for(unsigned i=0;i<2;++i){line(f,hosts[i].config,sizeof(hosts[i].config));line(f,hosts[i].snapshot,sizeof(hosts[i].snapshot));hosts[i].revision=1;}
    char target[64];line(f,target,sizeof(target));fclose(f);
    for(unsigned i=0;i<2;++i){host *h=&hosts[i];assert(dp_sdk_create((const uint8_t *)h->config,strlen(h->config),callback,i,&h->sdk)==DP_OK);uint64_t id=submit(h,DP_OP_START,0,"{}",2);complete(h,id);wait_count(&h->online,1);}
    char request[128];snprintf(request,sizeof(request),"{\"target_device_id\":\"%s\"}",target);
    complete(&hosts[0],submit(&hosts[0],DP_OP_CONNECT,0,request,strlen(request)));
    struct timespec until;clock_gettime(CLOCK_REALTIME,&until);until.tv_sec+=45;
    pthread_mutex_lock(&mutex);while(!hosts[1].incoming[0])assert(!pthread_cond_timedwait(&changed,&mutex,&until));
    snprintf(request,sizeof(request),"{\"session_id\":\"%s\",\"accept\":true}",hosts[1].incoming);pthread_mutex_unlock(&mutex);
    pthread_t flood_thread;assert(!pthread_create(&flood_thread,NULL,flood,NULL));
    complete(&hosts[1],submit(&hosts[1],DP_OP_RESPOND,0,request,strlen(request)));
    pthread_mutex_lock(&mutex);while(!hosts[0].connection||!hosts[1].connection)assert(!pthread_cond_timedwait(&changed,&mutex,&until));pthread_mutex_unlock(&mutex);
    uint64_t ignored=0;
    assert(dp_sdk_submit(hosts[1].sdk,DP_OP_SEND,hosts[0].connection,message,sizeof(message),&ignored)==DP_INVALID_HANDLE && !ignored);
    complete(&hosts[0],submit(&hosts[0],DP_OP_SEND,hosts[0].connection,message,sizeof(message)));wait_count(&hosts[1].messages,1);
    complete(&hosts[1],submit(&hosts[1],DP_OP_SEND,hosts[1].connection,message,sizeof(message)));wait_count(&hosts[0].messages,1);
    assert(!pthread_join(flood_thread,NULL));
    pthread_mutex_lock(&mutex);assert(hosts[0].flood_completions);pthread_mutex_unlock(&mutex);
    complete(&hosts[0],submit(&hosts[0],DP_OP_REFRESH,0,NULL,0));wait_count(&hosts[0].saves,1);wait_count(&hosts[0].online,2);
    complete(&hosts[0],submit(&hosts[0],DP_OP_SEND,hosts[0].connection,message,sizeof(message)));wait_count(&hosts[1].messages,2);
    uint64_t close=submit(&hosts[0],DP_OP_CLOSE_CONNECTION,hosts[0].connection,NULL,0);
    assert(dp_sdk_submit(hosts[0].sdk,DP_OP_SEND,hosts[0].connection,message,sizeof(message),&ignored)==DP_CLOSED && !ignored);
    complete(&hosts[0],close);
    for(unsigned i=0;i<2;++i){uint64_t id;assert(dp_sdk_shutdown(hosts[i].sdk,&id)==DP_OK);wait_count(&hosts[i].shutdown,1);uint32_t status=DP_BUSY;for(unsigned n=0;n<10000&&status==DP_BUSY;++n){status=dp_sdk_release(hosts[i].sdk);if(status==DP_BUSY){struct timespec delay={0,1000000};nanosleep(&delay,NULL);}}assert(status==DP_OK);}
    puts("C ABI service: real identity/WSS/approval/WebRTC binary echo, host CAS rotation, reconnect, cross-parent handle rejection, immediate close gate PASS");
    return 0;
}
