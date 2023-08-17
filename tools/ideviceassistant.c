#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _MSC_VER
#include <config_msvc.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <time.h>

#ifdef WIN32
#include <windows.h>
#endif


#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/notification_proxy.h>

#define MAC_EPOCH 978307200
#define PURPLEBUDDY_DOM "com.apple.purplebuddy"
#define INTERNATIONAL_DOM "com.apple.international"
#define DEV_RESTART_OPER_TIMEO 15
#define NP_SERVICE_NAME "com.apple.mobile.notification_proxy"

/*
 assistant is in game only with iOS 13 version. Tool bypasses other versions with exit code '0'
 */
#define SETUP_SUPPORTED_PRODUCT_VERSION 13

#define DEFAULT_NP_TO_LIMIT 4
#define POST_OPERATION_SLEEP_VAL 5

#define log(MSG) _log(MSG, __func__, __LINE__, NOTICE)

#define log_with_params(FMT, ...) _log_with_params(__func__, __LINE__, NOTICE, FMT, __VA_ARGS__)

#define debug_log(MSG)\
if (enable_debug_logging) {\
    _log(MSG, __func__, __LINE__, NOTICE);\
}

#define debug_log_with_params(FMT, ...)\
if (enable_debug_logging) {\
    _log_with_params(__func__, __LINE__, NOTICE, FMT, __VA_ARGS__);\
}

/* Main objects */
char *udid = NULL;
idevice_t device = NULL;
static lockdownd_client_t client = NULL;
lockdownd_service_descriptor_t service = NULL;
static np_client_t gnp = NULL;

/* ========================= Resources used for awaiting device after erase operation occured =========================*/
#define TIMER_DEFAULT_TO (int)(2.5 * 60)

#define REST_TO_LIVE_TIME 30

#define NP_SPRINGBOARD_PLUGGEDIN "com.apple.springboard.pluggedin"

#define PURPLEBUDDY_INFO_DOMAIN "com.apple.PurpleBuddy"

static bool exit_v2;

static const char *usbmuxd_event_user_data = NP_SPRINGBOARD_PLUGGEDIN;

static bool usbmuxd_event_occured;

static bool usbmuxd_subscription_removed;

static const char *info_domain_keys[] = {
    "GuessedCountry",
    "HSA2UpgradeMiniBuddy3Ran",
    "PaymentMiniBuddy4Ran",
    "chronicle",
    "lastPrepareLaunchSentinel",
    "setupMigratorVersion",
    NULL
};

enum {
    ASSISTANT_INVALID_ARG = -0x28,
    ASSISTANT_RESTART_FAILURE = -0x29
} assistant_error_t;

typedef struct domain {
    char key[64];
    char value[64];
    plist_type value_type;
} dom_t;

/* Known com.apple.purplebuddy domain keys */

static dom_t purplebuddy_domain_values[64] = {
    {"Language", "en-US", PLIST_STRING},
    {"Locale", "en_US", PLIST_STRING},
    {"SetupDone", "1", PLIST_BOOLEAN},
    {"SetupFinishedAllSteps", "1", PLIST_BOOLEAN},
    {"ForceNoBuddy", "1", PLIST_BOOLEAN},
    {"AppleIDPB10Presented", "1", PLIST_STRING},
    {"AssistantPHSOffered", "1", PLIST_STRING},
    {"AssistantPresented", "0", PLIST_BOOLEAN},
    {"AutoUpdatePresented", "0", PLIST_BOOLEAN},
    {"MagnifyPresented", "1", PLIST_STRING},
    {"Mesa2Presented", "1", PLIST_STRING},
    {"PBAppActivity2Presented", "1", PLIST_STRING},
    {"PBDiagnostics4Presented", "1", PLIST_STRING},
    {"Passcode4Presented", "1", PLIST_STRING},
    {"PhoneNumberPermissionPresentedKey", "0", PLIST_STRING}, /*1 previously*/
    {"PrivacyContentVersion", "2", PLIST_UINT},
    {"PrivacyPresented", "1", PLIST_STRING},
    {"RestoreChoice", "1", PLIST_STRING},
    {"ScreenTimePresented", "0", PLIST_STRING}, /*1 previously*/
    {"SetupLastExit", "1552029682", PLIST_DATE},
    {"SetupState", "SetupUsingAssistant", PLIST_STRING},
    {"SetupVersion", "11", PLIST_UINT},
    {"UserChoseLanguage", "0", PLIST_STRING}, /*1 previously*/
    {"WebDatabaseDirectory", "/var/mobile/Library/Caches", PLIST_STRING},
    {"WebKitLocalStorageDatabasePathPreferenceKey", "/var/mobile/Library/Caches", PLIST_STRING},
    {"WebKitMinimumZoomFontSizePreferenceKey", "15", PLIST_UINT},
    {"WebKitOfflineWebApplicationCacheEnabled", "1", PLIST_STRING},
    {"WebKitShrinksStandaloneImagesToFit", "1", PLIST_STRING},
    {"ApplicationSwitcherOnBoardingPresented", "1", PLIST_STRING},
    {"ControlCenterOnBoardingPresented", "1", PLIST_STRING},
    {"GoHomeOnBoardingPresented", "1", PLIST_STRING},
    {"SiriOnBoardingPresented",  "1", PLIST_STRING},
    {"TrueTonePresented", "1", PLIST_STRING},
    {"TimeZone", "Europe/Minsk", PLIST_STRING},
    {"", "", PLIST_NONE}/*signals end of array*/
};

/* Known com.apple.international domain keys */

static dom_t international_domain_values[32] = {
    {"Language", "en", PLIST_STRING},
    {"Locale", "en_US", PLIST_STRING},
    {"", "", PLIST_NONE}
};

pthread_mutex_t boot_mutex;
pthread_cond_t boot_condition;
char *event_to_wait = NULL;
int enable_debug_logging = 0;
static bool wait_for_boot;

/* Timer sources */
typedef struct timer_context_type {
    void(*cb)(void *);
    void *cb_ctx;
    int to;
    bool fire;
    pthread_mutex_t *mx;
} timer_ctx_t;

typedef enum log_type {
    ERROR = 0,
    NOTICE = 1
} log_type_t;

int make_log_prefix(char *prefix, log_type_t lg_type, const char *f, int ln) {
    return prefix ? sprintf(prefix, "%s:%d%s ", f, ln, (lg_type == ERROR) ? " ERROR:" : ":") : -1;
}

void _log(const char msg[], const char *f, int ln, log_type_t type) {
    if (!msg)
        return;
    char log_str[196] = {0};
    int written = 0;
    char *prefix = log_str;
    written = make_log_prefix(prefix, type, f, ln);
    written = sprintf((log_str + written), "%s\n", msg);
    fprintf(stdout, "%s\n", log_str);
}

void _log_with_params(const char *f, int ln, log_type_t type, const char fmt[], ...) {
    if (!fmt)
        return;
    char log_str[4048] = {0};
    int written = 0;
    char *prefix = log_str;
    written = make_log_prefix(prefix, type, f, ln);
    va_list va;
    va_start(va, fmt);
    written = vsprintf((log_str + written), fmt, va);
    va_end(va);
    fprintf(stdout, "%s\n", log_str);
}

//Declarations
void timer_fired_cb(void *ctx);
timer_ctx_t *timer_new_timer(void(*callback)(void *), void *ctx);

void timer_fired_cb(void *ctx) {
    debug_log("Timer callback did invocked");
    bool *ctx_unwrapped = ctx;
    debug_log_with_params("Ctx before: %d", *ctx_unwrapped);
    *ctx_unwrapped = true;
    debug_log_with_params("Ctx after: %d", *ctx_unwrapped);
}

static void *timer_loop(void *ctx) {
    if (!ctx) {
        debug_log("Invalid argument provided");
        return NULL;
    }
    timer_ctx_t *attr = ctx;
    
    time_t start = time(NULL);
    int i = 0;
    pthread_mutex_lock(attr->mx);
    debug_log("Timer mutex locked");
    while (((time(NULL) - start) < attr->to) && !attr->fire) {
        time_t end = time(NULL);
        debug_log_with_params("(%ld - %ld) > %d. %ld", end, start, attr->to, end - start);
        sleep(1);
        debug_log_with_params("Watching TIK_TOK during %d second(s)", ++i);
    }
    if (attr->fire)
        debug_log_with_params("Force stopping timer on %ld sec ticking", time(NULL) - start);
    attr->cb(attr->cb_ctx);
    pthread_mutex_unlock(attr->mx);
    debug_log("Timer mutex unlocked");
    return NULL;
}

timer_ctx_t *timer_new_timer(void(*callback)(void *), void *ctx) {
    if (!callback || !ctx) {
        debug_log("Invalid argument provided");
        return NULL;
    }
    pthread_mutex_t mx;
    pthread_mutex_t *mx_ptr = NULL;
    if (pthread_mutex_init(&mx, NULL)) {
        debug_log("Failed to initialize mutex");
        return NULL;
    }
    if (!(mx_ptr = malloc(sizeof(pthread_mutex_t)))) {
        debug_log("Failed to allocate pointer on heap space");
        pthread_mutex_destroy(&mx);
        return NULL;
    }
    *mx_ptr = mx;
    timer_ctx_t *t = malloc(sizeof(timer_ctx_t));
    if (!t) {
        pthread_mutex_destroy(&mx);
        debug_log("Failed to allocate time structer on heap space");
        return NULL;
    }
    memset(t, 0, sizeof(timer_ctx_t));
    t->to = -1;
    t->fire = false;
    t->cb = callback;
    t->cb_ctx = ctx;
    t->mx = mx_ptr;
    return t;
}

void timer_free(timer_ctx_t *t) {
    if (!t) return;
    t->cb = NULL;
    t->cb_ctx = NULL;
    pthread_mutex_destroy(t->mx);
    free(t->mx);
    t->mx = NULL;
    free(t);
}

int timer_start_with_fire_time(timer_ctx_t *t, const int limit) {
    if (!t || limit <= 0) {
        debug_log("Invalid argument provided");
        return -1;
    }
    t->to = limit;
    pthread_t tid;
    int r = pthread_create(&tid, NULL, &timer_loop, t);
    if (r != 0) {
        debug_log("Failed to create time thread!");
        return -1;
    }
    return 0;
}

int timer_stop(timer_ctx_t *t) {
    if (!t) {
        debug_log("Invalid argument provided");
        return -1;
    }
    debug_log("Stopping timer. Invocking callback immediately");
    t->fire = true;
    return 0;
}

static void darwin_notification_event_callback(const char *notification, void *user_data) {
    time_t t = time(NULL);
    if (strlen(notification) == 0) {
        /*Empty string can be received if connection with notification_proxy service is dropped.*/
        debug_log_with_params("Bad notification response. Expected: ('%s'). Received: ('%s') at %s. There's a chance that device has been detached again for unknown reason or the empty string was received simply! Ignore this notification.", NP_SPRINGBOARD_PLUGGEDIN, notification, asctime(localtime(&t)));
    } else {
        debug_log_with_params("\nNOTICE: ('%s') event occured at %s", notification, asctime(localtime(&t)));
        bool *ctx = user_data;
        debug_log_with_params("Ctx before: %d", *ctx);
        *ctx = true;
        debug_log_with_params("Ctx after: %d", *ctx);
    }
}

static np_client_t observe_notification_proxy_client_notification(const char *udid, const char *ntn_name, void(*handler)(const char *, void *)) {
    if (strlen(udid) == 0 || strlen(ntn_name) == 0 || !handler) {
        debug_log("Invalid argument provided. Ignore event");
        return NULL;
    }
    int e = 0;
    lockdownd_client_t lclient = NULL;
    lockdownd_service_descriptor_t service = NULL;
    idevice_t d = NULL;
    if ((e = idevice_new(&d, udid)) != IDEVICE_E_SUCCESS) {
        debug_log_with_params("Failed to create device for %s udid. Error code: %d", udid, e);
        goto RETURN_CLEANUP;
    }
    if ((e = lockdownd_client_new_with_handshake(d, &lclient, "com.mobitru.name.assistant")) != LOCKDOWN_E_SUCCESS) {
        debug_log_with_params("Failed to create lockdownd client for %s udid. Error code: %d", udid, e);
        goto RETURN_CLEANUP;
    }
    if ((e = lockdownd_start_service(lclient, NP_SERVICE_NAME, &service)) != LOCKDOWN_E_SUCCESS) {
        debug_log_with_params("Failed to start %s service for %s udid. Error code: %d", NP_SERVICE_NAME, udid, e);
        goto RETURN_CLEANUP;
    }
    if (service->port <= 0) {
        debug_log_with_params("Invalid port to connect to %s service. Error code: %d", NP_SERVICE_NAME, e);
        goto RETURN_CLEANUP;
    }
    if ((e = np_client_new(d, service, &gnp)) != NP_E_SUCCESS) {
        debug_log_with_params("Failed to create client for %s service. Error code: %d", NP_SERVICE_NAME, e);
        goto RETURN_CLEANUP;
    }
    if ((e = np_set_notify_callback(gnp, darwin_notification_event_callback, &exit_v2)) != NP_E_SUCCESS) {
        debug_log_with_params("Failed to configure client for %s service. Error code: %d", NP_SERVICE_NAME, e);
        goto RETURN_CLEANUP;
    }
    if ((e = np_observe_notification(gnp, ntn_name)) != NP_E_SUCCESS) {
        debug_log_with_params("Failed to start observing %s notification. Error code: %d", ntn_name, e);
    }
RETURN_CLEANUP:
    idevice_free(d);
    d = NULL;
    lockdownd_client_free(lclient);
    lclient = NULL;
    lockdownd_service_descriptor_free(service);
    service = NULL;
    if (e) {
        debug_log_with_params("Releasing %s client due to error code %d", NP_SERVICE_NAME, e);
        np_client_free(gnp);
        gnp = NULL;
    }
    return gnp;
}

static void usbmuxd_event_callback(const idevice_event_t *event, void *user_data) {
    if (usbmuxd_event_occured) {
        debug_log_with_params("Usbmuxd event already occured for %s udid. Ignoring any other incoming events", udid);
        return;
    }
    if (!event || !user_data) {
        debug_log("Invalid argument provided. Ignore event");
        return;
    }
    if (event->conn_type != CONNECTION_USBMUXD) {
        debug_log_with_params("Event's connection type is not USBMUXD one. Conn type value -> %d. Udid -> %s. Ignore event", event->conn_type, event->udid);
        return;
    }
    char *np_name = user_data;
    time_t t = time(NULL);
    switch (event->event) {
        case IDEVICE_DEVICE_ADD:
            if (strncmp(udid, event->udid, strlen(udid)) == 0) {
                debug_log_with_params("AddDeviceEvent for target udid -> %s. Trying to subscribe for %s notification. Cur time -> %s", udid, np_name, asctime(localtime(&t)));
                gnp = observe_notification_proxy_client_notification(udid, np_name, darwin_notification_event_callback);
                if (!gnp) {
                    debug_log("Failed to start observing notification proxy notification");
                }
                usbmuxd_event_occured = true;
            }
            break;
        case IDEVICE_DEVICE_REMOVE:
#warning Experemental feature
            if (strncmp(udid, event->udid, strlen(udid)) == 0)
                debug_log_with_params("ERROR: Got 'RemoveDeviceEvent' for %s udid from usbmuxd. THIS is considered as UNDEFINED behaviour as 'detach' event can't be handled properly by this tool. Node is supposed to start this tool AFTER the 'detach' event has occured. It might be that there's an issue with USB-cable or some other unhandled issue!!! In this case tool is going to wait its default global timer TO -> %d secs and then exit without any error indication.", udid, TIMER_DEFAULT_TO);
            break;
        case IDEVICE_DEVICE_PAIRED:
            debug_log("Got 'IDEVICE_DEVICE_PAIRED' event.");
            break;
        default:
            debug_log("Got 'Unknown' event.");
    }
}

/* ====================================================================================================================================================== */

static void print_usage(void)
{
    printf("Usage: ideviceassistant [OPTIONS]\n");
    printf("Skip setup assistant.\n");
    printf("\n");
    printf("  -d, --debug \t\t enable communication debugging\n");
    printf("  -u, --udid UDID \t target specific device by UDID\n");
    printf("  -r, --restart \t restart idevice\n");
    printf("  -t, --notification--timeout notification timeout value\t \n");
    printf("  -w, --wait-event \t wait idevice on boot(restore || erase).\n\t\t\t It means that setup starts when idevice is appeared on 'Hello screen'(i.e Setup.app && Springboar are launched);\n\t\t\t Event basically is any 'Darwin notification'(optional arg. If it's NULL - device setup starts emediately\n");
    printf("  -W, --wait-for-boot \t wait idevice after 'WaitForOnline' event occured.\n");
    printf("  -h, --help \t\t print usage information\n");
    printf("\n");
}

/**
 * This callback fired when notification_proxy service got desired notification on device and notify this process-observer on the host
 * NOTICE: possible addition -> if empty string 'notification' is received - we should stop waiting and notify with failure condition
 */

static int valid_np_resp_received = 0;
static void notify_f(const char *notification, void *user_data)
{
    if (!notification || strcmp(event_to_wait, notification)) {
        /*Empty string can be received if connection with notification_proxy service is dropped.*/
        log_with_params("Bad notification response. Expected: ('%s'). Received: ('%s')",event_to_wait, notification);
        valid_np_resp_received = 0;
        int sig_res = 0;
        sig_res = pthread_cond_signal(&boot_condition);
        if (sig_res) {
            log_with_params("bad 'pthread_cond_signal' result: %d code.", sig_res);
        }
        return;
    }
    log_with_params("\nNOTICE: ('%s') event occured\n", notification);
    valid_np_resp_received = 1;
    int sig_res = 0;
    sig_res = pthread_cond_signal(&boot_condition);
    if (sig_res) {
        log_with_params("bad 'pthread_cond_signal' result: %d code.", sig_res);
    }
}

static lockdownd_error_t lockdownd_set_value_for_key_in_domain(lockdownd_client_t _client, plist_t value, char *key, const char domain[]) {
    if (!_client || !value || plist_get_node_type(value) == PLIST_NONE || !key || !domain) {
        return LOCKDOWN_E_INVALID_ARG;
    }
    lockdownd_error_t lerr = LOCKDOWN_E_SUCCESS;
    lerr = lockdownd_set_value(_client, domain, key, value);
    return lerr;
}

static signed strtoint(char *str, int *i) {
    if (!str || !i)
        return -1;
    *i = 0;
    char *end = NULL;
    long version = 0; int base = 10;
    version = strtol(str, &end, base);
    if ((end && strlen(end)) || version == LONG_MAX || version == LONG_MIN)
        return -1;
    *i = (int)version;
    return 0;
}

static plist_t string_to_new_plist(char *string, plist_type type) {
    if (!string)
        return NULL;
    if (type == PLIST_UINT || type == PLIST_DATE || type == PLIST_BOOLEAN) {
        int number = 0;
        if (strtoint(string, &number)) {
            debug_log_with_params("Could not convert value from string '%s' to number. Skip key and continue setup...", string);
            return NULL;
        }
        return (type == PLIST_UINT) ?
        plist_new_uint((uint64_t)number) :
        ((type == PLIST_DATE) ?
         plist_new_uint((uint32_t)number - MAC_EPOCH) :
         (type == PLIST_BOOLEAN) ?
         plist_new_bool((uint8_t)number) : NULL);
    } else if (type == PLIST_STRING) {
        return plist_new_string(string);
    }
    return NULL;
}

struct cmd {
    char *cmd;
    int result;
    int finished;
};

void *bash_task(void *arg) {
    struct cmd *command = (struct cmd *)arg;
    if(command == NULL) return NULL;
    
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    
    int res = system(command->cmd);
    debug_log_with_params("%s command result is %d", command->cmd, res);
    command->result = res;
    command->finished = 1;
    return NULL;
}

int shell_spawn(char *cmdname, int timeout) {
    struct cmd command;
    command.cmd = cmdname;
    command.result = -1;
    command.finished = 0;
    
    pthread_t t_id;
    pthread_create(&t_id, NULL, bash_task, &command);
    
    time_t start = time(0);
    time_t end = time(0);
    
    while(!command.finished) {
        sleep(1);
        end = time(0);
        if((end - start) >= timeout) {
            debug_log_with_params("%s command timed out [%d seconds]", cmdname, timeout);
            pthread_cancel(t_id);
            break;
        }
    }
    return command.result;
}

static int get_device_version(lockdownd_client_t _client) {
    if (!_client) {
        log("Invalid arg passed");
        return 0;
    }
    plist_t p_version = NULL;
    int maj_product_version = 0;
    if (lockdownd_get_value(_client, NULL, "ProductVersion", &p_version) == LOCKDOWN_E_SUCCESS) {
        if (!p_version) {
            log("invalid plist reveived");
            return 0;
        }
        char *s_version = NULL;
        plist_get_string_val(p_version, &s_version);
        if (!s_version) {
            log_with_params("(%s) string from plist value", s_version);
            return 0;
        }
        if ((sscanf(s_version, "%d", &maj_product_version) != 1)) {
            log_with_params("invalid scan of string: (%s). scan result: (%d)", s_version, maj_product_version);
            return 0;
        }
        free(s_version);
        s_version = NULL;
    }
    plist_free(p_version);
    p_version = NULL;

    return maj_product_version;
}

/**
 * wait synchronously for condition to be signaled or timeout fired
 * @param mx mutex lock
 * @param cond conditional variable
 * @param mintowait numer time to wait. (specyfied in minutes)
 *
 * @return 0 on success, -1 on invalid args, EINVAL, EPERM, ETIMEDOUT
 */

static int wait_np_event_synchronously(pthread_mutex_t *mx, pthread_cond_t *cond, const unsigned mintowait) {
    if (!mx || !cond || mintowait > DEFAULT_NP_TO_LIMIT) {
        debug_log("invalid arguments passed");
        return -1;
    }
    int boot_np_res = 0;
    pthread_mutex_lock(mx);
    debug_log_with_params("Going to wait notification for (%u) minute(s)", mintowait);
    const long min = 60;
    const long total_secs = min * mintowait;
    struct timespec ts;
    int resval = clock_gettime(CLOCK_REALTIME, &ts);
    if (resval) {
        debug_log_with_params("ERROR: clock_gettime error: %d", resval);
        memset(&ts, 0, sizeof(struct timespec));
        time_t cur_time;
        time(&cur_time);
        ts.tv_sec = cur_time + total_secs;
        ts.tv_nsec = 0;
    } else {
        ts.tv_sec += total_secs;
    }
    boot_np_res = pthread_cond_timedwait(cond, mx, &ts);
    pthread_mutex_unlock(mx);

    return boot_np_res;
}

static int handle_np_response(int resp) {
    int ok = 0;
    if (resp == 0)
        return ok;

    switch (resp) {
        case EINVAL:
            debug_log_with_params("EINVAL(%d): Invalid arguments passed to 'pthread_cond_timedwait'", resp);
            break;
        case EPERM:
            debug_log_with_params("EPERM(%d): The mutex specified is not locked by the caller", resp);
            break;
        case ETIMEDOUT:
            debug_log_with_params("ETIMEDOUT(%d): The wait timed out without being satisfied.", resp);
            break;
        default:
            debug_log_with_params("Unknown(%d) error during 'pthread_cond_timedwait'", resp);
            break;
    }
    ok = -1;

    return ok;
}

static void cleanup() {
    if (client)
        lockdownd_client_free(client);
    if (device)
        idevice_free(device);
    if (gnp)
        np_client_free(gnp);
    if (service)
        lockdownd_service_descriptor_free(service);
    if (udid)
        free(udid);
    if (event_to_wait)
        free(event_to_wait);
    pthread_mutex_destroy(&boot_mutex);
    pthread_cond_destroy(&boot_condition);

    client = NULL;
    device = NULL;
    gnp = NULL;
    service = NULL;
    udid = NULL;
    event_to_wait = NULL;
}

static void on_signal(int sig) {
    log_with_params("got signal %d. Exiting with code (%d)", sig, -1);
    cleanup();
    exit(-1);
}

static void bind_signal() {
    signal(SIGINT, on_signal);
    signal(SIGQUIT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
}

int is_empty_domain(const dom_t d) {
    return (strcmp(d.key, "") && strcmp(d.value, "")) == 0 ? 1 : 0;
}


int main(int argc, char *argv[])
{
    bind_signal();
    int i = 0;
    unsigned notification_to = DEFAULT_NP_TO_LIMIT;
    int restart_device = 0;

    /* parse cli args */
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
//            idevice_set_debug_level(1);
            enable_debug_logging = 1;
            continue;
        }
        else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
            i++;
            if (!argv[i] || !(argv[i]) || !strcmp(argv[i], "")) {
                printf("No udid string provided\n");
                print_usage();
                return -1;
            }
            udid = strdup(argv[i]);
            if (!strncmp(udid, "-", 1)) {
                //TODO Possible memory leak here...
                free(udid);
                udid = NULL;
                printf("Invalid udid string passed\n");
                return -1;
            }
            continue;
        } else if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--notification--timeout")) {
            i++;
            if (!argv[i] || !argv[i]) {
                printf("No notification timeout specified\n");
                print_usage();
                return -1;
            }
            int cli_to = 0;
            if (strtoint(argv[i], &cli_to) ||
                cli_to <= 0 ||
                cli_to > DEFAULT_NP_TO_LIMIT) {
                _log_with_params(__func__, __LINE__, NOTICE, "Invalid notification timeout passed (%s). Using default value (%d)",argv[i],  DEFAULT_NP_TO_LIMIT);
                notification_to = DEFAULT_NP_TO_LIMIT;
            } else {
                notification_to = cli_to;
            }
            continue;
        }
        else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--wait-for-boot-with-event")) {
            i++;
            if (!argv[i] || !(argv[i]) || !strncmp(argv[i], "-", 1) || !strcmp(argv[i], "")) {
                printf("No event is provided\n");
                print_usage();
                return -1;
            }
            event_to_wait = strdup(argv[i]);
            //Could not validate Darwin event. Only for NULL ptr;
            if (!event_to_wait) {
                free(event_to_wait);
                event_to_wait = NULL;
                printf("No valid event is provided\n");
                return -1;
            }
            continue;
        }
        else if (!strcmp(argv[i], "-W") || !strcmp(argv[i], "--wait-for-boot")) {
            wait_for_boot = 1;
            event_to_wait = NP_SPRINGBOARD_PLUGGEDIN;
            continue;
        }
        else if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--restart")) {
            restart_device = 1;
            continue;
        }
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage();
            return 0;
        }
        else {
            print_usage();
            return -1;
        }
    }
    debug_log_with_params("Arguments:\n --udid: %s\n --restart: %d\n --wait-for-boot-with-event: %s\n --notification--timeout: %d",
                          udid,
                          restart_device,
                          event_to_wait,
                          notification_to);
    
    if (!udid) {
        log("No UDID specified!");
        print_usage();
        return -1;
    }
    
    if (wait_for_boot) {
        time_t start = time(NULL);
        log_with_params("Assistant is preparing for waiting for 'Setup' application. Start time: %s", asctime(localtime(&start)));
        debug_log("Starting global timer");
        timer_ctx_t *timer = NULL;
        if ((timer = timer_new_timer(&timer_fired_cb, &exit_v2)) == NULL) {
            log("Failed to create timer");
            return -1;
        }
        if (timer_start_with_fire_time(timer, TIMER_DEFAULT_TO)) {
            log("Failed to start timer");
            return -1;
        }
        debug_log("Subscribing to usbmuxd events");
        int e = IDEVICE_E_SUCCESS;
        /**
        idevice_subscription_context_t ctx = NULL;
        if (idevice_events_subscribe(&ctx, &usbmuxd_event_callback, (void *)usbmuxd_event_user_data) != IDEVICE_E_SUCCESS) {
            log_with_params("Failed to perform subscribtion to usbmuxd events. Device error code: %d", e);
            return -1;
        }*/
        //Fallback to old API (Node supported currently - xx.05.23)
        if ((e = idevice_event_subscribe(&usbmuxd_event_callback, (void *)usbmuxd_event_user_data)) != IDEVICE_E_SUCCESS) {
            log_with_params("Failed to perform subscribtion to usbmuxd events. Device error code: %d", e);
            return -1;
        }
        idevice_t d = NULL;
        lockdownd_client_t lcl = NULL;
        char *plist_xml = NULL;
        uint32_t len = 0;
        debug_log("Entering main loop");
        while (!exit_v2) {
            while (!exit_v2 && !usbmuxd_event_occured)
                sleep(1);
            if (!usbmuxd_subscription_removed) {
                debug_log("Unsibscribing from usbmuxd events");
                if (idevice_event_unsubscribe() != IDEVICE_E_SUCCESS)
                    debug_log("Failed to unsibscribe from usbmuxd events. Continue cleanup anyway...");
                usbmuxd_subscription_removed = true;
            }
            debug_log_with_params("Exit state: %d. UsbmuxdEventOccured state: %d", exit_v2, usbmuxd_event_occured);
            debug_log_with_params("Getting info from %s lockdownd domain", PURPLEBUDDY_INFO_DOMAIN);
            if ((e = idevice_new(&d, udid)) != IDEVICE_E_SUCCESS) {
                d = NULL;
            } else if ((e = lockdownd_client_new_with_handshake(d, &lcl, "com.mobitru.name.assistant")) != LOCKDOWN_E_SUCCESS) {
                idevice_free(d);
                d = NULL;
                lcl = NULL;
            } else {
                plist_t value = NULL;
                if ((e = lockdownd_get_value(lcl, PURPLEBUDDY_INFO_DOMAIN, info_domain_keys[0], &value)) != LOCKDOWN_E_SUCCESS) {
                    debug_log_with_params("Failed to get value for %s domain. Error code: %d", PURPLEBUDDY_INFO_DOMAIN, e);
                } else {
                    plist_to_xml(value, &plist_xml, &len);
                    if (!plist_xml || len == 0) {
                        debug_log("Failed to convert plist to xml format");
                    } else {
                        debug_log_with_params("Got target value for %s domain -> %s", PURPLEBUDDY_INFO_DOMAIN, plist_xml);
                        plist_t leaf = NULL;
                        debug_log_with_params("Checking %s key in dict", info_domain_keys[0]);
                        //Seems various versions of libimobiledevice and libplist libraries provide data in various containers. For ex.: 'GuessedCountry' can be wrapped either in plist dict or array stuctures accordingly. Checking just presence of data by key without any content validation for now.
                        if (plist_dict_get_size(value) > 1/*(leaf = plist_dict_get_item(value, info_domain_keys[0]))&& plist_dict_get_size(leaf) > 0*/) {
                            debug_log_with_params("Got some values from %s domain!", PURPLEBUDDY_INFO_DOMAIN);
                            /*
                            log_with_params("Got value by %s key. Starting 'RestToLive' timer", info_domain_keys[0]);
                            int rtl = REST_TO_LIVE_TIME;
                            while (!exit_v2 && rtl-- > 0) {
                                log_with_params("Waiting for RestToLive time out -> %d", rtl);
                                sleep(1);
                            }
                            if (!exit_v2) {
                                exit_v2 = true;
                                log("RestToLive timer fired earlier thant exit_v2 condition. Setting exit_v2 manually to end up main cicle");
                            } else {
                                log_with_params("Main condition exit_v2 did changed. Stopped RestToLive timer on %d value. Prepare to end up main cicle", rtl);
                            }*/
                            if (!exit_v2) {
                                debug_log("Setting global exit state manually to end up main cicle");
                                exit_v2 = true;
                            }
                        }
                    }
                    if (plist_xml) {
                        free(plist_xml);
                        plist_xml = NULL;
                    }
                    len = 0;
                }
                if (value)
                    plist_free(value);
            }
            sleep(1);
        }
        debug_log("Exit cleanup in progress...\nStopping global timer");
        if (timer_stop(timer) != 0)
            debug_log("Failed to stop global timer. Continue cleanup anyway...");
        debug_log("Trying to lock timer mutex for safe release");
        //This is required for wait for timer thread to exit. Once mutex is unlocked by timer thread - memory release is safe!
        pthread_mutex_lock(timer->mx);
        debug_log("Timer mutex locked - sync point achieved!");
        pthread_mutex_unlock(timer->mx);
        debug_log("Timer mutex unlocked. Safe memory release is garuntied");
        timer_free(timer);
        timer = NULL;
        if (!usbmuxd_subscription_removed) {
            debug_log("Unsibscribing from usbmuxd events");
            if (idevice_event_unsubscribe() != IDEVICE_E_SUCCESS)
                debug_log("Failed to unsibscribe from usbmuxd events. Continue cleanup anyway...");
        }
        if (d) {
            idevice_free(d);
            debug_log("Device released");
            d = NULL;
        }
        if (lcl) {
            lockdownd_client_free(lcl);
            debug_log("Lockdownd client released");
            lcl = NULL;
        }
        if (gnp) {
            debug_log("de-register from notification proxy service");
            np_set_notify_callback(gnp, NULL, NULL);
            np_client_free(gnp);
            debug_log("NotificationProxy client released");
            gnp = NULL;
        }
        time_t end = time(NULL);
        char exectimestr[64] = {'\0'};
        snprintf(exectimestr, sizeof(exectimestr), "%s", asctime(localtime(&end)));
        exectimestr[(strlen(exectimestr) - 1)] = '\0';
        log_with_params("=============== Assistant exits at %s. Exec time: %ld seconds ===============", exectimestr, (end - start));
        return 0;
    }
    
    lockdownd_error_t lerr = LOCKDOWN_E_SUCCESS;
    int initres = pthread_cond_init(&boot_condition, NULL);
    if (initres) {
        printf("%s func, %d line: ERROR: smth went wrong during setup. pthread_cond_init result: %d\n", __func__, __LINE__, initres);
        return -1;
    }
    initres = pthread_mutex_init(&boot_mutex, NULL);
    if (initres) {
        fprintf(stderr, "%s func, %d line: ERROR: smth went wrong during setup. pthread_mutex_init result: %d\n", __func__, __LINE__, initres);
    }
    
    if (!udid) {
        fprintf(stderr, "%s func, %d line: ERROR: No UDID specified\n",__func__, __LINE__);
        print_usage();
        lerr = ASSISTANT_INVALID_ARG;
        goto CLEANUP;
    }

    idevice_error_t deverr = idevice_new(&device, udid);
    if (deverr != IDEVICE_E_SUCCESS) {
        fprintf(stderr, "%s func, %d line: ERROR: No device found with udid %s\n",__func__, __LINE__, udid);
        lerr = (lockdownd_error_t)(int)deverr;
        goto CLEANUP;
    }

    lerr = lockdownd_client_new_with_handshake(device, &client, "idevicenotification");
    if (lerr != LOCKDOWN_E_SUCCESS) {
        fprintf(stderr, "%s func, %d line: ERROR: Could not connect to lockdownd, error code %d\n",__func__, __LINE__, lerr);
        goto CLEANUP;
    }
    
    int product_version = 0;
    product_version = get_device_version(client);

    if (restart_device) fprintf(stdout, "Going to restart device after setup\n");

    /* despite current 'product_version' assistant should wait for notification (NO matter if it fires or timedout occures)
     * NOTICE: attach event occures when device is visible for usb. But iOS is not prepared for further communication.
               So assistant waits for 'DEFAULT_NP_TO_LIMIT' till device prepares and appears on 'Hello screen'
     */
    if (event_to_wait) {
        lerr = lockdownd_start_service(client, NP_SERVICE_NAME, &service);
        if (lerr != LOCKDOWN_E_SUCCESS && (service->port <= 0)) {
            fprintf(stderr, "%s func, %d line: ERROR: Could not start service: %s\n",__func__, __LINE__, NP_SERVICE_NAME);
            goto CLEANUP;
        }
        if (np_client_new(device, service, &gnp) != NP_E_SUCCESS) {
            fprintf(stderr, "%s func, %d line: ERROR: Could not connect to %s!\n",__func__, __LINE__, NP_SERVICE_NAME);
            goto CLEANUP;
        }
        np_set_notify_callback(gnp, notify_f, NULL);
        fprintf(stdout, "NOTICE: going to observe %s notification\n", event_to_wait);
        np_observe_notification(gnp, event_to_wait);
        
        if (client)
            lockdownd_client_free(client);
        client = NULL;
        
        //just wait for notifications
        int boot_np_res = 0;
        boot_np_res = wait_np_event_synchronously(&boot_mutex, &boot_condition, notification_to);

        //Cleanup
        if (gnp)
            np_client_free(gnp);
        if (service)
            lockdownd_service_descriptor_free(service);
        gnp = NULL;
        service = NULL;

        /*if assistant does not support such product_version - it assumes that work is done and exit with 0 code*/
        if (product_version != SETUP_SUPPORTED_PRODUCT_VERSION) {
            log_with_params("Unsupported assistant product version: (%d)", product_version);
            lerr = LOCKDOWN_E_SUCCESS;
            goto CLEANUP;
        }

        if (handle_np_response(boot_np_res) && !valid_np_resp_received) {
            lerr = -boot_np_res;
            log_with_params("on observing '%s' notification after device restore: Exit with code (%d)...",
                             event_to_wait ?: "NULL",
                             lerr);
            goto CLEANUP;
        }
        //Hardcoded method. Attempt to syncronize assistant info about iOS state and real UI state
        debug_log_with_params("goint to rest for (%d) seconds", POST_OPERATION_SLEEP_VAL);
        sleep(POST_OPERATION_SLEEP_VAL);
    } else {
        debug_log("Performing setup withot waiting for device boot")
    }

    //Reinit
    lerr = lockdownd_client_new_with_handshake(device, &client, "ideviceassistant");
    if (lerr != LOCKDOWN_E_SUCCESS) {
        fprintf(stderr, "%s func, %d line: ERROR: Could not connect to lockdownd, error code %d\n",__func__, __LINE__, lerr);
        goto CLEANUP;
    }
    
    int j = 0;
    dom_t *domain = NULL;
    lerr = LOCKDOWN_E_SUCCESS;
    debug_log_with_params("Going to setup %s", INTERNATIONAL_DOM);
    while ((domain = (international_domain_values + j++)) &&
           domain &&
           !is_empty_domain((const dom_t)(*domain)))
    {
        plist_t new_plist = NULL;
        new_plist = string_to_new_plist(domain->value, domain->value_type);
        if (!new_plist) {
            debug_log_with_params("Could not generate plist from key '%s'. Skipping value and continue...", domain->key);
            continue;
        }
        lerr = lockdownd_set_value_for_key_in_domain(client, new_plist, domain->key, INTERNATIONAL_DOM);
        debug_log_with_params("key '%s' set to value '%s'. Operation result: %s. Lockdownd response %d.\n",
                              domain->key, domain->value,
                              (lerr == LOCKDOWN_E_SET_PROHIBITED ? "imutable value" : (lerr ? "failure" : "success")),
                              lerr);
    }

    if (lerr != LOCKDOWN_E_SUCCESS &&
        lerr != LOCKDOWN_E_SET_PROHIBITED) {
        debug_log_with_params("ERROR: Assistant bypass failure. Going to exit with code %d", lerr);
        goto CLEANUP;
    }

    j = 0;
    domain = NULL;
    lerr = LOCKDOWN_E_SUCCESS;

    debug_log_with_params("Going to setup %s", PURPLEBUDDY_DOM);
    while ((domain = (purplebuddy_domain_values + j++)) &&
           domain &&
           !is_empty_domain((const dom_t)(*domain)))
    {
        plist_t new_plist = NULL;
        new_plist = string_to_new_plist(domain->value, domain->value_type);
        if (!new_plist) {
            debug_log_with_params("Could not generate plist from key '%s'. Skipping value and continue...", domain->key);
            continue;
        }
        lerr = lockdownd_set_value_for_key_in_domain(client, new_plist, domain->key, PURPLEBUDDY_DOM);
        debug_log_with_params("key '%s' set to value '%s'. Operation result: %s. Lockdownd response %d.\n",
                              domain->key, domain->value,
                              (lerr == LOCKDOWN_E_SET_PROHIBITED ? "imutable value" : (lerr ? "failure" : "success")),
                              lerr);
        }

    if (lerr != LOCKDOWN_E_SUCCESS) {
        fprintf(stderr, "%s func, %d line: ERROR: Assistant bypass failure. Going to exit with code %d\n",__func__, __LINE__, lerr);
        goto CLEANUP;
    }
    lerr = (lerr == LOCKDOWN_E_SET_PROHIBITED) ? LOCKDOWN_E_SUCCESS : lerr;
    fprintf(stdout, "Lockdownd set %s && %s domain values successfully.\n", INTERNATIONAL_DOM, PURPLEBUDDY_DOM);

    if (restart_device && !lerr) {
        fprintf(stdout, "NOTICE: Going to restart device");
        char cmd[128] = {0};
        sprintf(cmd, "idevicediagnostics -u %s restart", udid);
        int restart_res = shell_spawn(cmd, DEV_RESTART_OPER_TIMEO);
        if (restart_res) {
            fprintf(stderr, "Device setup bypassed, but restart operation returned incorrect code %d\n", restart_res);
            lerr = ASSISTANT_RESTART_FAILURE;
        }
    }

    //Hardcoded method. Attempt to syncronize assistant info about iOS state and real UI state
    debug_log_with_params("goint to rest for (%d) seconds", POST_OPERATION_SLEEP_VAL);
    sleep(POST_OPERATION_SLEEP_VAL);

    CLEANUP:
    cleanup();

    return lerr;
}
