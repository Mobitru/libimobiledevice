/*
 * idevicedevmodectl.c
 * Activates DeveloperMode feature on iPhone, iPad devices with iOS16+
 *
 * Copyright © 2022 EPAM Systems, Inc. All Rights Reserved. All information contained herein is, and remains the
 * property of EPAM Systems, Inc. and/or its suppliers and is protected by international intellectual
 * property law. Dissemination of this information or reproduction of this material is strictly forbidden,
 * unless prior written permission is obtained from EPAM Systems, Inc
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/service.h>
#include <libimobiledevice/property_list_service.h>
#include <libimobiledevice-glue/utils.h>

//#define IPHONE_DEV_NAME "iPhone"
#define TOOL_NAME "runnerdevmodectl"
#define AMFI_LOCKDOWN_SERVICE_NAME "com.apple.amfi.lockdown"
#define LOCKDOWND_DEV_MODE_DOMAIN "com.apple.security.mac.amfi"
#define LOCKDOWND_DEV_MODE_KEY "DeveloperModeStatus"
#define LOCKDOWND_CLIENT_NAME "mt_assistant_client"
#define DEV_MODE_ACTION_FINAL 3
#define DEV_MODE_ACTION_ZERO 0
#define DEV_MODE_ACTION_ACTIVATE 1
#define DEV_MODE_ACTION_BYPASS_UI_ALERT 2
#define POST_SETUP_SLEEP_VAL 5

#define IDEVICE_LOOKUP_CONNECTION(X) X ? IDEVICE_LOOKUP_NETWORK : IDEVICE_LOOKUP_USBMUX

#define ACTION_TO_STR(A) \
        A == DEV_MODE_ACTION_ZERO ? "ActionUnspecified" : \
        A == DEV_MODE_ACTION_ACTIVATE ? "ActionActtivate" : \
        A == DEV_MODE_ACTION_BYPASS_UI_ALERT ? "ActionBypassAlert" : \
        A == DEV_MODE_ACTION_FINAL ? "ActionFinal" : "ActionUnknown"

enum {
    OP_STATUS,
    OP_TOGGLE
};

enum {
    RESET_OPTION = 0x0,
    DETACH_ONCE_OPTION = 0x2,
    ATTACH_ONCE_OPTION = 0x4
};

static int use_network = 0;

static int usbmuxd_event_option = 0;

//Functions declaration

static int amfid_send_action(property_list_service_client_t amfi, uint8_t action, plist_t *rsp);

static int amfid_send_action_for_device(const char *const udid, uint8_t action, plist_t *rsp);

static void usbmuxd_event_callback(const idevice_event_t *event, void *user_data);

static int get_developer_mode_status(idevice_t device, const char* udid);

static int get_developer_mode_status(idevice_t device, const char* udid)
{
    lockdownd_client_t lockdown = NULL;
    lockdownd_error_t lerr = LOCKDOWN_E_UNKNOWN_ERROR;
    plist_t val = NULL;

    if ((lerr = lockdownd_client_new_with_handshake(device, &lockdown, TOOL_NAME)) != LOCKDOWN_E_SUCCESS) {
        printf("failed to create lockdownd client and perform handshake\n");
        return -1;
    }

    lerr = lockdownd_get_value(lockdown, LOCKDOWND_DEV_MODE_DOMAIN, LOCKDOWND_DEV_MODE_KEY, &val);
    if (lerr != LOCKDOWN_E_SUCCESS) {
        printf("%d: failed to get DeveloperMode status. Probably the device with the other iOS version. i.e not iOS16\n", lerr);
        lockdownd_client_free(lockdown);
        return -1;
    }

    if (!val) {
        printf("NULL DeveloperModeStatus plist file\n");
        return -1;
    }
    uint8_t dev_mode_status = 0;
    plist_get_bool_val(val, &dev_mode_status);
    plist_free(val);
    lockdownd_client_free(lockdown);

    return dev_mode_status;
}

static bool handle_property_list_service_error_response(property_list_service_error_t e, plist_t dict) {
    if (e != PROPERTY_LIST_SERVICE_E_SUCCESS) {
        printf("plist service rsp error: %d\n", e);
        return false;
    }
    uint8_t success = 0;
    plist_t val = NULL;
    val = plist_dict_get_item(dict, "Error");
    bool res = false;
    if (val) {
        char* err = NULL;
        plist_get_string_val(val, &err);
        printf("could not perform operation, reason: %s\n", err);
        free(err);
        err = NULL;
    } else {
        val = plist_dict_get_item(dict, "success");
        if (val)
            plist_get_bool_val(val, &success);
        //debug only
        printf("success key value: %u\n", success);
        res = true;
    }
    return res;
}

static void print_usage(int argc, const char **argv, int is_error)
{
    char *name = NULL;
    name = strrchr(argv[0], '/');
    fprintf(is_error ? stderr : stdout, "Usage: %s [OPTIONS] [UDID]\n", (name ? name + 1: argv[0]));
    fprintf(is_error ? stderr : stdout,
        "\n" \
        "Check and activate Developer mode on iOS 16+ devices.\n" \
        "\n" \
        "  If UDID is given, the name of the connected device with that UDID" \
        "  will be retrieved.\n" \
        "\n" \
        "OPTIONS:\n" \
        "  -s, --status      list UDIDs of all devices attached via USB\n" \
        "  -h, --help      prints usage information\n" \
        "\n"
    );
}

static int amfid_send_action_for_device(const char *const udid, const uint8_t action, plist_t *rsp) {
    if (!udid) {
        printf("Invalid argument provided.\n");
        return -1;
    }
    idevice_t device = NULL;
    idevice_error_t e = 0;
    if ((e = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_CONNECTION(use_network))) != IDEVICE_E_SUCCESS) {
        printf("%d: No device found with udid %s.\n", e, udid);
        return -1;
    }
    int err = 0;
    int init_err = 0;
    void *service = NULL;
    err = service_client_factory_start_service(device, AMFI_LOCKDOWN_SERVICE_NAME, (void **)&service, TOOL_NAME, NULL, &init_err);
    if (err != 0 || init_err != 0) {
        if (err) printf("Failed to start abstract service for amfi: %d.\n", err);
        else printf("Failed to start abstract service for amfi - initialization error: %d.\n", init_err);
        idevice_free(device);
        device = NULL;
        return -1;
    }
    struct property_list_service_client_private {
        service_client_t parent;
    };
    struct property_list_service_client_private shadowed = { service };
    property_list_service_client_t plistservice = (property_list_service_client_t)&shadowed;
    int snd_res = amfid_send_action(plistservice, action, rsp);
    service_client_free(service);
    service = NULL;
    idevice_free(device);
    device = NULL;
    return snd_res;
}

static int amfid_send_action(property_list_service_client_t amfi, uint8_t action, plist_t *rsp) {
    if (!amfi) {
        printf("Invalid argument provided\n");
        return -1;
    }
    int ret = 0;
    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "action", plist_new_uint(action));
    property_list_service_error_t err = PROPERTY_LIST_SERVICE_E_SUCCESS;
    err = property_list_service_send_binary_plist(amfi, dict);
    plist_free(dict);
    dict = NULL;
    if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
        printf("Failed to send %s cmd to amfid\n", ACTION_TO_STR(action));
        ret = -1;
    } else {
        err = property_list_service_receive_plist(amfi, &dict);
        if (!handle_property_list_service_error_response(err, dict)) {
            printf("Invalid response got from %s cmd sent\n", ACTION_TO_STR(action));
            ret = -1;
        }
    }
    if (dict) {
        //caller is responsible for response release
        if (rsp && !*rsp) {
            *rsp = dict;
        } else {
            plist_free(dict);
        }
    }
    return ret;
}

static void usbmuxd_event_callback(const idevice_event_t *event, void *user_data) {
    const char *udid = user_data;
    if (!udid) {
        printf("Invalid user ctx provided.\n");
        return;
    }
    if (!event) {
        printf("got NULL usbmuxd event. Ignore current one.\n");
        return;
    }
    if (event->conn_type != CONNECTION_USBMUXD) {
        printf("Event's connection type is not usbmuxd one. Conn type value -> %d. UDID -> %s. Ignore event\n", event->conn_type, event->udid);
        return;
    }
    time_t t = time(NULL);
    switch (event->event) {
        case IDEVICE_DEVICE_ADD:
            if (strncmp(udid, event->udid, strlen(udid)) == 0) {
                printf("Attach event for %s/%s udid. Time -> %s", udid, event->udid, asctime(localtime(&t)));
                usbmuxd_event_option |= ATTACH_ONCE_OPTION;
            } else {
                printf("Ignore Attach event for %s udid\n", udid);
            }
            break;
        case IDEVICE_DEVICE_REMOVE:
            if (strncmp(udid, event->udid, strlen(udid)) == 0) {
                printf("%s device detached\n", udid);
                usbmuxd_event_option |= DETACH_ONCE_OPTION;
            }
            break;
        case IDEVICE_DEVICE_PAIRED:
            if (strncmp(udid, event->udid, strlen(udid)) == 0)
                printf("%s device paired\n", udid);
            break;
        default:
            printf("Got 'Unknown' event -> %d\n", event->event);
    }
}

static void usbmuxd_wiat_for_event(int event, int *ctx) {
    if (!ctx) {
        printf("Invalid argument provided.\n");
        return;
    }
    *ctx &= RESET_OPTION;
    while (!(*ctx & event)) {
        printf("waiting for %d event from usbmuxd\n", event);
        sleep(1);
    }
}

int main(int argc, const char *argv[]) {
    const char *udid = NULL;
    int op = OP_TOGGLE;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udid")) {
            i++;
            if (!argv[i] || !*argv[i]) {
                print_usage(argc, argv, 1);
                return -1;
            }
            udid = strdup(argv[i]);
            continue;
        } else if (!strcmp(argv[i], "-n") || !strcmp(argv[i], "--network")) {
            use_network = 1;
            continue;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_usage(argc, argv, 0);
            return 0;
        } else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--status")) {
            op = OP_STATUS;
        } else {
            print_usage(argc, argv, 1);
            return -1;
        }
    }
    
    signal(SIGPIPE, SIG_IGN);
    int res = 0;
    int prod_vers[2] = { -1, -1 };
//    const char *device_name = NULL;
    printf("Getting device product version.\n");
    idevice_t device = NULL;
    idevice_error_t e = IDEVICE_E_SUCCESS;
    if ((e = idevice_new_with_options(&device, udid, IDEVICE_LOOKUP_CONNECTION(use_network))) == IDEVICE_E_SUCCESS) {
        lockdownd_client_t lckd = NULL;
        lockdownd_error_t lckd_err = LOCKDOWN_E_SUCCESS;
        lckd_err = lockdownd_client_new_with_handshake(device, &lckd, LOCKDOWND_CLIENT_NAME);
        plist_t pval = NULL;
        if ((lckd_err = lockdownd_get_value(lckd, NULL, "ProductVersion", &pval))/* ||
            (lckd_err = lockdownd_get_value(lckd, NULL, "DeviceName", &pval))*/) {
            idevice_free(device);
            lockdownd_client_free(lckd);
            lckd = NULL;
            device = NULL;
            return -1;
        }
        const char *str_vers = plist_get_string_ptr(pval, NULL);
        if (!str_vers || sscanf(str_vers, "%d.%d", &prod_vers[0], &prod_vers[1]) < 2) {
            printf("Failed to get device product version.\n");
            idevice_free(device);
            device = NULL;
            lockdownd_client_free(lckd);
            lckd = NULL;
            plist_free(pval);
            pval = NULL;
            return -1;
        }
        plist_free(pval);
        pval = NULL;
    }
    if (prod_vers[0] == -1 || prod_vers[1] == -1) {
        printf("Product version post check failed.\n");
        return -1;
    }
    int dev_mode = -1;
    switch (op) {
        case OP_STATUS:
            printf("trying to get developer mode status\n");
            if ((dev_mode = get_developer_mode_status(device, udid)) < 0) {
                res = -1;
                printf("Failed to get developer mode status\n");
            } else {
                res = 0;
                printf("Developer mode is %s on %s device\n", dev_mode ? "enabled" : "disabled", udid);
            }
            break;
        case OP_TOGGLE:
            printf("sending %s action...\n", ACTION_TO_STR(DEV_MODE_ACTION_ACTIVATE));
            if ((res = amfid_send_action_for_device(udid, DEV_MODE_ACTION_ACTIVATE, NULL))) {
                break;
            }
            printf("subscribing to usbmuxd events.\n");
            if ((e = idevice_event_subscribe(&usbmuxd_event_callback, (void *)udid)) != IDEVICE_E_SUCCESS) {
                printf("failed to perform subscribtion to usbmuxd events. Device error code: %d\n", e);
                res = -1;
                break;
            }
            if ((prod_vers[0] == 16 && prod_vers[1] >= 4) || prod_vers[0] >= 17) {
                printf("using modern approach for devmode activation\n");
                //[Sleep (may be)] and Reset value to initial state. There is a 'callback' fire on the very first 'idevice_event_subscribe' function call which set variable before real attach event occurs.
                /* sleep(n_sec); */
                //Order or function calls matter!
                usbmuxd_wiat_for_event(DETACH_ONCE_OPTION, &usbmuxd_event_option);
                usbmuxd_wiat_for_event(ATTACH_ONCE_OPTION, &usbmuxd_event_option);
                printf("sending %s action...\n", ACTION_TO_STR(DEV_MODE_ACTION_BYPASS_UI_ALERT));
                if ((res = amfid_send_action_for_device(udid, DEV_MODE_ACTION_BYPASS_UI_ALERT, NULL))) {
                    printf("failed to send %s action to amfi service\n", ACTION_TO_STR(DEV_MODE_ACTION_BYPASS_UI_ALERT));
                }
            } else {
                int fork_res = -1;
                int parent_pid = getpid();
                printf("[%d] Parent process is going to fork child.\n", parent_pid);
                fork_res = fork();
                if (fork_res == 0) {
                    int child_pid = getpid();
                    printf("[%d] Hello from child.\n", child_pid);
                    printf("[%d] Child is going to subscribe to usbmuxd events.\n", child_pid);
                    if ((e = idevice_event_subscribe(&usbmuxd_event_callback, (void *)udid)) != IDEVICE_E_SUCCESS) {
                        printf("failed to perform subscribtion to usbmuxd events. Device error code: %d\n", e);
                        res = -1;
                        break;
                    }
                    //Order or function calls matter!
                    usbmuxd_wiat_for_event(DETACH_ONCE_OPTION, &usbmuxd_event_option);
                    usbmuxd_wiat_for_event(ATTACH_ONCE_OPTION, &usbmuxd_event_option);
                    const int slval = POST_SETUP_SLEEP_VAL * 2;
                    printf("sleeping %d secs after attach event\n", slval);
                    sleep(slval);
                    printf("sending %s action...\n", ACTION_TO_STR(DEV_MODE_ACTION_BYPASS_UI_ALERT));
                    if ((res = amfid_send_action_for_device(udid, DEV_MODE_ACTION_BYPASS_UI_ALERT, NULL))) {
                        printf("failed to send %u action to amfi service\n", DEV_MODE_ACTION_BYPASS_UI_ALERT);
                    }
                } else if (fork_res > 0) {
                    printf("[%d] Hello from parent. Fork child pid: %d.\n", parent_pid, fork_res);
                    //Order or function calls matter!
                    usbmuxd_wiat_for_event(DETACH_ONCE_OPTION, &usbmuxd_event_option);
                    usbmuxd_wiat_for_event(ATTACH_ONCE_OPTION, &usbmuxd_event_option);
                    const int slval = POST_SETUP_SLEEP_VAL * 3;
                    printf("[%d] Child has gone. Parent is going to go out too after %d sleeping...\n", parent_pid, slval);
                    sleep(slval);
                } else {
                    printf("%d Failed to fork child process\n", fork_res);
                    res = -1;
                }
            }
            break;
        default:
            printf("Unknown operation provided\n");
            res = -1;
    }
    if (idevice_event_unsubscribe() != IDEVICE_E_SUCCESS)
        printf("Failed to unsibscribe from usbmuxd events. Continue cleanup anyway...\n");
    printf("[%d]: Operation %s. Exit with code %d\n", getpid(), (res != 0 ? "failed" : "performed"), res);
    return res;
}
