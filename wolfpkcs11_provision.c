#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logging.h"

#include "wolfssl/options.h"

#include "wolfssl/wolfcrypt/wc_pkcs11.h"

LOG_MODULE_CREATE(wolfpkcs11_provision);

#define ERROR_OUT(...)                                                                             \
        {                                                                                          \
                LOG_ERROR(__VA_ARGS__);                                                            \
                ret = 1;                                                                           \
                goto exit;                                                                         \
        }

static const struct option cli_options[] = {
        {"module_label", required_argument, 0, 0x01},
        {"so_pin", required_argument, 0, 0x02},
        {"user_pin", required_argument, 0, 0x03},
        {"module_path", required_argument, 0, 0x04},
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, NULL, 0},
};

void print_help(char* prog_name)
{
        printf("Usage: %s [OPTIONS]\r\n", prog_name);
        printf("Options:\r\n");
        printf("  --module_label <label>       Label of the PKCS#11 module\r\n");
        printf("  --so_pin <pin>               Security Officer PIN of the PKCS#11 module\r\n");
        printf("  --user_pin <pin>             User PIN of the PKCS#11 module\r\n");
        printf("  --module_path <path>         Path to the PKCS#11 module\r\n");
        printf("  -v --verbose                 Enable verbose output\r\n");
        printf("  -d --debug                   Enable debug output\r\n");
        printf("  -h --help                    Print this help\r\n");
}

int main(int argc, char** argv)
{
        int ret = 0;
        int index = 0;
        CK_RV rv = CKR_OK;

        Pkcs11Dev device;
        bool deviceInitialized = false;
        Pkcs11Token token;
        bool tokenInitialized = false;

        char* moduleLabel = NULL;
        char* soPin = NULL;
        char* userPin = NULL;
        char* modulePath = NULL;

        /* Parse CLI args */
        if (argc < 2)
        {
                print_help(argv[0]);
                ERROR_OUT("no arguments provided");
        }

        while (true)
        {
                int result = getopt_long(argc, argv, "vdh", cli_options, &index);

                if (result == -1)
                        break; /* end of list */

                switch (result)
                {
                case 0x01: /* module_label */
                        moduleLabel = optarg;
                        break;
                case 0x02: /* so_pin */
                        soPin = optarg;
                        break;
                case 0x03: /* user_pin */
                        userPin = optarg;
                        break;
                case 0x04: /* module_path */
                        modulePath = optarg;
                        break;
                case 'v':
                        LOG_LVL_SET(LOG_LVL_INFO);
                        break;
                case 'd':
                        LOG_LVL_SET(LOG_LVL_DEBUG);
                        break;
                case 'h':
                        print_help(argv[0]);
                        exit(0);
                        break;
                default:
                        fprintf(stderr, "unknown option: %c\n", result);
                        print_help(argv[0]);
                        exit(-1);
                }
        }

        /* Initialize the PKCS#11 library */
        int pkcs11_version = WC_PCKS11VERSION_3_2;
        ret = wc_Pkcs11_Initialize_ex(&device, modulePath, NULL, &pkcs11_version, "PKCS 11", &rv);
        if (ret != 0)
                ERROR_OUT("PKCS#11 library initialization failed: %d", ret);
        LOG_DEBUG("PKCS#11 version: %d", device.version);

        deviceInitialized = true;

        /* Initialize token. This sets the module label and the security officer PIN */
        rv = device.func->C_InitToken(1,
                                      (CK_UTF8CHAR_PTR) soPin,
                                      strlen(soPin),
                                      (CK_UTF8CHAR_PTR) moduleLabel);
        if (rv != CKR_OK)
                ERROR_OUT("Unable to initialize token: %d", rv);

        /* Open the token */
        ret = wc_Pkcs11Token_Init_NoLogin(&token, &device, -1, NULL);
        if (ret != 0)
                ERROR_OUT("Unable to open token: %d", ret);
        tokenInitialized = true;

        /* Open a session without login */
        ret = wc_Pkcs11Token_Open(&token, 1);
        if (ret != 0)
                ERROR_OUT("Unable to open session: %d", ret);

        /* Login as SO */
        rv = token.func->C_Login(token.handle, CKU_SO, (CK_UTF8CHAR_PTR) soPin, strlen(soPin));
        if (rv != CKR_OK)
                ERROR_OUT("Unable to login as SO: %d", rv);

        /* Set the user PIN */
        rv = token.func->C_InitPIN(token.handle, (CK_UTF8CHAR_PTR) userPin, strlen(userPin));
        if (rv != CKR_OK)
                ERROR_OUT("Unable to set user PIN: %d", rv);

        /* Close the SO session */
        wc_Pkcs11Token_Close(&token);

        /* Open the token as user with login */
        ret = wc_Pkcs11Token_Init(&token, &device, -1, NULL, (unsigned char*) userPin, strlen(userPin));
        if (ret != 0)
                ERROR_OUT("Unable to init token: %d", ret);

        ret = wc_Pkcs11Token_Open(&token, 1);
        if (ret != 0)
                ERROR_OUT("Unable to open user session: %d", ret);

exit:
        if (tokenInitialized)
                wc_Pkcs11Token_Final(&token);

        if (deviceInitialized)
                wc_Pkcs11_Finalize(&device);

        return ret;
}
