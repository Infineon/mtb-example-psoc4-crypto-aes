/******************************************************************************
 * File Name:   main.c
 *
 * Description: This is the source code for the PSoC 4 Cryptography AES
 * demonstration example for ModusToolbox.
 *
 * Related Document: See README.md
 *
 *
 *******************************************************************************
 * Copyright 2020-2021, Cypress Semiconductor Corporation (an Infineon company) 
 * or an affiliate of Cypress Semiconductor Corporation.  All rights reserved.
 *
 * This software, including source code, documentation and related
 * materials ("Software") is owned by Cypress Semiconductor Corporation
 * or one of its affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license
 * agreement accompanying the software package from which you
 * obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software
 * source code solely for use in connection with Cypress's
 * integrated circuit products.  Any reproduction, modification, translation,
 * compilation, or representation of this Software except as specified
 * above is prohibited without the express written permission of Cypress.
 *
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 * reserves the right to make changes to the Software without notice. Cypress
 * does not assume any liability arising out of the application or use of the
 * Software or any product or circuit described in the Software. Cypress does
 * not authorize its products for use in any products where a malfunction or
 * failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product"). By
 * including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing
 * so agrees to indemnify Cypress against all liability.
 *******************************************************************************/

#include "cy_pdl.h"
#include "cybsp.h"
#include <stdio.h>
#include <string.h>

/********************************************************************************
 * Macros
 ********************************************************************************/
/* The input message size (inclusive of the string terminating character '\0').
 * Edit this macro to suit your message size. This must be in multiples of 16.
 */
#define MAX_MESSAGE_SIZE                     (112u)

/* Size of the message block that can be processed by Crypto hardware for
 * AES encryption.
 */
#define AES128_ENCRYPTION_LENGTH             (uint32_t)(16u)

/* Size of the Key block used for AES encryption. */
#define AES128_KEY_LENGTH                    (uint32_t)(16u)

/* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen. */
#define CLEAR_SCREEN                         "\x1b[2J\x1b[;H"

/* Number of bytes per line to be printed on the UART terminal. */
#define BYTES_PER_LINE                       (16u)

/* Time to wait (ms) to receive a character from UART terminal. 
 * Edit this as per the requirement.
 * Setting it to 0 makes the system wait forever to receive the data.
 */
#define UART_INPUT_TIMEOUT_MS                (0u)

/* The get_char function timed out with no received data */
#define CY_RSLT_ERR_CSP_UART_GETC_TIMEOUT               \
        (CY_RSLT_CREATE(CY_RSLT_TYPE_ERROR, CY_RSLT_MODULE_DRIVER_SCB, 1))

/* String containing the terminal screen header */
#define SCREEN_HEADER "\r\n__________________________________________________"\
        "____________________________\r\n*\t\tCE233472 - "\
        "PSoC 4 Cryptography AES demonstration\r\n*\r\n*\tThis code "\
        "example demonstrates the encryption and decryption of data "\
        "\r\n*\tusing the Advanced Encryption Scheme (AES) algorithm"\
        " in PSoC 4 MCU.\r\n*\r\n*\tUART Terminal Settings: Baud Rate"\
        "- 115200 bps, 8N1\r\n*"\
        "\r\n__________________________________________________"\
        "____________________________\r\n"

#define SCREEN_HEADER1 "\r\n\n__________________________________________________"\
        "____________________________\r\n"

/********************************************************************************
 * Data type definitions
 ********************************************************************************/
/* Data type definition to track the state machine accepting the user message */
typedef enum
{
    MESSAGE_ENTER_NEW,
    MESSAGE_READY
} message_status_t;

/********************************************************************************
 * Function Prototypes
 ********************************************************************************/
/* Function used to display the data in hexadecimal format */
void print_data(uint8_t* data, uint8_t len);

/* Function used to encrypt the message. */
void encrypt_message(uint8_t* message, uint8_t size);

/* Function used to decrypt the message. */
void decrypt_message(uint8_t* message, uint8_t size);

/* Function used to read user input from UART terminal */
cy_rslt_t get_char(uint8_t* value, uint32_t timeout);

/********************************************************************************
 * Global Variables
 ********************************************************************************/
/* Variable to hold the user message */ 
uint8_t message[MAX_MESSAGE_SIZE];

/* Variable to hold the encrypted message */
uint8_t encrypted_msg[MAX_MESSAGE_SIZE];

/* Variable to hold the decrypted message */
uint8_t decrypted_msg[MAX_MESSAGE_SIZE+1];

/* Variable to hold the AES Context */
cy_stc_crypto_aes_context_t aesContext;

/* Key used for AES encryption */
uint8_t aes_key[AES128_KEY_LENGTH] = {0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF, 0xFF, 0xEE,
        0xDD, 0xCC, 0xBB, 0xAA,
        0xAA, 0xBB, 0xCC, 0xDD,};

/********************************************************************************
 * Function Name: main
 ********************************************************************************
 * Summary:
 * Main function
 *
 * Parameters:
 *  void
 *
 * Return:
 *  int
 *
 *******************************************************************************/
int main(void)
{
    /* Variable to hold general status of operations*/
    cy_rslt_t result = CY_RSLT_SUCCESS;

    /* Variable to track the status of the message entered by the user */
    message_status_t msg_status = MESSAGE_ENTER_NEW;

    /*Variable pointing to individual elements within the message array*/
    uint8_t msg_size = 0;

    /* Initialize the device and board peripherals */
    result = cybsp_init();

    /* Board init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable global interrupts */
    __enable_irq();

    /* Allocate context for UART operation */
    cy_stc_scb_uart_context_t uartContext;

    /*Initialize UART*/
    result = Cy_SCB_UART_Init(UART_HW, &UART_config, &uartContext);

    /* SCB UART init failed. Stop program execution */
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Enable UART to operate */
    Cy_SCB_UART_Enable(UART_HW);

    /* \x1b[2J\x1b[;H - ANSI ESC sequence for clear screen */
    Cy_SCB_UART_PutString(UART_HW, CLEAR_SCREEN);

    /* Print terminal screen header */
    Cy_SCB_UART_PutString(UART_HW, SCREEN_HEADER);

    /*Variable to hold Crypto block status*/
    cy_en_crypto_status_t cryptoStatus;

    /* Enable Crypto IP */
    cryptoStatus = Cy_Crypto_Enable(CRYPTO);

    /* Crypto init failed. Stop program execution */
    if (cryptoStatus != CY_CRYPTO_SUCCESS)
    {
        CY_ASSERT(0);
    }

    /* Print enter message prompt */
    Cy_SCB_UART_PutString(UART_HW, "\r\nEnter the message:\r\n");

    for (;;)
    {
        switch (msg_status)
        {
            case MESSAGE_ENTER_NEW:
            {
                /* Obtain the user input message */
                result = get_char(&message[msg_size], UART_INPUT_TIMEOUT_MS);
                if (result == CY_RSLT_SUCCESS)
                {
                    /* Check if the ENTER Key is pressed. If pressed, set 
                    * the message status as MESSAGE_READY.
                    */
                    if (message[msg_size] == '\r' || message[msg_size] == '\n')
                    {
                        /* If the enter key is pressed without entering any message */
                        if (msg_size == 0)
                        {
                            Cy_SCB_UART_PutString(UART_HW, "\r\n\nEnter a valid message"\
                                    " before pressing the enter key!");

                            Cy_SCB_UART_PutString(UART_HW, SCREEN_HEADER1);

                            /* Clear the message buffer and set the msg_status to accept
                             * new message from the user.
                             */
                            memset(message, 0, MAX_MESSAGE_SIZE);
                            msg_status = MESSAGE_ENTER_NEW;
                            msg_size = 0;
                            Cy_SCB_UART_PutString(UART_HW, "\r\nEnter the message:\r\n");
                            break;
                        }
                        message[msg_size]='\0';
                        msg_status = MESSAGE_READY;
                    }
                    else
                    {
                        Cy_SCB_UART_Put(UART_HW, message[msg_size]);

                        /* Check if Backspace is pressed by the user. */
                        if(message[msg_size] != '\b')
                        {
                            msg_size++;
                        }
                        else
                        {
                            if(msg_size > 0)
                            {
                                msg_size--;
                            }
                        }

                        /* Check if size of the message exceeds MAX_MESSAGE_SIZE
                        * (inclusive of the string terminating character '\0').
                        */
                        if (msg_size > (MAX_MESSAGE_SIZE - 1))
                        {
                            Cy_SCB_UART_PutString(UART_HW, "\r\n\nMessage length"\
                                    " exceeds maximum characters!!!"\
                                    " Please enter a shorter message\r\nor edit the" 
                                    " macro MAX_MESSAGE_SIZE"\
                                    " to suit your message size.\r\n");

                            Cy_SCB_UART_PutString(UART_HW, SCREEN_HEADER1);

                            /* Clear the message buffer and set the msg_status to accept
                            * new message from the user.
                            */
                            msg_status = MESSAGE_ENTER_NEW;
                            memset(message, 0, MAX_MESSAGE_SIZE);
                            msg_size = 0;
                            Cy_SCB_UART_PutString(UART_HW, "\r\nEnter the message:\r\n");
                            break;
                        }
                    }
                }

                /* Message entry timed out. 
                * Edit the macro UART_INPUT_TIMEOUT_MS to change the timeout period.
                */
                else if (result == CY_RSLT_ERR_CSP_UART_GETC_TIMEOUT)
                {
                    Cy_SCB_UART_PutString(UART_HW, "\r\n\nMessage entry timed out!"\
                            " Please enter the message within the timeout period\r\n"\
                            "or edit the macro UART_INPUT_TIMEOUT_MS to change the"\
                            " timeout period.\r\n\n");

                    Cy_SCB_UART_PutString(UART_HW, SCREEN_HEADER1);

                    /* Clear the message buffer and set the msg_status to accept
                    * new message from the user.
                    */
                    memset(message, 0, MAX_MESSAGE_SIZE);
                    msg_size = 0;
                    Cy_SCB_UART_PutString(UART_HW, "\r\nEnter the message:\r\n");
                }
                break;
            }

            case MESSAGE_READY:
            {

                /* Encrypt the input data */
                encrypt_message(message, msg_size);

                /* Decrypt the input data */
                decrypt_message(encrypted_msg, sizeof(encrypted_msg));

                /* Clear the message buffer and set the msg_status to accept
                * new message from the user.
                */
                msg_status = MESSAGE_ENTER_NEW;
                memset(message, 0, MAX_MESSAGE_SIZE);
                msg_size = 0;
                Cy_SCB_UART_PutString(UART_HW, "\r\nEnter the message:\r\n");
                break;
            }
        }
    }
}

/********************************************************************************
 * Function Name: print_data()
 ********************************************************************************
 * Summary: Function used to display the data in hexadecimal format
 *
 * Parameters:
 *  uint8_t* data - Pointer to location of data to be printed
 *  uint8_t  len  - length of data to be printed
 *
 * Return:
 *  void
 *
 *******************************************************************************/
void print_data(uint8_t* data, uint8_t len)
{
    char print[10];
    for (uint32 i=0; i < len; i++)
    {
        if ((i % BYTES_PER_LINE) == 0)
        {
            Cy_SCB_UART_PutString(UART_HW, "\r\n");
        }
        sprintf(print,"0x%02X ", *(data+i));
        Cy_SCB_UART_PutString(UART_HW, print);
    }
    Cy_SCB_UART_PutString(UART_HW, "\r\n");
}

/********************************************************************************
 * Function Name: encrypt_message
 ********************************************************************************
 * Summary: Function used to encrypt the message.
 *
 * Parameters:
 *  char * message - pointer to the message to be encrypted
 *  uint8_t size   - size of message to be encrypted.
 *
 * Return:
 *  void
 *
 *******************************************************************************/
void encrypt_message(uint8_t* message, uint8_t size)
{
    /* Variable to hold the block count value */
    uint8_t aes_block_count = 0;

    /* Iteration variables */
    int i,j = 0;

    /*Variable to hold Crypto block status*/
    cy_en_crypto_status_t cryptoEncryptStatus;

    /* Calculate the block count of message in multiples of 16 */
    aes_block_count = (size % AES128_ENCRYPTION_LENGTH == 0) ?
            (size / AES128_ENCRYPTION_LENGTH)
            : (1 + size / AES128_ENCRYPTION_LENGTH);

    /* Initialize Crypto AES block  */
    cryptoEncryptStatus = Cy_Crypto_Aes_Init(
            CRYPTO,             /* Base address of the Crypto block registers */
            aes_key,            /* Pointer to key */
            CY_CRYPTO_KEY_AES_128, /* Key size */
            &aesContext);          /* Pointer to AES context structure */

    /* Check Crypto block init status */
    if (cryptoEncryptStatus != CY_CRYPTO_SUCCESS)
    {
        Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                " Crypto Init Failed\r\n");
        CY_ASSERT(0);
    }

    /* Perform encryption on message directly if message size is
     * a multiple of 16.
     */
    if (size % AES128_ENCRYPTION_LENGTH == 0)
    {
        for (int i = 0; i < aes_block_count ; i++)
        {
            /* Perform AES ECB Encryption mode of operation */
            cryptoEncryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_ENCRYPT,
                    (encrypted_msg + AES128_ENCRYPTION_LENGTH * i),
                    (message + AES128_ENCRYPTION_LENGTH * i),
                    &aesContext);

            /* Check Crypto operation status */
            if (cryptoEncryptStatus != CY_CRYPTO_SUCCESS)
            {
                Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                        " Encryption Failed\r\n");
                CY_ASSERT(0);
            }

            /* Wait for Crypto Block to be available */
            Cy_Crypto_WaitForReady(CRYPTO);
        }
    }

    /* If message size is not a multiple of 16, additional steps are required
     * to ensure AES-ECB operation is called with a valid 16-byte data in 
     * all iterations.
     */
    else
    {
        /* Create a temporary array of size AES128_ENCRYPTION_LENGTH
         * and initialize the array.
         */
        uint8_t temp_message[AES128_ENCRYPTION_LENGTH];
        memset(temp_message, '\0', sizeof(temp_message));

        /* Copy the last section of message which cannot be called with a 
         * valid 16-byte block, into the new array.
         */
        for (i = (AES128_ENCRYPTION_LENGTH * (aes_block_count-1)); i < size; i++)
        {
            temp_message[j++] = message[i];
        }

        /* Perform AES ECB Encryption directly on message blocks with valid 
         * 16-byte data.
         */
        for (int i = 0; i < aes_block_count-1 ; i++)
        {
            /* Perform AES ECB Encryption mode of operation */
            cryptoEncryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_ENCRYPT,
                    (encrypted_msg + AES128_ENCRYPTION_LENGTH * i),
                    (message + AES128_ENCRYPTION_LENGTH * i),
                    &aesContext);

            /* Check Crypto operation status */
            if (cryptoEncryptStatus != CY_CRYPTO_SUCCESS)
            {
                Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                        " Encryption Failed\r\n");
                CY_ASSERT(0);
            }

            /* Wait for Crypto Block to be available */
            Cy_Crypto_WaitForReady(CRYPTO);
        }

        /* Perform AES ECB Encryption on the last section of message 
         * and save the result in encrypted_msg buffer itself without
         * over writting the previous results.
         */
        cryptoEncryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_ENCRYPT, 
                (encrypted_msg + AES128_ENCRYPTION_LENGTH * (aes_block_count-1)),
                temp_message, &aesContext);

        /* Check Crypto operation status */
        if (cryptoEncryptStatus != CY_CRYPTO_SUCCESS)
        {
            Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                    " Encryption Failed\r\n");
            CY_ASSERT(0);
        }

    }

    /* Print the AES Key used for encryption */
    Cy_SCB_UART_PutString(UART_HW, "\r\n\nKey used for Encryption:\r\n");
    print_data(aes_key, AES128_KEY_LENGTH);

    /* Print the result after encryption */
    Cy_SCB_UART_PutString(UART_HW, "\r\nResult of Encryption:\r\n");
    print_data((uint8_t*) encrypted_msg, 
            aes_block_count * AES128_ENCRYPTION_LENGTH);

    /* Clear the AES context */
    Cy_Crypto_Aes_Free(CRYPTO, &aesContext);
}

/*******************************************************************************
 * Function Name: decrypt_message
 *******************************************************************************
 * Summary: Function used to decrypt the message.
 *
 * Parameters:
 *  char * message - pointer to the message to be decrypted
 *  uint8_t size   - size of message to be decrypted.
 *
 * Return:
 *  void
 *
 ******************************************************************************/
void decrypt_message(uint8_t* message, uint8_t size)
{
    /* Variable to hold the block count value */
    uint8_t aes_block_count = 0;

    /* Iteration variables */
    int i,j = 0;

    /*Variable to hold Crypto block status*/
    cy_en_crypto_status_t cryptoDecryptStatus;

    /* Calculate the block count of message in multiples of 16 */
    aes_block_count =  (size % AES128_ENCRYPTION_LENGTH == 0) ?
            (size / AES128_ENCRYPTION_LENGTH)
            : (1 + size / AES128_ENCRYPTION_LENGTH);

    /* Initializes the Crypto AES block */
    cryptoDecryptStatus = Cy_Crypto_Aes_Init(
            CRYPTO,             /* Base address of the Crypto block registers */
            aes_key,            /* Pointer to key */
            CY_CRYPTO_KEY_AES_128, /* Key size */
            &aesContext);          /* Pointer to AES context structure */

    /* Check Crypto block init status */
    if (cryptoDecryptStatus != CY_CRYPTO_SUCCESS)
    {
        Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                " Crypto Init Failed\r\n");
        CY_ASSERT(0);
    }

    /* Perform decryption of a message directly if  
     * the message size is a multiple of 16.
     */
    if (size % AES128_ENCRYPTION_LENGTH == 0)
    {
        /* Start decryption operation*/
        for (int i = 0; i < aes_block_count ; i++)
        {
            /* Perform AES ECB Decryption mode of operation */
            cryptoDecryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_DECRYPT,
                    (decrypted_msg + AES128_ENCRYPTION_LENGTH * i),
                    (message + AES128_ENCRYPTION_LENGTH * i),
                    &aesContext);

            /* Check Crypto operation status */
            if (cryptoDecryptStatus != CY_CRYPTO_SUCCESS)
            {
                Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                        " Decryption Failed\r\n");
                CY_ASSERT(0);
            }

            /* Wait for Crypto Block to be available */
            Cy_Crypto_WaitForReady(CRYPTO);
        }

        /* Add a null character at the end of decrypted_msg array */
        decrypted_msg[size]='\0';
    }

    /* If message size is not a multiple of 16, additional steps are required
     * to ensure AES-ECB operation is called with a valid 16-byte data in 
     * all iterations.
     */
    else
    {
        /* Create a temporary array of size AES128_ENCRYPTION_LENGTH
         * and initialize the array.
         */
        uint8_t temp_message[AES128_ENCRYPTION_LENGTH];
        memset(temp_message, 0, sizeof(temp_message));

        /* Copy the last section of message which cannot be called with a 
         * valid 16-byte block, into the new array.
         */
        for (i=(AES128_ENCRYPTION_LENGTH * (aes_block_count-1)); i<size; i++)
        {
            temp_message[j++] = message[i];
        }

        /* Perform AES ECB Decryption directly on message blocks with valid 
         * 16-byte data.
         */
        for (i = 0; i < aes_block_count-1 ; i++)
        {
            /* Perform AES ECB Decryption mode of operation */
            cryptoDecryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_DECRYPT,
                    (decrypted_msg + AES128_ENCRYPTION_LENGTH * i),
                    (message + AES128_ENCRYPTION_LENGTH * i),
                    &aesContext);

            /* Check Crypto operation status */
            if (cryptoDecryptStatus != CY_CRYPTO_SUCCESS)
            {
                Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                        " Decryption Failed\r\n");
                CY_ASSERT(0);
            }

            /* Wait for Crypto Block to be available */
            Cy_Crypto_WaitForReady(CRYPTO);
        }

        /* Perform AES ECB Decryption on the last section of message 
         * and save the result in decrypted_msg buffer itself without
         * over writting the previous results.
         */
        cryptoDecryptStatus = Cy_Crypto_Aes_Ecb(CRYPTO, CY_CRYPTO_DECRYPT,
                    (decrypted_msg + AES128_ENCRYPTION_LENGTH * (aes_block_count-1)),
                    temp_message, &aesContext);
        
        /* Check Crypto operation status */
        if (cryptoDecryptStatus != CY_CRYPTO_SUCCESS)
        {
            Cy_SCB_UART_PutString(UART_HW, "\r\n\n Status:"\
                    " Decryption Failed\r\n");
            CY_ASSERT(0);
        }

        /* Add a null character at the end of decrypted_msg array */
        decrypted_msg[size]='\0';
    }

    /* Print the decrypted message on the UART terminal */
    Cy_SCB_UART_PutString(UART_HW, "\r\nResult of Decryption:\r\n\n");
    Cy_SCB_UART_PutString(UART_HW, (char*)decrypted_msg);
    Cy_SCB_UART_PutString(UART_HW, SCREEN_HEADER1);

    /* Clears the Crypto AES context */
    Cy_Crypto_Aes_Free(CRYPTO, &aesContext);
}

/*******************************************************************************
 * Function Name: get_char
 *******************************************************************************
 * Summary: Function used to read user input from UART terminal
 *
 * Parameters:
 *  uint8_t * value  - pointer to the array storing the message.
 *  uint32_t timeout - The time in ms to spend attempting to receive
 *                     from serial port. Zero is wait forever.
 *
 * Return:
 *  cy_rslt_t        - Provides result of an operation as a structured bitfield
 *
 ******************************************************************************/
cy_rslt_t get_char(uint8_t* value, uint32_t timeout)
{
    /* Variable to hold the user input character */
    uint32_t read_value = Cy_SCB_UART_Get(UART_HW);

    /* Variable to store the timeout counter */
    uint32_t timeoutTicks = timeout;

    /* Variable to hold the result of operation */
    cy_rslt_t uart_result = CY_RSLT_SUCCESS;

    /* Waiting for user input character */
    while (read_value == CY_SCB_UART_RX_NO_DATA)
    {
        /* If UART_INPUT_TIMEOUT_MS is 0, wait forever.
         * Else, wait until user input timeout.
         */
        if(timeout != 0UL)
        {
            if(timeoutTicks > 0UL)
            {
                Cy_SysLib_Delay(1);
                timeoutTicks--;
            }
            else
            {
                /* Change the result status to UART timeout */
                uart_result = CY_RSLT_ERR_CSP_UART_GETC_TIMEOUT;
                break;
            }
        }
        read_value = Cy_SCB_UART_Get(UART_HW);
    }
    *value = (uint8_t)read_value;
    return uart_result;
}

/* [] END OF FILE */
