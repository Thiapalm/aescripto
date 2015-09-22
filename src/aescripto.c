/*
 * aescripto.c
 *
 *  Created on: 10/09/2015
 *      Author: Thiago
 */

#include <stdio.h>
#include <stdlib.h>
#include "aes256.h"
#include <string.h>
#include <unistd.h>
//MACROS

//CONSTS
const char version[] = "V1.0.0";

// ENUM & STRUCT & TYPEDEFS
typedef void (*actionptr)(aes256_context *, uint8_t *);

char * output[] = {
		"%02x",
		"%c"
};

enum output_type
{
	HEX = 0,
	CHAR
};

typedef enum action_t
{
  ENCRYPT = 0,
  DECRYPT,
  FAULT
} action_t;

typedef enum status_t
{
  STATUS_OK = 0,
  STATUS_FAULT
} status_t;

typedef enum message_type
{
  MESSAGE_HEX = 0,
  MESSAGE_TEXT,
  MESSAGE_FILE,
  MESSAGE_INVALID
} message_type_t;

enum exit_codes
{
  X_SUCCESS = 0,
  X_FAILARGS,
  X_WRONGMESSAGE,
  X_WRONGKEY,
  X_WRONGNUMBEROFARGUMENTS,
  X_NULL
};

typedef struct params
{
  action_t operation;
  status_t has_message;
  status_t has_key;
} params_t;

typedef struct input_data
{
  uint8_t * aes_key;
  char * aes_message;
  message_type_t type_of_message;
} input_data_t;

//GLOBAL VARIABLES
params_t input_validity =
{
  .operation = FAULT,
  .has_message = STATUS_FAULT,
  .has_key = STATUS_FAULT
};

actionptr aes_operation[] = {aes256_encrypt_ecb, aes256_decrypt_ecb};
input_data_t data;
char * charptr;

//FUNCTION START
void printhelp()
{
  fprintf(stdout,"Usage: AESCripto [-e or -d] -k <key> -x <message>\r\n\r\n");
  fprintf(stdout,"[-options]: \r\n");
  fprintf(stdout,"  -h			Shows this Help\r\n");
  fprintf(stdout,"  -e			Encrypt message\r\n");
  fprintf(stdout,"  -d			Decrypt message\r\n\r\n");
  fprintf(stdout,"  -k			32Byte size Key\r\n");
  fprintf(stdout,"  -x			Hexadecimal message\r\n\r\n");
  fprintf(stdout,"The Key must have 32Byte in size.\r\n");
  fprintf(stdout,"The Hexadecimal message must be typed without the initial '0x'.\r\n");
  fprintf(stdout,"Example:\n aescripto -e -k 12345678901234567890123456789012 -x 000102030405060708090a0b0c0d0e0f");

}

void my_exit(uint8_t exit_code)
{
  switch (exit_code)
  {
    case X_SUCCESS:
      //fprintf(stdout,"\r\nAESCripto is over, Thanks for using!\r\n");
      break;
    case X_FAILARGS:
      fprintf(stderr,"Usage: AESCripto [-e or -d] -k <key> -x <message>\r\n");
      break;
    case X_WRONGMESSAGE:
      fprintf(stderr,"Message %s has the wrong size, it must have 16 Bytes!\r\n", charptr);
      break;
    case X_WRONGKEY:
      fprintf(stderr,"The Key has the wrong size, it must have 32 Bytes!\r\n");
      break;
    case X_WRONGNUMBEROFARGUMENTS:
      fprintf(stderr,"Wrong number of arguments!\r\n => $s\r\n", charptr);
      break;
    default:
      break;
  }
  exit(EXIT_SUCCESS);
}

uint8_t tohex(char *value, int i)
{
    uint8_t result = 0;
    if ((value[i] - '0') <= 9 )
    {
        result = (value[i] - '0');
    } else if (((value[i] - 'A') <= 5))
    {
        result = (value[i] - 'A') + 10;
    } else if (((value[i] - 'a') <= 5))
    {
        result = (value[i] - 'a') + 10;
    }
    return result;
}

uint8_t * hex (input_data_t data, action_t action, uint8_t * array, uint8_t array_size)
{

	int i = 0;
	int k = 0;
	while (i != array_size)
	{

			array[k] = (tohex(data.aes_message, i) << 4);
			i++;
			array[k] += tohex(data.aes_message, i);
			i++;
			k++;
	}

	return &array[0];
}

uint8_t * text (input_data_t data, action_t action, uint8_t * array, uint8_t array_size)
{

    if (action == DECRYPT)
    {
		int i = 0;
		int k = 0;
		while (i != array_size)
		{
			array[k] = (tohex(data.aes_message, i) << 4);
			i++;
			array[k] += tohex(data.aes_message, i);
			i++;
			k++;
		}


    } else if (action == ENCRYPT)
    {

		int ind = 0;
		for(ind = 0; ind < array_size / 2; ind++){
			sprintf((char*)array + ind*2, "%02X", data.aes_message[ind]);
		}

    }

    printf("%s\n", array);

    return &array[0];
}

void my_action (input_data_t data, action_t action)
{
    aes256_context ctx;
    aes256_init(&ctx, data.aes_key);

    uint8_t * valuep;
    char * outputp;
    uint8_t value[16];
    int this_size = 0;

    int size = strlen(data.aes_message);

	int outsize = size * 2;
	uint8_t outvalue[outsize];


    if (data.type_of_message == MESSAGE_HEX)
    {
    	valuep = &value[0];
    	hex(data, action, valuep, size);
    	this_size = size / 2;
    	outputp = output[HEX];

    } else if (data.type_of_message == MESSAGE_TEXT)
    {

    	if (action == DECRYPT)
        {
        	valuep = &outvalue[0];
        	hex(data, action, valuep, outsize);
        	this_size = outsize / 2;
        	outputp = output[HEX];


        	int i = 0;
            while (i != this_size / 2)
            {
            	fprintf(stdout, outputp, valuep[i]);
                i++;
            }

        } else if (action == ENCRYPT)
        {
        	valuep = &outvalue[0];
        	text(data, action, valuep, outsize);
        	this_size = size;
        	outputp = output[HEX];
        }
    }

    aes_operation[action](&ctx, valuep);

    printf("\nRESULT:\n");

	int i = 0;
    while (i != this_size)
    {
    	fprintf(stdout, outputp, valuep[i]);
        i++;
    }

    my_exit(X_SUCCESS);
}

int main(int argc, char *argv[])
{
    //fprintf (stdout, "\r\nAESCrypto %s, a AES256 ECB de/encryption tool\r\n\r\n", version);
    charptr = argv[0];
    data.type_of_message = MESSAGE_INVALID;

    char op;
    while ((op = getopt(argc, argv, "hdek:x:m:")) != EOF)
    {
      switch (op) {
        case 'h':
          printhelp();
          my_exit(X_SUCCESS);
          break;
        case 'd':
          input_validity.operation = DECRYPT;
          break;
        case 'e':
          input_validity.operation = ENCRYPT;
          break;
        case 'k':
          input_validity.has_key = STATUS_OK;
          if (strlen(optarg) == 32)
          {
            data.aes_key = (uint8_t*)optarg;
          } else
          {
            my_exit(X_WRONGKEY);
          }

          break;
        case 'x':
          input_validity.has_message = STATUS_OK;
          data.aes_message = optarg;
          if (data.type_of_message == MESSAGE_INVALID)
          {
            data.type_of_message = MESSAGE_HEX;
          } else
          {
            my_exit(X_FAILARGS);
          }
          break;
        case 'm':
          input_validity.has_message = STATUS_OK;
          data.aes_message = optarg;
          if (data.type_of_message == MESSAGE_INVALID)
          {
            data.type_of_message = MESSAGE_TEXT;
          } else
          {
            my_exit(X_FAILARGS);
          }
          break;
        default:
          my_exit(X_FAILARGS);
          break;
      }

    }
    argc -= optind;
    //argv += optind;

    // if there is any more arguments, return error
    if (argc)
    {
      charptr = argv[optind];
      my_exit(X_WRONGNUMBEROFARGUMENTS);
    }

    if (input_validity.operation < FAULT)
    {
      my_action(data, input_validity.operation);
    }
    //If reached this point, then there is a fault operation
    my_exit(X_FAILARGS);
    return EXIT_SUCCESS;				// Non reachable code, used to avoid warnings
}
