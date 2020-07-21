#include "radarengine.h"

#include <math.h>
#include <unistd.h>

RadarState state_radar = RADAR_OFF;
ReportFilter filter;
ReportAlign align;
ReportScanSignal scanSignal;
RadarSettings radar_settings;
ARPASettings arpa_settings;
GZSettings gz_settings;
TrailSettings trail_settings;
ADSBSettings adsb_settings;

double currentOwnShipLat;
double currentOwnShipLon;
double radarHeading;
double currentHeading;
bool headingUp;
bool gps_auto;
bool hdg_auto;

bool enable_mti;
int mti_value;

P2CLookupTable *lookupTable = 0;
P2CLookupTable* GetP2CLookupTable()
{
    if (!lookupTable)
    {
        lookupTable = (P2CLookupTable*)malloc(sizeof(P2CLookupTable));

        if (!lookupTable)
        {
            qDebug()<<Q_FUNC_INFO<<"Out Of Memory, fatal!";
            exit(1);
        }

        for (int arc = 0; arc < LINES_PER_ROTATION + 1; arc++)
        {
            GLfloat sine = cosf((GLfloat)arc * PI * 2 / LINES_PER_ROTATION);
            GLfloat cosine = sinf((GLfloat)arc * PI * 2 / LINES_PER_ROTATION);
            for (int radius = 0; radius < RETURNS_PER_LINE + 1; radius++)
            {
                lookupTable->x[arc][radius] = (GLfloat)radius * cosine/RETURNS_PER_LINE;
                lookupTable->y[arc][radius] = (GLfloat)radius * sine/RETURNS_PER_LINE;
//                qDebug()<<Q_FUNC_INFO<<"x "<<lookupTable->x[arc][radius]<<"y "<<lookupTable->y[arc][radius];
            }
        }
    }
    return lookupTable;
}


/********************************encrypt*****************************/
bool valid = false;
// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES128 encryption in CBC-mode of operation and handles 0-padding.
// ECB enables the basic ECB 16-byte block algorithm. Both can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#if defined(ECB) && ECB

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t *output);
void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output);

#endif // #if defined(ECB) && ECB


#if defined(CBC) && CBC

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);
void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv);

#endif // #if defined(CBC) && CBC

QString encodeText(const QString &rawText) ;
QString decodeText(QString hexEncodedText) ;

/*

This is an implementation of the AES128 algorithm, specifically ECB and CBC mode.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <stdint.h>
#include <string.h> // CBC mode, for memset
//#include "aes.h"


/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES128-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif


/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* state;

// The array that stores the round keys.
static uint8_t RoundKey[176];

// The Key input to the AES Program
static const uint8_t* Key;

#if defined(CBC) && CBC
  // Initial Vector used only for CBC mode
  static uint8_t* Iv;
#endif

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };


// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
static const uint8_t Rcon[255] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}

static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(void)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for(i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for(; (i < (Nb * (Nr + 1))); ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      tempa[j]=RoundKey[(i-1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i/Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(void)
{
  uint8_t i, j;
  for(i = 0; i < 4; ++i)
  {
    for(j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(void)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp       = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp       = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(void)
{
  uint8_t i;
  uint8_t Tmp,Tm,t;
  for(i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(void)
{
  int i;
  uint8_t a,b,c,d;
  for(i=0;i<4;++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(void)
{
  uint8_t i,j;
  for(i=0;i<4;++i)
  {
    for(j=0;j<4;++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(void)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp=(*state)[3][1];
  (*state)[3][1]=(*state)[2][1];
  (*state)[2][1]=(*state)[1][1];
  (*state)[1][1]=(*state)[0][1];
  (*state)[0][1]=temp;

  // Rotate second row 2 columns to right
  temp=(*state)[0][2];
  (*state)[0][2]=(*state)[2][2];
  (*state)[2][2]=temp;

  temp=(*state)[1][2];
  (*state)[1][2]=(*state)[3][2];
  (*state)[3][2]=temp;

  // Rotate third row 3 columns to right
  temp=(*state)[0][3];
  (*state)[0][3]=(*state)[1][3];
  (*state)[1][3]=(*state)[2][3];
  (*state)[2][3]=(*state)[3][3];
  (*state)[3][3]=temp;
}


// Cipher is the main function that encrypts the PlainText.
static void Cipher(void)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < Nr; ++round)
  {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(round);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);
}

static void InvCipher(void)
{
  uint8_t round=0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round=Nr-1;round>0;round--)
  {
    InvShiftRows();
    InvSubBytes();
    AddRoundKey(round);
    InvMixColumns();
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows();
  InvSubBytes();
  AddRoundKey(0);
}

static void BlockCopy(uint8_t* output, uint8_t* input)
{
  uint8_t i;
  for (i=0;i<KEYLEN;++i)
  {
    output[i] = input[i];
  }
}



/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && ECB


void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output)
{
  // Copy input to output, and work in-memory on output
  BlockCopy(output, input);
  state = (state_t*)output;

  Key = key;
  KeyExpansion();

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher();
}

void AES128_ECB_decrypt(uint8_t* input, const uint8_t* key, uint8_t *output)
{
  // Copy input to output, and work in-memory on output
  BlockCopy(output, input);
  state = (state_t*)output;

  // The KeyExpansion routine must be called before encryption.
  Key = key;
  KeyExpansion();

  InvCipher();
}


#endif // #if defined(ECB) && ECB





#if defined(CBC) && CBC


static void XorWithIv(uint8_t* buf)
{
  uint8_t i;
  for(i = 0; i < KEYLEN; ++i)
  {
    buf[i] ^= Iv[i];
  }
}

void AES128_CBC_encrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  uintptr_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

  BlockCopy(output, input);
  state = (state_t*)output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  if(iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for(i = 0; i < length; i += KEYLEN)
  {
    XorWithIv(input);
    BlockCopy(output, input);
    state = (state_t*)output;
    Cipher();
    Iv = output;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    BlockCopy(output, input);
    memset(output + remainders, 0, KEYLEN - remainders); /* add 0-padding */
    state = (state_t*)output;
    Cipher();
  }
}

void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* iv)
{
  uintptr_t i;
  uint8_t remainders = length % KEYLEN; /* Remaining bytes in the last non-full block */

  BlockCopy(output, input);
  state = (state_t*)output;

  // Skip the key expansion if key is passed as 0
  if(0 != key)
  {
    Key = key;
    KeyExpansion();
  }

  // If iv is passed as 0, we continue to encrypt without re-setting the Iv
  if(iv != 0)
  {
    Iv = (uint8_t*)iv;
  }

  for(i = 0; i < length; i += KEYLEN)
  {
    BlockCopy(output, input);
    state = (state_t*)output;
    InvCipher();
    XorWithIv(output);
    Iv = input;
    input += KEYLEN;
    output += KEYLEN;
  }

  if(remainders)
  {
    BlockCopy(output, input);
    memset(output+remainders, 0, KEYLEN - remainders); /* add 0-padding */
    state = (state_t*)output;
    InvCipher();
  }
}

const uint8_t iv[] = { 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96,
                       0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x5e, 0xaf };

inline int getAlignedSize(int currSize, int alignment) {
    int padding = (alignment - currSize % alignment) % alignment;
    return currSize + padding;
}

QStringList keyList = QString("abadiku3abadimu1,"
                            "warning: GDB: Failed to set controlling terminal: Inappropriate ioctl for device,"
                            "#define the macros below to 1/0 to enable/disable the mode of operation"
                              "inline int getAlignedSize(int currSize, int alignment) {"
                              "QString encodeText(const QString &rawText)"
                              "onst uint8_t iv[] = { 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96,"
                              "S3P4gtme7lJMcKwCRmOeivaPyAXCjdzXKoLWqNo8DwTuiH0OXcYR0w/b9Rub++YP@1~89%$#BD6@1~89%$#BD5"
                              "readline  ID_SERIAL=ST500DM002-1BD142_S2AQFSHC"
                              "QSettings source(QString(/usr/share/MIT/OSD/radar_settings.ini),QSettings::IniFormat);"
                              "void AES128_CBC_decrypt_buffer(uint8_t* output, uint8_t* input, uint32_t length, const uint8_t* key, const uint8_t* i"
                              ).split(",");

QString encodeText(const QString &rawText)
{
    /*set random number and key num*/
    srand(time(NULL));
    int curKeyNum = rand()%10;
    QString key = keyList.at(curKeyNum);


    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(key.toUtf8());
    QByteArray keyData = hash.result();

    const ushort *rawData = rawText.utf16();
    void *rawDataVoid = (void*)rawData;
    const char *rawDataChar = static_cast<const char *>(rawDataVoid);
    QByteArray inputData;
        // ushort is 2*uint8_t + 1 byte for '\0'
    inputData.append(rawDataChar, rawText.size() * 2 + 1);

    const int length = inputData.size();
    int encryptionLength = getAlignedSize(length, 16);

    QByteArray encodingBuffer(encryptionLength, 0);
    inputData.resize(encryptionLength);

    AES128_CBC_encrypt_buffer((uint8_t*)encodingBuffer.data(), (uint8_t*)inputData.data(),
                              encryptionLength, (const uint8_t*)keyData.data(), iv);

    QByteArray data(encodingBuffer.data(), encryptionLength);
    QString hex = QString::fromLatin1(data.toHex());
    return hex.append(QString::number(curKeyNum));
}

QString decodeText(QString hexEncodedText)
{
    /*set random number and key num*/
    int curKeyNum = QString(hexEncodedText.at(hexEncodedText.size()-1)).toInt();
    QString key = keyList.at(curKeyNum);
    hexEncodedText.remove(hexEncodedText.size()-1,1);

    QCryptographicHash hash(QCryptographicHash::Md5);
    hash.addData(key.toUtf8());
    QByteArray keyData = hash.result();

    const int length = hexEncodedText.size();
    int encryptionLength = getAlignedSize(length, 16);

    QByteArray encodingBuffer(encryptionLength, 0);

    QByteArray encodedText = QByteArray::fromHex(hexEncodedText.toLatin1());
    encodedText.resize(encryptionLength);

    AES128_CBC_decrypt_buffer((uint8_t*)encodingBuffer.data(), (uint8_t*)encodedText.data(),
                              encryptionLength, (const uint8_t*)keyData.data(), iv);

    void *data = encodingBuffer.data();
    const ushort *decodedData = static_cast<const ushort *>(data);
    QString result = QString::fromUtf16(decodedData);
    return result;
}

#endif // #if defined(CBC) && CBC

bool checkHddId()
{
    /**
     * Check HDD ID for security reason.
     */

    // get HDD ID from file system
    QFile file( "/var/log/udev" );
    if( file.open( QIODevice::ReadOnly ) )
    {
        QTextStream fileStream( &file );
        QString hddID;

        while( !fileStream.atEnd() )
        {
            QStringList readList;
            QString buffer = fileStream.readLine();

            // if HDD ID found
            if( buffer.contains( "ID_SERIAL=" ) )
            {
                readList.append( buffer );
            }

            if( readList.size() > 0 )
                hddID = readList.last();
        }

        qDebug() << "HDD ID: " << hddID;
        qDebug() << "HDD ID: " << encodeText( hddID );

        file.close();
        file.setFileName( QDir::homePath()+"/.simrad/cryptSIMRAD.ini" );

        if( !file.open( QIODevice::ReadOnly ) )
        {
//            qDebug()<<QApplication::applicationDirPath();
            file.setFileName(QString(QApplication::applicationDirPath()+"/cryptSIMRAD.ini"));
            if(!file.open(QIODevice::ReadOnly))
            {
                qDebug() << " verif not found!";
                return false;
            }
        }

        fileStream.setDevice( &file );

        QString idGuard = fileStream.readLine();

        idGuard = decodeText(idGuard);

        qDebug() << "HDD Guard: " << idGuard;

        if( hddID == idGuard )
        {
            qDebug() << " Accepted";
            return true;
        }
        else
        {
            qDebug() << "HDD ID not valid!";
            return false;
        }
    }
    else
        return false;
}



/****************************kalman*********************************/
KalmanFilter::KalmanFilter(QObject *parent) :
    QObject(parent)
{
    I = I.Identity();
    Q = ZeroMatrix2;
    R = ZeroMatrix2;

    ResetFilter();
    qDebug()<<Q_FUNC_INFO;
}
void KalmanFilter::ResetFilter() {
  // reset the filter to use  it for a new case
  A = I;

  // transpose of A
  AT = A;

  // Jacobian matrix of partial derivatives dfi / dwj
  W = ZeroMatrix42;
  W(2, 0) = 1.;
  W(3, 1) = 1.;

  // transpose of W
  WT = ZeroMatrix24;
  WT(0, 2) = 1.;
  WT(1, 3) = 1.;

  // Observation matrix, jacobian of observation function h
  // dhi / dvj
  // angle = atan2 (lat,lon) * 2048 / (2 * pi) + v1
  // r = sqrt(x * x + y * y) + v2
  // v is measurement noise
  H = ZeroMatrix24;

  // Transpose of observation matrix
  HT = ZeroMatrix42;

  // Jacobian V, dhi / dvj
  // As V is the identity matrix, it is left out of the calculation of the Kalman gain

  // P estimate error covariance
  // initial values follow
  // P(1, 1) = .0000027 * range * range;   ???
  P = ZeroMatrix4;
  P(0, 0) = 20.;
  P(1, 1) = P(1, 1);
  P(2, 2) = 4.;
  P(3, 3) = 4.;

  // Q Process noise covariance matrix
  Q(0, 0) = NOISE;  // variance in lat speed, (m / sec)2
  Q(1, 1) = NOISE;  // variance in lon speed, (m / sec)2

  // R measurement noise covariance matrix
  R(0, 0) = 100.0;  // variance in the angle 3.0
  R(1, 1) = 25.;    // variance in radius  .5
}

void KalmanFilter::Predict(LocalPosition* xx, double delta_time) {
  Matrix<double, 4, 1> X;
  X(0, 0) = xx->lat;
  X(1, 0) = xx->lon;
  X(2, 0) = xx->dlat_dt;
  X(3, 0) = xx->dlon_dt;
  A(0, 2) = delta_time;  // time in seconds
  A(1, 3) = delta_time;
  /*
  qDebug()<<Q_FUNC_INFO<<"xx lat"<<X(0, 0)<<"xx lon"<<X(1, 0)
         <<"ddlat "<<X(2, 0)<<"dlon"<<X(3, 0)
        <<"A(0, 0)"<<A(0, 0)<<"A(0, 1)"<<A(0, 1)<<"A(0, 2)"<<A(0, 2)
          <<"A(0, 3)"<<A(0, 3);
  */

  AT(2, 0) = delta_time;
  AT(3, 1) = delta_time;

  X = A * X;
  xx->lat = X(0, 0);
  xx->lon = X(1, 0);
  xx->dlat_dt = X(2, 0);
  xx->dlon_dt = X(3, 0);
  xx->sd_speed_m_s = sqrt((P(2, 2) + P(3, 3)) / 2.);
  return;
}

void KalmanFilter::Update_P() {
  // calculate apriori P
  // separated from the predict to prevent the update being done both in pass 1 and pass2

  P = A * P * AT + W * Q * WT;
  return;
}
void KalmanFilter::SetMeasurement(Polar* pol, LocalPosition* x, Polar* expected, int range) {
// pol measured angular position
// x expected local position
// expected, same but in polar coordinates
#define SQUARED(x) ((x) * (x))
  double q_sum = SQUARED(x->lon) + SQUARED(x->lat);

  double c = 2048. / (2. * PI);
  H(0, 0) = -c * x->lon / q_sum;
  H(0, 1) = c * x->lat / q_sum;

  q_sum = sqrt(q_sum);
  H(1, 0) = x->lat / q_sum * 512. / (double)range;
  H(1, 1) = x->lon / q_sum * 512. / (double)range;

  HT = H.Transpose();

  Matrix<double, 2, 1> Z;
  Z(0, 0) = (double)(pol->angle - expected->angle);  // Z is  difference between measured and expected
  if (Z(0, 0) > LINES_PER_ROTATION / 2) {
    Z(0, 0) -= LINES_PER_ROTATION;
  }
  if (Z(0, 0) < -LINES_PER_ROTATION / 2) {
    Z(0, 0) += LINES_PER_ROTATION;
  }
  Z(1, 0) = (double)(pol->r - expected->r);

  Matrix<double, 4, 1> X;
  X(0, 0) = x->lat;
  X(1, 0) = x->lon;
  X(2, 0) = x->dlat_dt;
  X(3, 0) = x->dlon_dt;

  // calculate Kalman gain
  K = P * HT * ((H * P * HT + R).Inverse());

  // calculate apostriori expected position
  X = X + K * Z;
  x->lat = X(0, 0);
  x->lon = X(1, 0);
  x->dlat_dt = X(2, 0);
  x->dlon_dt = X(3, 0);

  // update covariance P
  P = (I - K * H) * P;
  x->sd_speed_m_s = sqrt((P(2, 2) + P(3, 3)) / 2.);  // rough approximation of standard dev of speed
  return;
}




/*****************************receive data class*********************************/
#define HEADING_TRUE_FLAG 0x4000
#define HEADING_MASK (SPOKES - 1)
#define HEADING_VALID(x) (((x) & ~(HEADING_TRUE_FLAG | HEADING_MASK)) == 0)

struct RadarReport_01C4_18
{  // 01 C4 with length 18
    UINT8 what;                 // 0   0x01
    UINT8 command;              // 1   0xC4
    UINT8 radar_status;         // 2
    UINT8 field3;               // 3
    UINT8 field4;               // 4
    UINT8 field5;               // 5
    UINT16 field6;              // 6-7
    UINT16 field8;              // 8-9
    UINT16 field10;             // 10-11
};
struct RadarReport_02C4_99
{     // length 99
    UINT8 what;                    // 0   0x02
    UINT8 command;                 // 1 0xC4
    UINT32 range;                  //  2-3   0x06 0x09
    UINT16 field4;                 // 6-7    0
    UINT32 field8;                 // 8-11   1
    UINT8 gain;                    // 12
    UINT8 field13;                 // 13  ==1 for sea auto
    UINT8 field14;                 // 14
    UINT16 field15;                // 15-16
    UINT32 sea;                    // 17-20   sea state (17)
    UINT8 field21;                 // 21
    UINT8 rain;                    // 22   rain clutter
    UINT8 field23;                 // 23
    UINT32 field24;                // 24-27
    UINT32 field28;                // 28-31
    UINT8 field32;                 // 32
    UINT8 field33;                 // 33
    UINT8 interference_rejection;  // 34
    UINT8 field35;                 // 35
    UINT8 field36;                 // 36
    UINT8 field37;                 // 37
    UINT8 target_expansion;        // 38
    UINT8 field39;                 // 39
    UINT8 field40;                 // 40
    UINT8 field41;                 // 41
    UINT8 target_boost;            // 42
};

struct RadarReport_03C4_129
{
    UINT8 what;
    UINT8 command;
    UINT8 radar_type;  //01 = 4G, 08 = 3G, 0F = BR24
    UINT8 u00[55];     // Lots of unknown
    UINT16 firmware_date[16];
    UINT16 firmware_time[16];
    UINT8 u01[7];
};

struct RadarReport_04C4_66
{  // 04 C4 with length 66
    UINT8 what;                 // 0   0x04
    UINT8 command;              // 1   0xC4
    UINT32 field2;              // 2-5
    UINT16 bearing_alignment;   // 6-7
    UINT16 field8;              // 8-9
    UINT16 antenna_height;      // 10-11
};

struct RadarReport_08C4_18
{           // 08 c4  length 18
    UINT8 what;                          // 0  0x08
    UINT8 command;                       // 1  0xC4
    UINT8 field2;                        // 2
    UINT8 local_interference_rejection;  // 3
    UINT8 scan_speed;                    // 4
    UINT8 sls_auto;                      // 5
    UINT8 field6;                        // 6
    UINT8 field7;                        // 7
    UINT8 field8;                        // 8
    UINT8 side_lobe_suppression;         // 9
    UINT16 field10;                      // 10-11
    UINT8 noise_rejection;               // 12    noise rejection
    UINT8 target_sep;                    // 13
};

struct common_header
{
    UINT8 headerLen;       // 1 bytes
    UINT8 status;          // 1 bytes
    UINT8 scan_number[2];  // 2 bytes, 0-4095
    UINT8 u00[4];          // 4 bytes
    UINT8 angle[2];        // 2 bytes
    UINT8 heading[2];      // 2 bytes heading with RI-10/11. See bitmask explanation above.
};

struct br4g_header
{
    UINT8 headerLen;       // 1 bytes
    UINT8 status;          // 1 bytes
    UINT8 scan_number[2];  // 2 bytes, 0-4095
    UINT8 u00[2];          // Always 0x4400 (integer)
    UINT8 largerange[2];   // 2 bytes or -1
    UINT8 angle[2];        // 2 bytes
    UINT8 heading[2];      // 2 bytes heading with RI-10/11 or -1. See bitmask explanation above.
    UINT8 smallrange[2];   // 2 bytes or -1
    UINT8 rotation[2];     // 2 bytes, rotation/angle
    UINT8 u02[4];          // 4 bytes signed integer, always -1
    UINT8 u03[4];          // 4 bytes signed integer, mostly -1 (0x80 in last byte) or 0xa0 in last byte
};                       /* total size = 24 */
struct radar_line
{
    union
    {
        common_header common;
        br4g_header br4g;
    };
    UINT8 data[RETURNS_PER_LINE];
};
struct radar_frame_pkt
{
    UINT8 frame_hdr[8];
    radar_line line[120];  //  scan lines, or spokes
};

RadarReceive::RadarReceive(QObject *parent) :
    QThread(parent)
{
//    if(!checkHddId())
//        exit(1);

    exit_req = false;

}
RadarReceive::~RadarReceive()
{
}
void RadarReceive::exitReq()
{
    mutex.lock();
    exit_req = true;
    mutex.unlock();
}
void RadarReceive::setMulticastData(QString addr, uint port)
{
    _data = addr;
    _data_port = port;
}
void RadarReceive::setMulticastReport(QString addr, uint port)
{
    _report = addr;
    _report_port = port;
}

void RadarReceive::run()
{
    qDebug()<<Q_FUNC_INFO;
    QUdpSocket socketDataReceive;
    QUdpSocket socketReportReceive;
    QString data_thread = _data;
    QString report_thread = _report;
    uint data_port_thread = _data_port;
    uint reportport_thread = _report_port;
    exit_req = false;

    QHostAddress groupAddress = QHostAddress(data_thread);
    if(socketDataReceive.bind(QHostAddress::AnyIPv4,data_port_thread, QUdpSocket::ShareAddress))
    {
        socketDataReceive.joinMulticastGroup(groupAddress);
        qDebug()<<Q_FUNC_INFO<<"bind data multicast access succesed";
    }
    groupAddress = QHostAddress(report_thread);
    if(socketDataReceive.bind(QHostAddress::AnyIPv4,reportport_thread, QUdpSocket::ShareAddress))
    {
        socketDataReceive.joinMulticastGroup(groupAddress);
        qDebug()<<Q_FUNC_INFO<<"bind report multicast access succesed";
    }

    while(!exit_req)
    {
        if(socketDataReceive.state()==QAbstractSocket::BoundState)
        {
//            qDebug()<<Q_FUNC_INFO<<"socketDataReceive.state()==QAbstractSocket::BoundState ";
            while (socketDataReceive.hasPendingDatagrams())
            {
                QByteArray datagram;
                datagram.resize(socketDataReceive.pendingDatagramSize());
                socketDataReceive.readDatagram(datagram.data(), datagram.size());

                processFrame(datagram,datagram.size());
                //                qDebug()<<Q_FUNC_INFO<<"Receive datagram with size "<<datagram.size();
            }
        }
        else
        {
            groupAddress = QHostAddress(data_thread);
            if(socketDataReceive.bind(QHostAddress::AnyIPv4,data_port_thread, QUdpSocket::ShareAddress))
            {
                socketDataReceive.joinMulticastGroup(groupAddress);
                qDebug()<<Q_FUNC_INFO<<"bind data multicast access succesed";
            }
            else
            {
                qDebug()<<Q_FUNC_INFO<<"bind data access failed "<<socketDataReceive.errorString();
            }

        }

        if(socketReportReceive.state()==QAbstractSocket::BoundState)
        {
            while (socketReportReceive.hasPendingDatagrams())
            {
                QByteArray datagram;
                datagram.resize(socketReportReceive.pendingDatagramSize());
                socketReportReceive.readDatagram(datagram.data(), datagram.size());

                processReport(datagram,datagram.size());
                qDebug()<<Q_FUNC_INFO<<"Receive datagram report with size "<<datagram.size();
            }
        }
        else
        {
            groupAddress = QHostAddress(report_thread);
            if(socketReportReceive.bind(QHostAddress::AnyIPv4,reportport_thread, QUdpSocket::ShareAddress))
            {
                socketReportReceive.joinMulticastGroup(groupAddress);
                qDebug()<<Q_FUNC_INFO<<"bind report multicast access succesed";
            }
            else
            {
                qDebug()<<Q_FUNC_INFO<<"bind report access failed "<<socketReportReceive.errorString();
            }

        }

        msleep(5);
    }
    qDebug()<<Q_FUNC_INFO<<"radar receive terminated";

}
void RadarReceive::processReport(QByteArray data, int len)
{
    qDebug()<<Q_FUNC_INFO;

    const UINT8 *report =  (const UINT8*)data.constData();
    if (report[1] == 0xC4)
    {
        switch ((len << 8) + report[0])
        {
        case (18 << 8) + 0x01:
        {  //  length 18, 01 C4
            RadarReport_01C4_18 *s = (RadarReport_01C4_18 *)report;
            // Radar status in byte 2
            if (s->radar_status != 0)
            {
                switch (report[2])
                {
                case 0x01:
                    emit updateReport(0,1,0);
                    break;
                case 0x02:
                    emit updateReport(0,2,0);
                    break;
                case 0x05:
                    emit updateReport(0,3,0);
                    break;
                default:
                    break;
                }
            }
            break;
        }

        case (99 << 8) + 0x02:
        {  // length 99, 02 C4
            RadarReport_02C4_99 *s = (RadarReport_02C4_99 *)report;
            if (s->field8 == 1) //auto
                emit updateReport(1,0,0);
            else
            {
                s->gain = s->gain !=0 ? s->gain : 1;
                emit updateReport(1,0,s->gain);
            }

            emit updateReport(1,1,s->rain);
            if (s->field13 == 0x01) //auto
                emit updateReport(1,2,0);
            else
            {
                s->sea = s->sea !=0 ? s->sea : 1;
                emit updateReport(1,2,s->sea);
            }
            emit updateReport(1,3,s->target_boost);
            emit updateReport(1,4,s->interference_rejection);
            emit updateReport(1,5,s->target_expansion);
            emit updateReport(1,6,s->range/10);
            break;
        }

        case (66 << 8) + 0x04:
        {  // 66 bytes starting with 04 C4
            RadarReport_04C4_66 *data = (RadarReport_04C4_66 *)report;

            emit updateReport(3,0,data->bearing_alignment);
            emit updateReport(3,1,data->antenna_height);
            break;
        }
        case (18 << 8) + 0x08:
        {  // length 18, 08 C4
            // contains scan speed, noise rejection and target_separation and sidelobe suppression
            RadarReport_08C4_18 *s08 = (RadarReport_08C4_18 *)report;

            emit updateReport(4,0,s08->scan_speed);
            emit updateReport(4,1,s08->noise_rejection);
            emit updateReport(4,2,s08->target_sep);
            emit updateReport(4,4,s08->local_interference_rejection);

            if (s08->sls_auto == 1)
            {
                emit updateReport(4,3,0);
            }
            else
            {
                s08->side_lobe_suppression = s08->side_lobe_suppression != 0 ?
                            s08->side_lobe_suppression : 1;
                emit updateReport(4,3,s08->side_lobe_suppression);
            }
            break;
        }
        default:
        {
            qDebug()<<Q_FUNC_INFO<<"receive unknown report. size"<<len;
            break;
        }
        }
        return ;
    }
}

void RadarReceive::processFrame(QByteArray data, int len)
{
    radar_frame_pkt *packet = (radar_frame_pkt *)data.data();

    if (len < (int)sizeof(packet->frame_hdr)) {
        return;
    }

    int scanlines_in_packet = (len - sizeof(packet->frame_hdr)) / sizeof(radar_line);
    if (scanlines_in_packet != 32)
    {
        qDebug()<<Q_FUNC_INFO<<"broken packet";
    }

    for (int scanline = 0; scanline < scanlines_in_packet; scanline++)
    {
        radar_line *line = &packet->line[scanline];

        // Validate the spoke
        if (line->common.headerLen != 0x18)
        {
            qDebug()<<Q_FUNC_INFO<<"strange header length "<<line->common.headerLen;
            continue;
        }
        if (line->common.status != 0x02 && line->common.status != 0x12)
        {
            qDebug()<<Q_FUNC_INFO<<"strange header status "<<line->common.status;
        }

        int range_raw = 0;
        int angle_raw = 0;
        short int heading_raw = 0;
        int range_meters = 0;

        heading_raw = (line->common.heading[1] << 8) | line->common.heading[0];

        short int large_range = (line->br4g.largerange[1] << 8) | line->br4g.largerange[0];
        short int small_range = (line->br4g.smallrange[1] << 8) | line->br4g.smallrange[0];
        angle_raw = (line->br4g.angle[1] << 8) | line->br4g.angle[0];

        /* tapping result
             * tx : 100 -> rec : 176/2c0
             * tx : 250 -> rec : 439/6dc
             * tx : 500 -> rec : 879/dbc
             * tx : 750 -> rec : 2029/1498
             * tx : 1 km -> rec : 2841
             * tx : 1.5 km -> rec :  4057
             * tx : 2 km -> rec :  3514
             * tx : 3 km -> rec :  8285
             * tx : 4 km -> rec :  9940
             * tx : 6 km -> rec :  16538
             * tx : 8 km -> rec :  21263 large range?
             * tx : 12 km-> rec :  31950 large range?
             * tx : 16 km-> rec :  -19411 large range?
             * tx : 24 km-> rec :  -1636 large range?
             * tx : 36     -> rec :  -2255 large range?
             * tx : 48 km -> rec :  -23349 large range?
             * tx : 64 km-> rec :  -9286 large range?
             * tx : 72 km-> rec :  -2255 large range?
             * tx : 96 km-> rec :  -23349 large range?

      from lib plugin
      if (large_range == 0x80) {
        if (small_range == -1) {
          range_raw = 0;  // Invalid range received
        } else {
          range_raw = small_range;
        }
      } else {
        range_raw = large_range * 256;
      }
      range_meters = range_raw / 4;

*/
        if (large_range == 0x80)
        {
            if (small_range == -1)
            {
                range_raw = 0;  // Invalid range received
            }
            else
            {
                range_raw = small_range/4;
            }
        }
        else
        {
            range_raw = large_range;
        }
        range_meters = range_raw;
//        range_meters *= 0.5688;
//        qDebug()<<Q_FUNC_INFO<<range_raw;

        bool radar_heading_valid = HEADING_VALID(heading_raw);
        bool radar_heading_true = (heading_raw & HEADING_TRUE_FLAG) != 0;
        double heading = -400;

        if (radar_heading_valid)
        {
            heading = MOD_DEGREES(SCALE_RAW_TO_DEGREES(MOD_ROTATION(heading_raw)));
        }
        else
        {
            // no heading on radar
            //          qDebug()<<Q_FUNC_INFO<<"no heading on radar "<<heading;
        }

        const char *data_p = (const char *)line->data;
        QByteArray raw_data = QByteArray(data_p,512);
        //      qDebug()<<Q_FUNC_INFO<<"sizeof data "<<sizeof(line->data)<<"size data array"<<raw_data.size();
        emit ProcessRadarSpoke(angle_raw,
                               raw_data,
                               RETURNS_PER_LINE,
                               range_meters,
                               heading,
                               radar_heading_true);
    }
}





/**********radar info*************/
#define STAYALIVE_TIMEOUT (5000)  // Send data every 5 seconds to ping radar
#define DATA_TIMEOUT (5000)
#define MARGIN (100)
#define TRAILS_SIZE (RETURNS_PER_LINE * 2 + MARGIN * 2)

enum {
    TRAIL_15SEC, //6 rev
    TRAIL_30SEC, //12 rev
    TRAIL_1MIN,  //24 rev
    TRAIL_3MIN,  //72 rev
    TRAIL_5MIN, //120 rev
    TRAIL_10MIN, //240 rev
    TRAIL_CONTINUOUS,
    TRAIL_ARRAY_SIZE
};
GLubyte old_strength_info[2048][512];
GLubyte new_strength_info[2048][512];

RI::RI(QObject *parent) :
    QObject(parent)
{
//    if(!checkHddId())
//        exit(1);

    radar_timeout = 0;
    m_range_meters = 0;
    //    draw_trails = false; //next implementation load from conf file

    old_draw_trails = trail_settings.enable;
    old_trail = trail_settings.trail;

    ComputeColourMap();
    ComputeTargetTrails();

    timer = new QTimer(this);
    connect(timer,SIGNAL(timeout()),this,SLOT(timerTimeout()));

    m_gz = new GZ(this);

    receiveThread = new RadarReceive(this);
    connect(receiveThread,SIGNAL(updateReport(quint8,quint8,quint32)),
            this,SLOT(receiveThread_Report(quint8,quint8,quint32)));
    connect(receiveThread,SIGNAL(ProcessRadarSpoke(int,QByteArray,int,int,double,bool)),
            this,SLOT(radarReceive_ProcessRadarSpoke(int,QByteArray,int,int,double,bool)));

    timer->start(1000);
}
void RI::timerTimeout()
{
    quint64 now = QDateTime::currentMSecsSinceEpoch();

    if(state_radar == RADAR_TRANSMIT && TIMED_OUT(now,data_timeout))
    {
        state_radar = RADAR_STANDBY;
        ResetSpokes();
    }
    if(state_radar == RADAR_TRANSMIT && TIMED_OUT(now,stay_alive_timeout))
    {
        emit signal_stay_alive();
        stay_alive_timeout = now + STAYALIVE_TIMEOUT;
    }
    if(state_radar == RADAR_STANDBY && TIMED_OUT(now,radar_timeout))
    {
        state_radar = RADAR_OFF;
        ResetSpokes();
    }

    if(old_draw_trails != trail_settings.enable)
    {
        if(!trail_settings.enable)
            ClearTrails();

        ComputeColourMap();
        ComputeTargetTrails();
        old_draw_trails = trail_settings.enable;
    }
    if(old_trail != trail_settings.trail)
    {
        ClearTrails();
        ComputeColourMap();
        ComputeTargetTrails();
        old_trail = trail_settings.trail;
    }
}

void RI::radarReceive_ProcessRadarSpoke(int angle_raw,
                                               QByteArray data,
                                               int dataSize,
                                               int range_meter,
                                               double heading,
                                               bool radar_heading_true)
{
    quint64 now = QDateTime::currentMSecsSinceEpoch();
    radar_timeout = now + WATCHDOG_TIMEOUT;
    data_timeout = now + DATA_TIMEOUT;
    state_radar = RADAR_TRANSMIT;

    radarHeading = heading;

    short int hdt_raw = radar_settings.headingUp ? 0 : SCALE_DEGREES_TO_RAW(currentHeading);
    int bearing_raw = angle_raw + hdt_raw;

    int angle = MOD_ROTATION2048(angle_raw / 2);    // divide by 2 to map on 2048 scanlines
    int bearing = MOD_ROTATION2048(bearing_raw / 2);  // divide by 2 to map on 2048 scanlines

    if(angle >= HALF_LINES_PER_ROTATION)
        angle -= HALF_LINES_PER_ROTATION;
    if(bearing >= HALF_LINES_PER_ROTATION)
        bearing -= HALF_LINES_PER_ROTATION;

    UINT8 *raw_data = (UINT8*)data.data();

    raw_data[RETURNS_PER_LINE - 1] = 200;  //  range ring, for testing

    if ((m_range_meters != range_meter))
    {
        ResetSpokes();
        qDebug()<<Q_FUNC_INFO<<"detected spoke range change from "<<m_range_meters<<" to "<<range_meter;
        int g;
        for (g = 0; g < ARRAY_SIZE(g_ranges_metric); g++)
        {
            if (g_ranges_metric[g].actual_meters == range_meter)
            {
                rng_gz = g_ranges_metric[g].meters;
                break;
            }
        }
        m_range_meters = range_meter;
        emit signal_range_change(m_range_meters);
    }

    UINT8 weakest_normal_blob = 50; //next load from configuration file
    UINT8 *hist_data = m_history[bearing].line;
    m_history[bearing].time = now;
    m_history[bearing].lat = currentOwnShipLat;
    m_history[bearing].lon = currentOwnShipLon;
    for (size_t radius = 0; radius < data.size(); radius++)
    {

        if(enable_mti)
        {
            new_strength_info[bearing][radius] = raw_data[radius];
            if(abs((int)(old_strength_info[bearing][radius] - new_strength_info[bearing][radius])) < mti_value)
                raw_data[radius]=0;
        }

        hist_data[radius] = hist_data[radius] << 1;  // shift left history byte 1 bit
        // clear leftmost 2 bits to 00 for ARPA
        hist_data[radius] = hist_data[radius] & 63;
        if (raw_data[radius] >= weakest_normal_blob)
        {
            // and add 1 if above threshold and set the left 2 bits, used for ARPA
            hist_data[radius] = hist_data[radius] | 192;
        }

        if(enable_mti)
            old_strength_info[bearing][radius] = new_strength_info[bearing][radius];
    }

    /*check Guardzone*/
    if(gz_settings.show && gz_settings.enable_alarm)
        m_gz->ProcessSpoke(angle, raw_data, m_history[bearing].line, rng_gz);


    /*Trail handler*/
    if(trail_settings.enable)
    {
        if (m_old_range != m_range_meters && m_old_range != 0 && m_range_meters != 0)
        {
            // zoom trails
            float zoom_factor = (float)m_old_range / (float)m_range_meters;
            ZoomTrails(zoom_factor);
        }
        if (m_old_range == 0 || m_range_meters == 0)
        {
            ClearTrails();
        }
        m_old_range = m_range_meters;

        // Relative trails
        UINT8 *trail = m_trails.relative_trails[angle];
        for (size_t radius = 0; radius < dataSize - 1; radius++)
        {  // len - 1 : no trails on range circle
            if (raw_data[radius] >= weakest_normal_blob)
                *trail = 1;

            else
            {
                if (*trail > 0 && *trail < TRAIL_MAX_REVOLUTIONS)
                    (*trail)++;

                raw_data[radius] = m_trail_colour[*trail];

            }
            trail++;
        }
    }

    /*trigger plot spoke*/
    emit signal_plotRadarSpoke(3, //next implemetation load from conf file
                               bearing,raw_data,dataSize);
}
void RI::ComputeTargetTrails()
{
    static TrailRevolutionsAge maxRevs[TRAIL_ARRAY_SIZE] =
    {
        SECONDS_TO_REVOLUTIONS(15),
        SECONDS_TO_REVOLUTIONS(30),
        SECONDS_TO_REVOLUTIONS(60),
        SECONDS_TO_REVOLUTIONS(180),
        SECONDS_TO_REVOLUTIONS(300),
        SECONDS_TO_REVOLUTIONS(600),
        TRAIL_MAX_REVOLUTIONS + 1
    };

    TrailRevolutionsAge maxRev = maxRevs[trail_settings.trail];
    if (!trail_settings.enable)
        maxRev = 0;


    TrailRevolutionsAge revolution;
    double coloursPerRevolution = 0.;
    double colour = 0.;

    // Like plotter, continuous trails are all very white (non transparent)
    if (trail_settings.enable && (trail_settings.trail < TRAIL_CONTINUOUS))
        coloursPerRevolution = BLOB_HISTORY_COLOURS / (double)maxRev;

    qDebug()<<Q_FUNC_INFO<<"Target trail value "<<maxRev<<"revolutions";

    // Disperse the BLOB_HISTORY values over 0..maxrev
    for (revolution = 0; revolution <= TRAIL_MAX_REVOLUTIONS; revolution++)
    {
        if (revolution >= 1 && revolution < maxRev)
        {
            m_trail_colour[revolution] = (BlobColour)(BLOB_HISTORY_0 + (int)colour);
            colour += coloursPerRevolution;
        }
        else
            m_trail_colour[revolution] = BLOB_NONE;

    }
}
void RI::ZoomTrails(float zoom_factor)
{
    // zoom relative trails
    memset(&m_trails.copy_of_relative_trails, 0, sizeof(m_trails.copy_of_relative_trails));
    for (int i = 0; i < LINES_PER_ROTATION; i++)
    {
        for (int j = 0; j < RETURNS_PER_LINE; j++)
        {
            int index_j = (int((float)j * zoom_factor));
            if (index_j >= RETURNS_PER_LINE) break;
            if (m_trails.relative_trails[i][j] != 0)
            {
                m_trails.copy_of_relative_trails[i][index_j] = m_trails.relative_trails[i][j];
            }
        }
    }
    memcpy(&m_trails.relative_trails[0][0], &m_trails.copy_of_relative_trails[0][0], sizeof(m_trails.copy_of_relative_trails));
}
void RI::ClearTrails()
{
    memset(&m_trails, 0, sizeof(m_trails));
}
void RI::ComputeColourMap()
{
    for (int i = 0; i <= UINT8_MAX; i++)
    {
        m_colour_map[i] = (i >= 200 /*red strong threshold*/) ? BLOB_STRONG
                                                              : (i >= 100 /*green strong threshold*/)
                                                                ? BLOB_INTERMEDIATE
                                                                : (i >= 50 /*blue strong threshold*/) ? BLOB_WEAK : BLOB_NONE; //next implementation load from conf file
        //        qDebug()<<Q_FUNC_INFO<<"color map "<<i<<m_colour_map[i];
    }

    for (int i = 0; i < BLOB_COLOURS; i++)
        m_colour_map_rgb[i] = QColor(0, 0, 0);

    m_colour_map_rgb[BLOB_STRONG] = Qt::red;
    m_colour_map_rgb[BLOB_INTERMEDIATE] = Qt::green;
    m_colour_map_rgb[BLOB_WEAK] = Qt::blue;

    if (trail_settings.enable)
    {
        /*
      float r1 = m_pi->m_settings.trail_start_colour.Red();
      float g1 = m_pi->m_settings.trail_start_colour.Green();
      float b1 = m_pi->m_settings.trail_start_colour.Blue();
      float r2 = m_pi->m_settings.trail_end_colour.Red();
      float g2 = m_pi->m_settings.trail_end_colour.Green();
      float b2 = m_pi->m_settings.trail_end_colour.Blue();
      */
        int r1 = 255.0;
        int g1 = 255.0;
        int b1 = 255.0;
        int r2 = 0.0;
        int g2 = 0.0;
        int b2 = 0.0;
        float delta_r = (float)((r2 - r1) / BLOB_HISTORY_COLOURS);
        float delta_g = (float)((g2 - g1) / BLOB_HISTORY_COLOURS);
        float delta_b = (float)((b2 - b1) / BLOB_HISTORY_COLOURS);


        for (BlobColour history = BLOB_HISTORY_0;
             history <= BLOB_HISTORY_MAX;
             history = (BlobColour)(history + 1))
        {
            m_colour_map[history] = history;
            m_colour_map_rgb[history] = QColor(r1, g1, b1);
            r1 += (int)delta_r;
            g1 += (int)delta_g;
            b1 += (int)delta_b;
        }
    }

}
void RI::ResetSpokes()
{
    UINT8 zap[RETURNS_PER_LINE];

    qDebug()<<Q_FUNC_INFO<<"reset spokes, history and trails";

    memset(zap, 0, sizeof(zap));
    memset(m_history, 0, sizeof(m_history));

    m_gz->ResetBogeys();

    for (size_t r = 0; r < LINES_PER_ROTATION; r++)
        emit signal_plotRadarSpoke(0,r,zap,sizeof(zap));

}
void RI::trigger_clearTrail()
{
    ClearTrails();
}
void RI::trigger_ReqRadarSetting()
{
    ResetSpokes();
    receiveThread->exitReq();
    sleep(1);
    receiveThread->setMulticastData(radar_settings.ip_data,radar_settings.port_data);
    receiveThread->setMulticastReport(radar_settings.ip_report,radar_settings.port_report);
    receiveThread->start();
}

void RI::receiveThread_Report(quint8 report_type, quint8 report_field, quint32 value)
{
    quint64 now = QDateTime::currentMSecsSinceEpoch();
    radar_timeout = now + WATCHDOG_TIMEOUT;

    switch (report_type)
    {
    case RADAR_STATE:
        switch (report_field)
        {
        case RADAR_STANDBY:
            state_radar = RADAR_STANDBY;
            qDebug()<<Q_FUNC_INFO<<"report status RADAR_STANDBY";
            break;
        case RADAR_TRANSMIT:
            state_radar = RADAR_TRANSMIT;
            qDebug()<<Q_FUNC_INFO<<"report status RADAR_TRANSMIT";
            break;
        case RADAR_WAKING_UP:
            state_radar = RADAR_WAKING_UP;
            qDebug()<<Q_FUNC_INFO<<"report status RADAR_WAKING_UP";
            break;
        default:
            break;
        }
        break;
    case RADAR_FILTER:
        switch (report_field)
        {
        case RADAR_GAIN:
            filter.gain = value;
            qDebug()<<Q_FUNC_INFO<<"report gain"<<filter.gain;
            break;
        case RADAR_RAIN:
            filter.rain = value;
            qDebug()<<Q_FUNC_INFO<<"report rain"<<filter.rain;
            break;
        case RADAR_SEA:
            filter.sea = value;
            qDebug()<<Q_FUNC_INFO<<"report sea"<<filter.sea;
            break;
        case RADAR_TARGET_BOOST:
            filter.targetBoost = value;
            qDebug()<<Q_FUNC_INFO<<"report TargetBoost"<<filter.targetBoost;
            break;
        case RADAR_LOCAL_INTERFERENCE_REJECTION:
            filter.LInterference = value;
            qDebug()<<Q_FUNC_INFO<<"report local interference"<<filter.LInterference;
            break;
        case RADAR_TARGET_EXPANSION:
            filter.targetExpan = value;
            qDebug()<<Q_FUNC_INFO<<"report argetExpan"<<filter.targetExpan;
            break;
        case RADAR_RANGE:
            filter.range = value;
            qDebug()<<Q_FUNC_INFO<<"report range"<<filter.range;
            break;
        default:
            break;
        }
        break;
    case RADAR_ALIGN:
        switch (report_field)
        {
        case RADAR_BEARING:
            // bearing alignment
            align.bearing = (int)value / 10;
            if (align.bearing > 180)
                align.bearing = align.bearing - 360;
            qDebug()<<Q_FUNC_INFO<<"report radar bearing alignment"<<align.bearing;
            break;
        case RADAR_ANTENA:
            // antenna height
            align.antena_height = value;
            qDebug()<<Q_FUNC_INFO<<"report radar antenna_height"<<align.antena_height/1000;
            break;
        default:
            break;
        }
        break;
    case RADAR_SCAN_AND_SIGNAL:
        switch (report_field)
        {
        case RADAR_SCAN_SPEED:
            scanSignal.scan_speed = value;
            qDebug()<<Q_FUNC_INFO<<"report radar scan_speed"<<scanSignal.scan_speed ;
            break;
        case RADAR_NOISE_REJECT:
            scanSignal.noise_reject = value;
            qDebug()<<Q_FUNC_INFO<<"report radar noise_reject"<<scanSignal.noise_reject ;
            break;
        case RADAR_TARGET_SEPARATION:
            scanSignal.target_sep = value;
            qDebug()<<Q_FUNC_INFO<<"report radar target_sep"<<scanSignal.target_sep ;
            break;
        case RADAR_LOBE_SUPRESION:
            scanSignal.side_lobe_suppression = value; //0->auto
            qDebug()<<Q_FUNC_INFO<<"report radar side_lobe_suppression"<<scanSignal.side_lobe_suppression ;
            break;
        case RADAR_INTERFERENT:
            scanSignal.local_interference_rejection = value;
            qDebug()<<Q_FUNC_INFO<<"report radar local_interference_rejection"<<scanSignal.local_interference_rejection ;
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}




/****************************guard zone************************************/
GZ::GZ(RI *ri)
{
//    if(!checkHddId())
//        exit(1);

    m_ri = ri;
    m_type = (GZType)(gz_settings.circle_type);
    m_start_bearing = gz_settings.start_bearing;
    m_end_bearing = gz_settings.end_bearing;
    m_inner_range = gz_settings.inner_range;
    m_outer_range = gz_settings.outer_range;
    ResetBogeys();
}

void GZ::ProcessSpoke(int angle, UINT8* data, UINT8* hist, int range)
{

    //    qDebug()<<Q_FUNC_INFO<<"inner "<<m_inner_range<<"outter "<<m_outer_range;
    size_t range_start = m_inner_range * RETURNS_PER_LINE / range / 2;  // Convert from meters to 0..511
    size_t range_end = m_outer_range * RETURNS_PER_LINE / range / 2;    // Convert from meters to 0..511
    bool in_guard_zone = false;

    if(m_inner_range != gz_settings.inner_range)
    {
        m_inner_range = gz_settings.inner_range;
        ResetBogeys();
    }
    if(m_outer_range != gz_settings.outer_range)
    {
        m_outer_range = gz_settings.outer_range;
        ResetBogeys();
    }
    if(m_start_bearing != gz_settings.start_bearing)
    {
        m_start_bearing = gz_settings.start_bearing;
        ResetBogeys();
    }
    if(m_end_bearing != gz_settings.end_bearing)
    {
        m_end_bearing = gz_settings.end_bearing;
        ResetBogeys();
    }
    if(m_type != (GZType)gz_settings.circle_type)
    {
        m_type = (GZType)gz_settings.circle_type;
        ResetBogeys();
    }

    int start_brn_2048 = SCALE_DEGREES_TO_RAW2048(m_start_bearing);
    int end_brn_2048 = SCALE_DEGREES_TO_RAW2048(m_end_bearing);

    switch (m_type)
    {
    case GZ_ARC:
        if ((angle >= start_brn_2048 && angle < end_brn_2048) ||
                (start_brn_2048 >= end_brn_2048 && (angle >= start_brn_2048 || angle < end_brn_2048)))
        {
            if (range_start < RETURNS_PER_LINE)
            {
                if (range_end > RETURNS_PER_LINE)
                    range_end = RETURNS_PER_LINE;

                for (size_t r = range_start; r <= range_end; r++)
                {
//                    uint8_t atad = data[r];
//                    if (/*!m_multi_sweep_filter ||*/ HISTORY_FILTER_ALLOW(hist[r]))
                    {
                        if (data[r] >= 50)
//                            if (data[r] >= m_ri->m_settings.threshold_blue)
                            m_running_count++;

                    }
                }
            }
            in_guard_zone = true;
        }
        break;

    case GZ_CIRCLE:
        if (range_start < RETURNS_PER_LINE)
        {
            if (range_end > RETURNS_PER_LINE)
            {
                range_end = RETURNS_PER_LINE;
            }

            for (size_t r = range_start; r <= range_end; r++)
            {
//                if (/*!m_multi_sweep_filter ||*/ HISTORY_FILTER_ALLOW(hist[r]))
                {
                    if (data[r] >= 50)
//                        if (data[r] >= m_pi->m_settings.threshold_blue)
                        m_running_count++;

                }
            }
            if (angle > m_last_angle)
                in_guard_zone = true;

        }
        break;

    default:
        in_guard_zone = false;
        break;
    }

    if (m_last_in_guard_zone && !in_guard_zone)
    {
        // last bearing that could add to m_running_count, so store as bogey_count;
        m_bogey_count = m_running_count;
        m_running_count = 0;

//        qDebug()<<Q_FUNC_INFO<<m_log_name<<"angle"<<angle<<"last_angle"<<m_last_angle<<"range"<<range<<"guardzone"<<range_start
//               <<"..."<<range_end<<"("<<m_inner_range<<"-"<<m_outer_range<<")"<<"bogey_count"<<m_bogey_count;
        // When debugging with a static ship it is hard to find moving targets, so move
        // the guard zone instead. This slowly rotates the guard zone.
        if (0 && m_type == GZ_ARC)
        {
            m_start_bearing += LINES_PER_ROTATION - 0;
            m_end_bearing += LINES_PER_ROTATION - 0;
            m_start_bearing %= LINES_PER_ROTATION;
            m_end_bearing %= LINES_PER_ROTATION;
        }
    }

    m_last_in_guard_zone = in_guard_zone;
    m_last_angle = angle;
}





/*********************arpa*************************/
#define TARGET_SEARCH_RADIUS1 (20)    // radius of target search area for pass 1 (on top of the size of the blob). configurable?
#define TARGET_SEARCH_RADIUS2 (60)   // radius of target search area for pass 1. configurable?
#define SCAN_MARGIN (150)            // number of lines that a next scan of the target may have moved
#define SCAN_MARGIN2 (1000)          // if target is refreshed after this time you will be shure it is the next sweep
#define MAX_TARGET_DIAMETER (200)    // target will be set lost if diameter larger than this value. configurable?
#define MAX_LOST_COUNT (3)           // number of sweeps that target can be missed before it is seet to lost

#define FOR_DELETION (-2)  // status of a duplicate target used to delete a target
#define LOST (-1)
#define ACQUIRE0 (0)  // 0 under acquisition, first seen, no contour yet
#define ACQUIRE1 (1)  // 1 under acquisition, contour found, first position FOUND
#define ACQUIRE2 (2)  // 2 under acquisition, speed and course taken
#define ACQUIRE3 (3)  // 3 under acquisition, speed and course verified, next time active
//    >=4  active

#define Q_NUM (4)  // status Q to OCPN at target status
#define T_NUM (6)  // status T to OCPN at target status
#define TARGET_SPEED_DIV_SDEV 2.
#define STATUS_TO_OCPN (1)            // First status to be send track info
#define START_UP_SPEED (0.5)          // maximum allowed speed (m/sec) for new target, real format with .
#define DISTANCE_BETWEEN_TARGETS (4)  // minimum separation between targets. configurable?


static int target_id_count = 0;
int m_range;


Position Polar2Pos(Polar pol, Position own_ship, double range)
{
    // The "own_ship" in the fumction call can be the position at an earlier time than the current position
    // converts in a radar image angular data r ( 0 - 512) and angle (0 - 2096) to position (lat, lon)
    // based on the own ship position own_ship
    Position pos;
    pos.lat = own_ship.lat +
            (double)pol.r / (double)RETURNS_PER_LINE * range * cos(deg2rad(SCALE_RAW_TO_DEGREES2048(pol.angle))) / 60. / 1852.;
    pos.lon = own_ship.lon +
            (double)pol.r / (double)RETURNS_PER_LINE * range * sin(deg2rad(SCALE_RAW_TO_DEGREES2048(pol.angle))) /
            cos(deg2rad(own_ship.lat)) / 60. / 1852.;
    return pos;
}

Polar Pos2Polar(Position p, Position own_ship, int range)
{
    // converts in a radar image a lat-lon position to angular data
    Polar pol;
    double dif_lat = p.lat;
    dif_lat -= own_ship.lat;
    double dif_lon = (p.lon - own_ship.lon) * cos(deg2rad(own_ship.lat));
    pol.r = (int)(sqrt(dif_lat * dif_lat + dif_lon * dif_lon) * 60. * 1852. * (double)RETURNS_PER_LINE / (double)range + 1);
    pol.angle = (int)((atan2(dif_lon, dif_lat)) * (double)LINES_PER_ROTATION / (2. * PI) + 1);  // + 1 to minimize rounding errors
    if (pol.angle < 0) pol.angle += LINES_PER_ROTATION;
    return pol;
}

RA::RA(QObject *parent,RI *ri) :
    QObject(parent),m_ri(ri)
{
//    if(!checkHddId())
//        exit(1);

    m_number_of_targets = 0;
    for (int i = 0; i < MAX_NUMBER_OF_TARGETS; i++)
        m_target[i] = 0;

}

void RA::RefreshArpaTargets()
{
    m_range = range_meters;

    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (m_target[i])
        {
            if (m_target[i]->m_status == LOST)
            {
                qDebug()<<Q_FUNC_INFO<<"lost target "<<i;
                // we keep the lost target for later use, destruction and construction is expensive
                ARPATarget* lost = m_target[i];
                int len = sizeof(ARPATarget*);
                // move rest of larget list up to keep them in sequence
                memmove(&m_target[i], &m_target[i] + 1, (m_number_of_targets - i) * len);
                m_number_of_targets--;
                // set the lost target at the last position
                m_target[m_number_of_targets] = lost;
            }
        }
    }

    int target_to_delete = -1;
    // find a target with status FOR_DELETION if it is there
    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (!m_target[i]) continue;
        if (m_target[i]->m_status == FOR_DELETION)
        {
            target_to_delete = i;
        }
    }
    if (target_to_delete != -1)
    {
        // delete the target that is closest to the target with status FOR_DELETION
        Position* deletePosition = &m_target[target_to_delete]->m_position;
        double min_dist = 1000;
        int del_target = -1;
        for (int i = 0; i < m_number_of_targets; i++)
        {
            if (!m_target[i]) continue;
            if (i == target_to_delete || m_target[i]->m_status == LOST) continue;
            double dif_lat = deletePosition->lat - m_target[i]->m_position.lat;
            double dif_lon = (deletePosition->lon - m_target[i]->m_position.lon) * cos(deg2rad(deletePosition->lat));
            double dist2 = dif_lat * dif_lat + dif_lon * dif_lon;
            if (dist2 < min_dist)
            {
                min_dist = dist2;
                del_target = i;
            }
        }
        // del_target is the index of the target closest to target with index target_to_delete
        if (del_target != -1)
        {
            qDebug()<<Q_FUNC_INFO<<"set lost closest";
            m_target[del_target]->SetStatusLost();
        }
        m_target[target_to_delete]->SetStatusLost();
    }
//    qDebug()<<Q_FUNC_INFO<<"target to delete "<<target_to_delete<<"target number"<<m_number_of_targets;

    // main target refresh loop

    // pass 1 of target refresh
    int dist = TARGET_SEARCH_RADIUS1;
    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (!m_target[i])
        {
            qDebug()<<Q_FUNC_INFO<<"BR24radar_pi:  error target non existent i="<<i;
            continue;
        }
        m_target[i]->m_pass_nr = PASS1;
        if (m_target[i]->m_pass1_result == NOT_FOUND_IN_PASS1) continue;
        m_target[i]->RefreshTarget(dist);
        /*
        if (m_target[i]->m_pass1_result == NOT_FOUND_IN_PASS1)
        {
        }
        */
    }

    // pass 2 of target refresh
    dist = TARGET_SEARCH_RADIUS2;
    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (!m_target[i])
        {
            qDebug()<<Q_FUNC_INFO<<" error target non existent i="<<i;
            continue;
        }
        if (m_target[i]->m_pass1_result == UNKNOWN) continue;
        m_target[i]->m_pass_nr = PASS2;
        m_target[i]->RefreshTarget(dist);
    }
    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (!m_target[i])
        {
            qDebug()<<Q_FUNC_INFO<<" error target non existent i="<<i;
            continue;
        }
    }

}
bool RA::Pix(int ang, int rad)
{
    if (rad <= 1 || rad >= RETURNS_PER_LINE - 1) //  avoid range ring
        return false;

    return ((m_ri->m_history[MOD_ROTATION2048(ang)].line[rad] & 128) != 0);
}

bool RA::MultiPix(int ang, int rad)
{
    // checks the blob has a contour of at least length pixels
    // pol must start on the contour of the blob
    // false if not
    // if false clears out pixels of th blob in hist
    //    wxCriticalSectionLocker lock(ArpaTarget::m_ri->m_exclusive);
    int length = arpa_settings.min_contour_length;
    Polar start;
    start.angle = ang;
    start.r = rad;
    if (!Pix(start.angle, start.r))
        return false;

    Polar current = start;  // the 4 possible translations to move from a point on the contour to the next
    Polar max_angle;
    Polar min_angle;
    Polar max_r;
    Polar min_r;
    Polar transl[4];  //   = { 0, 1,   1, 0,   0, -1,   -1, 0 };
    transl[0].angle = 0;
    transl[0].r = 1;
    transl[1].angle = 1;
    transl[1].r = 0;
    transl[2].angle = 0;
    transl[2].r = -1;
    transl[3].angle = -1;
    transl[3].r = 0;
    int count = 0;
    int aa;
    int rr;
    bool succes = false;
    int index = 0;
    max_r = current;
    max_angle = current;
    min_r = current;
    min_angle = current;  // check if p inside blob
    if (start.r >= RETURNS_PER_LINE - 1)
        return false;  //  r too large

    if (start.r < 3)
        return false;  //  r too small

    // first find the orientation of border point p
    for (int i = 0; i < 4; i++)
    {
        index = i;
        aa = current.angle + transl[index].angle;
        rr = current.r + transl[index].r;
        succes = !Pix(aa, rr);
        if (succes) break;
    }
    if (!succes)
    {
        qDebug()<<Q_FUNC_INFO<<" Error starting point not on contour";
        return false;
    }
    index += 1;  // determines starting direction
    if (index > 3) index -= 4;
    while (current.r != start.r || current.angle != start.angle || count == 0)
    {  // try all translations to find the next point  // start with the "left most" translation relative to the
        // previous one
        index += 3;  // we will turn left all the time if possible
        for (int i = 0; i < 4; i++)
        {
            if (index > 3) index -= 4;
            aa = current.angle + transl[index].angle;
            rr = current.r + transl[index].r;
            succes = Pix(aa, rr);
            if (succes)   // next point found
                break;

            index += 1;
        }
        if (!succes)
        {
            qDebug()<<Q_FUNC_INFO<<"RA::CheckContour no next point found count="<<count;
            return false;  // return code 7, no next point found
        }                // next point found
        current.angle = aa;
        current.r = rr;
        if (count >= length)
            return true;

        count++;
        if (current.angle > max_angle.angle)
            max_angle = current;

        if (current.angle < min_angle.angle)
            min_angle = current;

        if (current.r > max_r.r)
            max_r = current;

        if (current.r < min_r.r)
            min_r = current;

    }  // contour length is less than m_min_contour_length
    // before returning false erase this blob so we do not have to check this one again
    if (min_angle.angle < 0)
    {
        min_angle.angle += LINES_PER_ROTATION;
        max_angle.angle += LINES_PER_ROTATION;
    }
    for (int a = min_angle.angle; a <= max_angle.angle; a++)
    {
        for (int r = min_r.r; r <= max_r.r; r++)
            m_ri->m_history[MOD_ROTATION2048(a)].line[r] &= 63;
    }
    return false;
}
void RA::DeleteAllTargets()
{
    for (int i = 0; i < m_number_of_targets; i++)
    {
        if (!m_target[i]) continue;
        m_target[i]->SetStatusLost();
    }
}
void RA::AcquireNewMARPATarget(Position p)
{
    qDebug()<<Q_FUNC_INFO<<p.lat<<p.lon;

    AcquireOrDeleteMarpaTarget(p, ACQUIRE0);
}
void RA::AcquireOrDeleteMarpaTarget(Position target_pos, int status)
{
    qDebug()<<Q_FUNC_INFO<<target_pos.lat<<target_pos.lon;
    int i_target;
    if (m_number_of_targets < MAX_NUMBER_OF_TARGETS - 1 ||
            (m_number_of_targets == MAX_NUMBER_OF_TARGETS - 1 && status == FOR_DELETION))
    {
        if (m_target[m_number_of_targets] == 0)
        {
            m_target[m_number_of_targets] = new ARPATarget(this,m_ri);
            qDebug()<<Q_FUNC_INFO<<"create new ARPAtarget";
        }
        i_target = m_number_of_targets;
        m_number_of_targets++;
    }
    else
    {
        qDebug()<<Q_FUNC_INFO<<" Error, max targets exceeded ";
        return;
    }

    ARPATarget* target = m_target[i_target];
    target->m_position = target_pos;  // Expected position
    target->m_position.time = QDateTime::currentMSecsSinceEpoch();
    target->m_position.dlat_dt = 0.;
    target->m_position.dlon_dt = 0.;
    target->m_status = status;
    qDebug()<<Q_FUNC_INFO<<"target new status"<<status;
    qDebug()<<Q_FUNC_INFO<<"target lat"<<target->m_position.lat;
    qDebug()<<Q_FUNC_INFO<<"target lon"<<target->m_position.lon;

    target->m_max_angle.angle = 0;
    target->m_min_angle.angle = 0;
    target->m_max_r.r = 0;
    target->m_min_r.r = 0;

    if (!target->m_kalman)
        target->m_kalman = new KalmanFilter(this);

    target->m_automatic = false;
    return;

}
int RA::AcquireNewARPATarget(Polar pol, int status)
{
    // acquires new target from mouse click position
    // no contour taken yet
    // target status status, normally 0, if dummy target to delete a target -2
    // returns in X metric coordinates of click
    // constructs Kalman filter
    Position own_pos;
    Position target_pos;
    own_pos.lat = currentOwnShipLat;
    own_pos.lon =currentOwnShipLon;
    target_pos = Polar2Pos(pol, own_pos, m_range);
    // make new target or re-use an existing one with status == lost
    int i;
    if (m_number_of_targets < MAX_NUMBER_OF_TARGETS - 1 || (m_number_of_targets == MAX_NUMBER_OF_TARGETS - 1 && status == -2))
    {
        if (!m_target[m_number_of_targets])
            m_target[m_number_of_targets] = new ARPATarget(this, m_ri);

        i = m_number_of_targets;
        m_number_of_targets++;
    }
    else
    {
        qDebug()<<Q_FUNC_INFO<<" Error, max targets exceeded ";
        return -1;
    }

    ARPATarget* target = m_target[i];

    target->m_position = target_pos;  // Expected position
    target->m_position.time = QDateTime::currentMSecsSinceEpoch();
    target->m_position.dlat_dt = 0.;
    target->m_position.dlon_dt = 0.;
    target->m_position.sd_speed_kn = 0.;
    target->m_status = status;
    target->m_max_angle.angle = 0;
    target->m_min_angle.angle = 0;
    target->m_max_r.r = 0;
    target->m_min_r.r = 0;

    if (!target->m_kalman)
        target->m_kalman = new KalmanFilter();

    target->m_check_for_duplicate = false;
    target->m_automatic = true;
    target->m_target_id = 0;
    target->RefreshTarget(TARGET_SEARCH_RADIUS1);
    return i;
}

void RA::DeleteTarget(Position target_pos) { AcquireOrDeleteMarpaTarget(target_pos, FOR_DELETION); }

ARPATarget::ARPATarget(QObject *parent, RI *ri) :
    QObject(parent),m_ri(ri)
{
//    if(!checkHddId())
//        exit(1);

    qDebug()<<Q_FUNC_INFO;
    m_kalman = 0;
    m_status = LOST;
    m_contour_length = 0;
    m_lost_count = 0;
    m_target_id = 0;
    m_refresh = 0;
    m_automatic = false;
    m_speed_kn = 0.;
    m_course = 0.;
    m_stationary = 0;
    m_position.dlat_dt = 0.;
    m_position.dlon_dt = 0.;
    m_speeds.nr = 0;
    m_pass1_result = UNKNOWN;
    m_pass_nr = PASS1;
//    old_heading = radar_settings.headingUp ? 0 : currentHeading;
}
ARPATarget::~ARPATarget()
{
    if (m_kalman)
    {
        delete m_kalman;
        m_kalman = 0;
    }
}
bool ARPATarget::Pix(int ang, int rad)
{
    if (rad <= 1 || rad >= RETURNS_PER_LINE - 1) //  avoid range ring
        return false;

    if (m_check_for_duplicate)        // check bit 1
        return ((m_ri->m_history[MOD_ROTATION2048(ang)].line[rad] & 64) != 0);
    else        // check bit 0
        return ((m_ri->m_history[MOD_ROTATION2048(ang)].line[rad] & 128) != 0);

}
bool ARPATarget::FindContourFromInside(Polar* pol)
{  // moves pol to contour of blob
    // true if success
    // false when failed
    //    qDebug()<<Q_FUNC_INFO;
    int ang = pol->angle;
    int rad = pol->r;
    if (rad >= RETURNS_PER_LINE - 1 || rad < 3)
        return false;

    if (!(Pix(ang, rad)))
        return false;

    while (Pix(ang, rad))
        ang--;

    ang++;
    pol->angle = ang;
    // check if the blob has the required min contour length
    if (MultiPix(ang, rad))
        return true;
    else
        return false;

}
bool ARPATarget::MultiPix(int ang, int rad)
{  // checks the blob has a contour of at least length pixels
    // pol must start on the contour of the blob
    // false if not
    // if false clears out pixels of th blob in hist
    int length = arpa_settings.min_contour_length;
    Polar start;
    start.angle = ang;
    start.r = rad;
    if (!Pix(start.angle, start.r))
        return false;

    Polar current = start;  // the 4 possible translations to move from a point on the contour to the next
    Polar max_angle;
    Polar min_angle;
    Polar max_r;
    Polar min_r;
    Polar transl[4];  //   = { 0, 1,   1, 0,   0, -1,   -1, 0 };
    transl[0].angle = 0;
    transl[0].r = 1;
    transl[1].angle = 1;
    transl[1].r = 0;
    transl[2].angle = 0;
    transl[2].r = -1;
    transl[3].angle = -1;
    transl[3].r = 0;
    int count = 0;
    int aa;
    int rr;
    bool succes = false;
    int index = 0;
    max_r = current;
    max_angle = current;
    min_r = current;
    min_angle = current;  // check if p inside blob
    if (start.r >= RETURNS_PER_LINE - 1)
    {
        qDebug()<<Q_FUNC_INFO<<"r too large";
        return false;  //  r too large
    }
    if (start.r < 3)
    {
        qDebug()<<Q_FUNC_INFO<<"r too small";
        return false;  //  r too small
    }
    // first find the orientation of border point p
    for (int i = 0; i < 4; i++)
    {
        index = i;
        aa = current.angle + transl[index].angle;
        rr = current.r + transl[index].r;
        succes = !Pix(aa, rr);
        if (succes) break;
    }
    if (!succes)
    {
        qDebug()<<Q_FUNC_INFO<<" Error starting point not on contour";
        return false;
    }
    index += 1;  // determines starting direction
    if (index > 3) index -= 4;
    while (current.r != start.r || current.angle != start.angle || count == 0)
    {  // try all translations to find the next point  // start with the "left most" translation relative to the
        // previous one
        index += 3;         // we will turn left all the time if possible
        for (int i = 0; i < 4; i++)
        {
            if (index > 3) index -= 4;
            aa = current.angle + transl[index].angle;
            rr = current.r + transl[index].r;
            succes = Pix(aa, rr);
            if (succes)  // next point found
                break;

            index += 1;
        }
        if (!succes)
        {
            qDebug()<<Q_FUNC_INFO<<" no next point found count="<<count;
            return false;  // return code 7, no next point found
        }                // next point found
        current.angle = aa;
        current.r = rr;
        if (count >= length)
            return true;

        count++;
        if (current.angle > max_angle.angle)
            max_angle = current;

        if (current.angle < min_angle.angle)
            min_angle = current;

        if (current.r > max_r.r)
            max_r = current;

        if (current.r < min_r.r)
            min_r = current;

    }  // contour length is less than m_min_contour_length
    // before returning false erase this blob so we do not have to check this one again
    qDebug()<<Q_FUNC_INFO<<" contour length less than minimal ="<<length;

    if (min_angle.angle < 0)
    {
        min_angle.angle += LINES_PER_ROTATION;
        max_angle.angle += LINES_PER_ROTATION;
    }
    for (int a = min_angle.angle; a <= max_angle.angle; a++)
    {
        for (int r = min_r.r; r <= max_r.r; r++)
            m_ri->m_history[MOD_ROTATION2048(a)].line[r] &= 63;

    }
    return false;
}

void ARPATarget::SetStatusLost()
{
    qDebug()<<Q_FUNC_INFO;
    m_contour_length = 0;
    m_lost_count = 0;
    if (m_kalman)         // reset kalman filter, don't delete it, too  expensive
        m_kalman->ResetFilter();

    if (m_status >= STATUS_TO_OCPN)
    {
        Polar p;
        p.angle = 0;
        p.r = 0;
        //    PassARPAtoOCPN(&p, L);
    }
    m_status = LOST;
    m_target_id = 0;
    m_automatic = false;
    m_refresh = 0;
    m_speed_kn = 0.;
    m_course = 0.;
    m_stationary = 0;
    m_position.dlat_dt = 0.;
    m_position.dlon_dt = 0.;
    m_speeds.nr = 0;
    m_pass_nr = PASS1;
}
#define PIX(aa, rr)       \
    if (rr > 510) continue; \
    if (MultiPix(aa, rr)) { \
    pol->angle = aa;      \
    pol->r = rr;          \
    return true;          \
    }

bool ARPATarget::FindNearestContour(Polar* pol, int dist)
{
    // make a search pattern along a square
    // returns the position of the nearest blob found in pol
    // dist is search radius (1 more or less)
    //    qDebug()<<Q_FUNC_INFO;

    int a = pol->angle;
    int r = pol->r;
    if (dist < 2) dist = 2;
    for (int j = 1; j <= dist; j++)
    {
        int dist_r = j;
        int dist_a = (int)(326. / (double)r * j);  // 326/r: conversion factor to make squares
        //        qDebug()<<Q_FUNC_INFO<<"dist_a "<<dist_a;
        if (dist_a == 0) dist_a = 1;
        for (int i = 0; i <= dist_a; i++)
        {  // "upper" side
            PIX(a - i, r + dist_r);            // search starting from the middle
            PIX(a + i, r + dist_r);
        }
        for (int i = 0; i < dist_r; i++)
        {  // "right hand" side
            PIX(a + dist_a, r + i);
            PIX(a + dist_a, r - i);
        }
        for (int i = 0; i <= dist_a; i++)
        {  // "lower" side
            PIX(a + i, r - dist_r);
            PIX(a - i, r - dist_r);
        }
        for (int i = 0; i < dist_r; i++)
        {  // "left hand" side
            PIX(a - dist_a, r + i);
            PIX(a - dist_a, r - i);
        }
    }
    return false;
}
bool ARPATarget::GetTarget(Polar* pol, int dist1)
{
    // general target refresh
    bool contour_found = false;
    int dist = dist1;
    if (m_status == ACQUIRE0 || m_status == ACQUIRE1)
        dist *= 2;

    if (dist > pol->r - 5) dist = pol->r - 5;  // don't search close to origin
    int a = pol->angle;
    int r = pol->r;

    if (Pix(a, r))
        contour_found = FindContourFromInside(pol);
    else
        contour_found = FindNearestContour(pol, dist);

    if (!contour_found)
        return false;

    int cont = GetContour(pol);
    if (cont != 0)
    {
        // reset pol
        pol->angle = a;
        pol->r = r;
        return false;
    }
    return true;
}
void ARPATarget::ResetPixels()
{
    //    qDebug()<<Q_FUNC_INFO;
    // resets the pixels of the current blob (plus a little margin) so that blob will no be found again in the same sweep
    for (int r = m_min_r.r - DISTANCE_BETWEEN_TARGETS; r <= m_max_r.r + DISTANCE_BETWEEN_TARGETS; r++)
    {
        if (r >= LINES_PER_ROTATION || r < 0) continue;
        for (int a = m_min_angle.angle - DISTANCE_BETWEEN_TARGETS; a <= m_max_angle.angle + DISTANCE_BETWEEN_TARGETS; a++)
            m_ri->m_history[MOD_ROTATION2048(a)].line[r] = m_ri->m_history[MOD_ROTATION2048(a)].line[r] & 127;
    }
}

void ARPATarget::RefreshTarget(int dist)
{
    Position prev_X;
    Position prev2_X;
    Position own_pos;
    Polar pol;
    double delta_t;
    LocalPosition x_local;
    quint64 prev_refresh = m_refresh;

    // refresh may be called from guard directly, better check
    if (m_status == LOST)
        return;

    own_pos.lat = currentOwnShipLat;
    own_pos.lon = currentOwnShipLon;

    pol = Pos2Polar(m_position, own_pos, m_range);
//    qDebug()<<"old pol "<<pol.angle<<pol.r;
//    qDebug()<<"old pos "<<m_position.lat<<m_position.lon;

    /*motion mode correction
    double dif_bearing = (radar_settings.headingUp ? 0 : currentHeading) - old_heading;
    pol.angle += SCALE_DEGREES_TO_RAW2048(dif_bearing);
    Position new_pos = Polar2Pos(pol,own_pos,m_range);
    m_position.lat = new_pos.lat;
    m_position.lon = new_pos.lon;
    old_heading = (radar_settings.headingUp ? 0 : currentHeading);
    qDebug()<<"new pol "<<pol.angle<<pol.r;
     qDebug()<<"new pos "<<m_position.lat<<m_position.lon;
*/

    quint64 time1 = m_ri->m_history[MOD_ROTATION2048(pol.angle)].time;
    int margin = SCAN_MARGIN;
    if (m_pass_nr == PASS2)
    {
        margin += 100;
        qDebug()<<Q_FUNC_INFO<<"try pass2";
    }
    quint64 time2 = m_ri->m_history[MOD_ROTATION2048(pol.angle + margin)].time;
    if ((time1 < (m_refresh + SCAN_MARGIN2) || time2 < time1) && m_status != 0)
    {
        quint64 now = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();  // millis
        int diff = now - m_refresh;
        if (diff > 28000)
        {
            qDebug()<<"target not refreshed, missing spokes, set lost, status="<<m_status<<", target_id="<<m_target_id<<" timediff="<<diff;
            SetStatusLost();
        }
        else if ((diff < 28000) && (diff > 4000))
        {
            /*arpa future pos prediction
            */
            if(m_status > 1)
            {
                if(future_first)
                {
                    m_time_future = now;
                    m_max_angle_future = m_max_angle;
                    m_min_angle_future = m_min_angle;
                    m_max_r_future = m_max_r;
                    m_min_r_future = m_min_r;
                    future_first = false;
                }
                else
                {
                    double dt = (now - m_time_future)/1000;
                    if(dt > 1)
                    {
                        m_time_future = now;
                        int buf_deg = MOD_ROTATION2048(m_max_angle_future.angle);
                        buf_deg = SCALE_RAW_TO_DEGREES2048(buf_deg);
                        int max_r_xA = m_max_r_future.r*qSin(deg2rad(buf_deg));
                        int max_r_yA = m_max_r_future.r*qCos(deg2rad(buf_deg));
                        double dx = 8*(m_position.dlon_dt*dt*RETURNS_PER_LINE)/m_range;
                        double dy = 8*(m_position.dlat_dt*dt*RETURNS_PER_LINE)/m_range;
                        int max_r_xB = max_r_xA+dx;
                        int max_r_yB = max_r_yA-dy;

                        buf_deg = MOD_ROTATION2048(m_min_angle_future.angle);
                        buf_deg = SCALE_RAW_TO_DEGREES2048(buf_deg);
                        int min_r_xA = m_min_r_future.r*qSin(deg2rad(buf_deg));
                        int min_r_yA = m_min_r_future.r*qCos(deg2rad(buf_deg));
                        int min_r_xB = min_r_xA+dx;
                        int min_r_yB = min_r_yA-dy;

//                        m_max_r_future.r = m_max_r_future.r;
                        m_max_r_future.r= sqrt(pow(max_r_xB,2)+pow(max_r_yB,2));
                        m_max_angle_future.angle = rad2deg(atan2(max_r_xB,max_r_yB));
                        m_max_angle_future.angle = SCALE_DEGREES_TO_RAW2048(m_max_angle_future.angle);
                        m_max_angle_future.angle = MOD_ROTATION2048(m_max_angle_future.angle);

//                        m_min_r_future.r = m_min_r_future.r;
                        m_min_r_future.r = sqrt(pow(min_r_xB,2)+pow(min_r_yB,2));
                        m_min_angle_future.angle = rad2deg(atan2(min_r_xB,min_r_yB));
                        m_min_angle_future.angle = SCALE_DEGREES_TO_RAW2048(m_min_angle_future.angle);
                        m_min_angle_future.angle = MOD_ROTATION2048(m_min_angle_future.angle);


                        qDebug()<<"dx"<<dx<<"dy"<<dy<<"dt"<<dt<<"dlat"<<m_position.dlat_dt<<"dlon"
                               <<m_position.dlon_dt<<"m_range"<<m_range<<"m_speed_kn"<<m_speed_kn<<"course"<<m_course;

                    }
                }

            }

        }
        else if(diff < 4000)
        {
            m_time_future = now;
            m_max_angle_future = m_max_angle;
            m_min_angle_future = m_min_angle;
            m_max_r_future = m_max_r;
            m_min_r_future = m_min_r;
            future_first = true;
        }

        return;
    }
    // set new refresh time
    m_refresh = time1;
    prev_X = m_position;  // save the previous target position
    prev2_X = prev_X;

    // PREDICTION CYCLE
    m_position.time = time1;                                                // estimated new target time
    delta_t = ((double)((m_position.time - prev_X.time))) / 1000.;  // in seconds
    //    qDebug()<<Q_FUNC_INFO<<"m_pos time"<<m_position.time<<"prev time"<<prev_X.time;
    if (m_status == 0)
        delta_t = 0.;

    if (m_position.lat > 90.)
    {
        qDebug()<<Q_FUNC_INFO<<"lat >90";
        SetStatusLost();
        return;
    }
    x_local.lat = (m_position.lat - own_pos.lat) * 60. * 1852.;                              // in meters
    x_local.lon = (m_position.lon - own_pos.lon) * 60. * 1852. * cos(deg2rad(own_pos.lat));  // in meters
    x_local.dlat_dt = m_position.dlat_dt;                                                    // meters / sec
    x_local.dlon_dt = m_position.dlon_dt;                                                    // meters / sec
    //    qDebug()<<Q_FUNC_INFO<<"111..x_local.lat"<<x_local.lat<<"x_local.lon"<<x_local.lon;
    m_kalman->Predict(&x_local, delta_t);  // x_local is new estimated local position of the target
    // now set the polar to expected angular position from the expected local position
    pol.angle = (int)(atan2(x_local.lon, x_local.lat) * LINES_PER_ROTATION / (2. * PI));
    if (pol.angle < 0) pol.angle += LINES_PER_ROTATION;
    pol.r =(int)(sqrt(x_local.lat * x_local.lat + x_local.lon * x_local.lon) * (double)RETURNS_PER_LINE / (double)m_range);
    // zooming and target movement may  cause r to be out of bounds
    if (pol.r >= RETURNS_PER_LINE || pol.r <= 0)
    {
        qDebug()<<Q_FUNC_INFO<<" r out of area";
        SetStatusLost();
        return;
    }
    m_expected = pol;  // save expected polar position

    // Measurement cycle
    int dist1 = dist;
    Polar back = pol;
    if (GetTarget(&pol, dist1))
    {
        ResetPixels();
        // target too large? (land masses?) get rid of it
        if (abs(back.r - pol.r) > MAX_TARGET_DIAMETER || abs(m_max_r.r - m_min_r.r) > MAX_TARGET_DIAMETER ||
                abs(m_min_angle.angle - m_max_angle.angle) > MAX_TARGET_DIAMETER)
        {
            qDebug()<<Q_FUNC_INFO<<"target too large? (land masses?) get rid of it";
            SetStatusLost();
            return;
        }

        // target refreshed, measured position in pol
        // check if target has a new later time than previous target
        if (pol.time <= prev_X.time && m_status > 1)
        {
            // found old target again, reset what we have done
            qDebug()<<Q_FUNC_INFO<<" Error Gettarget same time found";
            m_position = prev_X;
            prev_X = prev2_X;
            return;
        }

        m_lost_count = 0;
        if (m_status == ACQUIRE0)
        {
            // as this is the first measurement, move target to measured position
            Position p_own;
            p_own.lat = m_ri->m_history[MOD_ROTATION2048(pol.angle)].lat;  // get the position at receive time
            p_own.lon = m_ri->m_history[MOD_ROTATION2048(pol.angle)].lon;
            m_position = Polar2Pos(pol, p_own, m_range);  // using own ship location from the time of reception
            m_position.dlat_dt = 0.;
            m_position.dlon_dt = 0.;
            m_expected = pol;
            m_position.sd_speed_kn = 0.;
        }

        m_status++;
        // target gets an id when status  == STATUS_TO_OCPN
        if (m_status == STATUS_TO_OCPN)
        {
            target_id_count++;
            if (target_id_count >= 10000) target_id_count = 1;
            m_target_id = target_id_count;
        }

        // Kalman filter to  calculate the apostriori local position and speed based on found position (pol)
        if (m_status > 1)
        {
            m_kalman->Update_P();
            m_kalman->SetMeasurement(&pol, &x_local, &m_expected, m_range);  // pol is measured position in polar coordinates
        }

        // x_local expected position in local coordinates

        m_position.time = pol.time;  // set the target time to the newly found time
    }                              // end of target found
    // target not found
    else
    {
        // target not found
        if (m_pass_nr == PASS1) m_kalman->Update_P();
        // check if the position of the target has been taken by another target, a duplicate
        // if duplicate, handle target as not found but don't do pass 2 (= search in the surroundings)
        bool duplicate = false;
        m_check_for_duplicate = true;
        if (m_pass_nr == PASS1 && GetTarget(&pol, dist1))
        {
            m_pass1_result = UNKNOWN;
            duplicate = true;
            qDebug()<<Q_FUNC_INFO<<"found duplicate";
        }
        m_check_for_duplicate = false;

        // not found in pass 1
        // try again later in pass 2 with a larger distance
        if (m_pass_nr == PASS1 && !duplicate)
        {
            qDebug()<<Q_FUNC_INFO<<"NOT_FOUND_IN_PASS1";
            m_pass1_result = NOT_FOUND_IN_PASS1;
            // reset what we have done
            pol.time = prev_X.time;
            m_refresh = prev_refresh;
            m_position = prev_X;
            prev_X = prev2_X;
            return;
        }
        else if (m_pass_nr == PASS2)
        {
            qDebug()<<Q_FUNC_INFO<<"NOT_FOUND_IN_PASS2";
            pol.time = prev_X.time;
            m_refresh = prev_refresh;
            prev2_X.lat += 0.000010;
            prev2_X.lon += 0.00010;
            m_position = prev2_X;
            prev_X = prev2_X;

            return;
        }


        // delete low status targets immediately when not found
        if (m_status == ACQUIRE0 || m_status == ACQUIRE1 || m_status == 2)
        {
            SetStatusLost();
            return;
        }

        m_lost_count++;

        // delete if not found too often
        if (m_lost_count > MAX_LOST_COUNT)
        {
            qDebug()<<Q_FUNC_INFO<<"not found often";
            SetStatusLost();
            return;
        }
    }  // end of target not found
    // set pass1_result ready for next sweep
    m_pass1_result = UNKNOWN;
    if (m_status != ACQUIRE1)
    {
        // if status == 1, then this was first measurement, keep position at measured position
        m_position.lat = own_pos.lat + x_local.lat / 60. / 1852.;
        m_position.lon = own_pos.lon + x_local.lon / 60. / 1852. / cos(deg2rad(own_pos.lat));
        m_position.dlat_dt = x_local.dlat_dt;  // meters / sec
        m_position.dlon_dt = x_local.dlon_dt;  // meters /sec
        m_position.sd_speed_kn = x_local.sd_speed_m_s * 3600. / 1852.;
    }

    // set refresh time to the time of the spoke where the target was found
    m_refresh = m_position.time;
    if (m_status >= 1)
    {
        if (m_status == 2)
        {
            // avoid extreme start-up speeds
            if (m_position.dlat_dt > START_UP_SPEED) m_position.dlat_dt = START_UP_SPEED;
            if (m_position.dlat_dt < -START_UP_SPEED) m_position.dlat_dt = -START_UP_SPEED;
            if (m_position.dlon_dt > START_UP_SPEED) m_position.dlon_dt = START_UP_SPEED;
            if (m_position.dlon_dt < -START_UP_SPEED) m_position.dlon_dt = -START_UP_SPEED;
        }
        if (m_status == 3)
        {
            // avoid extreme start-up speeds
            if (m_position.dlat_dt > 2 * START_UP_SPEED) m_position.dlat_dt = 2 * START_UP_SPEED;
            if (m_position.dlat_dt < -2 * START_UP_SPEED) m_position.dlat_dt = -2 * START_UP_SPEED;
            if (m_position.dlon_dt > 2 * START_UP_SPEED) m_position.dlon_dt = 2 * START_UP_SPEED;
            if (m_position.dlon_dt < -2 * START_UP_SPEED) m_position.dlon_dt = -2 * START_UP_SPEED;
        }
        double s1 = m_position.dlat_dt;                          // m per second
        double s2 = m_position.dlon_dt;                          // m  per second
        m_speed_kn = (sqrt(s1 * s1 + s2 * s2)) * 3600. / 1852.;  // and convert to nautical miles per hour
        m_course = rad2deg(atan2(s2, s1));
        if (m_course < 0) m_course += 360.;
        if (m_speed_kn > 20.)
            pol = Pos2Polar(m_position, own_pos, m_range);


        if (m_speed_kn < (double)TARGET_SPEED_DIV_SDEV * m_position.sd_speed_kn)
        {
            m_speed_kn = 0.;
            m_course = 0.;
            if (m_stationary < 2)
                m_stationary++;
        }
        else if (m_stationary > 0)
            m_stationary--;

    }
    return;
}

int ARPATarget::GetContour(Polar* pol)
{  // sets the measured_pos if succesfull
    // pol must start on the contour of the blob
    // follows the contour in a clockwise direction
    // returns metric position of the blob in Z
    // the 4 possible translations to move from a point on the contour to the next
    Polar transl[4];  //   = { 0, 1,   1, 0,   0, -1,   -1, 0 };
    transl[0].angle = 0;
    transl[0].r = 1;

    transl[1].angle = 1;
    transl[1].r = 0;

    transl[2].angle = 0;
    transl[2].r = -1;

    transl[3].angle = -1;
    transl[3].r = 0;

    int count = 0;
    Polar start = *pol;
    Polar current = *pol;
    int aa;
    int rr;

    bool succes = false;
    int index = 0;
    m_max_r = current;
    m_max_angle = current;
    m_min_r = current;
    m_min_angle = current;
    // check if p inside blob
    if (start.r >= RETURNS_PER_LINE - 1)
    {
        qDebug()<<Q_FUNC_INFO<<"return code 1, r too large";
        return 1;  // return code 1, r too large
    }
    if (start.r < 4)
    {
        qDebug()<<Q_FUNC_INFO<<"return code 2, r too small";
        return 2;  // return code 2, r too small
    }
    if (!Pix(start.angle, start.r))
    {
        qDebug()<<Q_FUNC_INFO<<"return code 3, starting point outside blob";
        return 3;  // return code 3, starting point outside blob
    }
    // first find the orientation of border point p
    for (int i = 0; i < 4; i++)
    {
        index = i;
        aa = current.angle + transl[index].angle;
        rr = current.r + transl[index].r;
        //  if (rr > 511) return 13;  // r too large
        succes = !Pix(aa, rr);
        if (succes) break;
    }
    if (!succes)
    {
        qDebug()<<Q_FUNC_INFO<<"return code 4, starting point not on contour";
        return 4;  // return code 4, starting point not on contour
    }
    index += 1;  // determines starting direction
    if (index > 3) index -= 4;

    while (current.r != start.r || current.angle != start.angle || count == 0)
    {
        // try all translations to find the next point
        // start with the "left most" translation relative to the previous one
        index += 3;  // we will turn left all the time if possible
        for (int i = 0; i < 4; i++)
        {
            if (index > 3) index -= 4;
            aa = current.angle + transl[index].angle;
            rr = current.r + transl[index].r;
            succes = Pix(aa, rr);
            if (succes)                // next point found
                break;

            index += 1;
        }
        if (!succes)
        {
            qDebug()<<Q_FUNC_INFO<<" no next point found count= "<<count;
            return 7;  // return code 7, no next point found
        }
        // next point found
        current.angle = aa;
        current.r = rr;
        if (count < MAX_CONTOUR_LENGTH - 2)
            m_contour[count] = current;

        if (count == MAX_CONTOUR_LENGTH - 2)
            m_contour[count] = start;  // shortcut to the beginning for drawing the contour

        if (count < MAX_CONTOUR_LENGTH - 1)
            count++;

        if (current.angle > m_max_angle.angle)
            m_max_angle = current;

        if (current.angle < m_min_angle.angle)
            m_min_angle = current;

        if (current.r > m_max_r.r)
            m_max_r = current;

        if (current.r < m_min_r.r)
            m_min_r = current;

    }
    m_contour_length = count;
    //  CalculateCentroid(*target);    we better use the real centroid instead of the average, todo
    if (m_min_angle.angle < 0)
    {
        m_min_angle.angle += LINES_PER_ROTATION;
        m_max_angle.angle += LINES_PER_ROTATION;
    }
    pol->angle = (m_max_angle.angle + m_min_angle.angle) / 2; //av angle of centroid
    if (m_max_r.r > RETURNS_PER_LINE - 1 || m_min_r.r > RETURNS_PER_LINE - 1)
        return 10;  // return code 10 r too large

    if (m_max_r.r < 2 || m_min_r.r < 2)
        return 11;  // return code 11 r too small

    if (pol->angle >= LINES_PER_ROTATION)
        pol->angle -= LINES_PER_ROTATION;

    pol->r = (m_max_r.r + m_min_r.r) / 2; //av radius of centroid
    pol->time = m_ri->m_history[MOD_ROTATION2048(pol->angle)].time;
    return 0;  //  succes, blob found
}

/****************************radar draw***************************/
QString RD::methods = "Vertex Array";

// Factory to generate a particular draw implementation
RD* RD::make_Draw(RI *ri, int draw_method)
{
//    if(!checkHddId())
//        exit(1);
    qDebug()<<Q_FUNC_INFO;
  switch (draw_method)
  {
    case 0:
      methods = "Vertex Array";
      return new RDVert(ri);
    case 1:
      methods = "Shader";
      return new RDVert(ri);
    default:
      qDebug()<<Q_FUNC_INFO<<"unsupported draw method "<<draw_method;
  }
  return 0;
}

RD::~RD() {}

QString RD::GetDrawingMethods() {

  return methods;
}

#define ADD_VERTEX_POINT(angle, radius, r, g, b, a)          \
{                                                          \
    line->points[count].x = m_polarLookup->x[angle][radius]; \
    line->points[count].y = m_polarLookup->y[angle][radius]; \
    line->points[count].red = r;                             \
    line->points[count].green = g;                           \
    line->points[count].blue = b;                            \
    line->points[count].alpha = a;                           \
    count++;                                                 \
    }

void RDVert::SetBlob(VertexLine* line, int angle_begin, int angle_end, int r1, int r2, GLubyte red, GLubyte green,
                              GLubyte blue, GLubyte alpha)
{
//    qDebug()<<Q_FUNC_INFO<<"angle_begin "<<angle_begin<<"angle_end "<<angle_end<<"r1 "<<r1<<"r2 "<<r2
//           <<"red "<<red<<"green "<<green<<"blue "<<blue<<"alpha "<<alpha;
    if (r2 == 0)
    {
        return;
    }
    int arc1 = MOD_ROTATION2048(angle_begin);
    int arc2 = MOD_ROTATION2048(angle_end);
    size_t count = line->count;

    if (line->count + VERTEX_PER_QUAD > line->allocated)
    {
        const size_t extra = 8 * VERTEX_PER_QUAD;
        line->points = (VertexPoint*)realloc(line->points, (line->allocated + extra) * sizeof(VertexPoint));
        line->allocated += extra;
        m_count += extra;
        qDebug()<<"extra loc";
    }

    if (!line->points)
    {
        if (!m_oom)
        {
            qDebug()<<"BR24radar_pi: Out of memory";
            m_oom = true;
        }
        return;
    }

    // First triangle
//    qDebug()<<Q_FUNC_INFO<<arc1<<arc2<<r1<<r2;
    ADD_VERTEX_POINT(arc1, r1, red, green, blue, alpha);
    ADD_VERTEX_POINT(arc1, r2, red, green, blue, alpha);
    ADD_VERTEX_POINT(arc2, r1, red, green, blue, alpha);

    // Second triangle

    ADD_VERTEX_POINT(arc2, r1, red, green, blue, alpha);
    ADD_VERTEX_POINT(arc1, r2, red, green, blue, alpha);
    ADD_VERTEX_POINT(arc2, r2, red, green, blue, alpha);

    line->count = count;
//    for(int i=0;i<line->count;i++)
//        qDebug()<<"count" <<i<<"x "<<line->points[i].x<<"y "<<line->points[i].y
//               <<"red"<<line->points[i].red<<"green"<<line->points[i].green<<"blue"<<line->points[i].blue<<"alpha"<<line->points[i].alpha;

}

void RDVert::ProcessRadarSpoke(int transparency, int angle, u_int8_t* data, size_t len)
{
    QColor colour;
    GLubyte alpha = 255 * (MAX_OVERLAY_TRANSPARENCY - transparency) / MAX_OVERLAY_TRANSPARENCY;
    BlobColour previous_colour = BLOB_NONE;
    GLubyte strength = 0;
    quint64 now = QDateTime::currentMSecsSinceEpoch();

//    qDebug()<<Q_FUNC_INFO<<"angle"<<angle;

    int r_begin = 0;
    int r_end = 0;

    if (angle < 0 || angle >= LINES_PER_ROTATION)
    {
        return;
    }

    VertexLine* line = &m_vertices[angle];

    if (!line->points)
    {
        static size_t INITIAL_ALLOCATION = 600;
        line->allocated = INITIAL_ALLOCATION * VERTEX_PER_QUAD;
        m_count += INITIAL_ALLOCATION * VERTEX_PER_QUAD;
        line->points = (VertexPoint*)malloc(line->allocated * sizeof(VertexPoint));
        if (!line->points)
        {
            if (!m_oom)
            {
                qDebug()<<"BR24radar_pi: Out of memory";
                m_oom = true;
            }
            line->allocated = 0;
            line->count = 0;
            return;
        }
//        qDebug()<<"init loc";

    }
    line->count = 0;
    line->timeout = now + 6000;
//    line->timeout = now + m_ri->m_pi->m_settings.max_age;

    for (size_t radius = 0; radius < len; radius++)
    {
        //MTI
            strength = data[radius];

        BlobColour actual_colour = m_ri->m_colour_map[strength];
        //        qDebug()<<Q_FUNC_INFO<<"strength "<<strength<<"actual color "<<actual_colour;

        if (actual_colour == previous_colour)
        {
            // continue with same color, just register it
            r_end++;
        }
        else if (previous_colour == BLOB_NONE && actual_colour != BLOB_NONE)
        {
            // blob starts, no display, just register
            r_begin = radius;
            r_end = r_begin + 1;
            previous_colour = actual_colour;  // new color
        }
        else if (previous_colour != BLOB_NONE && (previous_colour != actual_colour))
        {
            colour = m_ri->m_colour_map_rgb[previous_colour];

            SetBlob(line, angle, angle + 1, r_begin, r_end, colour.red(), colour.green(), colour.blue(), alpha);

            previous_colour = actual_colour;
            if (actual_colour != BLOB_NONE)
            {  // change of color, start new blob
                r_begin = radius;
                r_end = r_begin + 1;
            }
        }

    }

    if (previous_colour != BLOB_NONE)
    {  // Draw final blob
        colour = m_ri->m_colour_map_rgb[previous_colour];

        SetBlob(line, angle, angle + 1, r_begin, r_end, colour.red(), colour.green(), colour.blue(), alpha);
    }
}

void RDVert::DrawRadarImage()
{
    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_COLOR_ARRAY);

    //    qDebug()<<Q_FUNC_INFO;
    quint64 now = QDateTime::currentMSecsSinceEpoch();

    for (size_t i = 0; i < LINES_PER_ROTATION; i++)
//        for (size_t i = 0; i < HALF_LINES_PER_ROTATION; i++)
    {
        VertexLine* line = &m_vertices[i];
        if (!line->count || TIMED_OUT(now, line->timeout))
        {
            continue;
        }

        glVertexPointer(2, GL_FLOAT, sizeof(VertexPoint), &line->points[0].x);
        glColorPointer(4, GL_UNSIGNED_BYTE, sizeof(VertexPoint), &line->points[0].red);
        glDrawArrays(GL_TRIANGLES, 0, line->count);
//        glDrawArrays(GL_POINTS, 0, line->count);
    }

    glDisableClientState(GL_VERTEX_ARRAY);  // disable vertex arrays
    glDisableClientState(GL_COLOR_ARRAY);
}




/**********************radar transmit**********************/

radarTransmit::radarTransmit(QObject *parent) :
    QObject(parent)
{
    socket.setSocketOption(QAbstractSocket::MulticastTtlOption, 1);
}
void radarTransmit::setMulticastData(QString addr, uint port)
{
    _data = addr;
    _data_port = port;
}

void radarTransmit::setRange(int meters)
{
    if (meters >= 50 && meters <= 72704)
    {
        unsigned int decimeters = (unsigned int)meters * 10;
        const char pck[6] = {0x03,
                             0xc1,
                             (const char)((decimeters >> 0) & 0XFFL),
                             (const char)((decimeters >> 8) & 0XFFL),
                             (const char)((decimeters >> 16) & 0XFFL),
                             (const char)((decimeters >> 24) & 0XFFL)};
//        qDebug()<<Q_FUNC_INFO<<"transmit: range "<<meters<<"raw "<<decimeters;

        socket.writeDatagram(pck,6,QHostAddress(_data),_data_port);

    }
}
void radarTransmit::RadarStby()
{
    qDebug()<<Q_FUNC_INFO;

    const char standby1[3]={0x00,0xC1,0x01};
    const char standby2[3]={0x01,0xC1,0x00};

    socket.writeDatagram(standby1,3,QHostAddress(_data),_data_port);
    socket.waitForBytesWritten();
    socket.writeDatagram(standby2,3,QHostAddress(_data),_data_port);

}
void radarTransmit::RadarTx()
{
    qDebug()<<Q_FUNC_INFO;
    const char transmit1[3]={0x00,0xC1,0x01};
    const char transmit2[3]={0x01,0xC1,0x01};

    socket.writeDatagram(transmit1,3,QHostAddress(_data),_data_port);
    socket.waitForBytesWritten();
    socket.writeDatagram(transmit2,3,QHostAddress(_data),_data_port);

}
void radarTransmit::RadarStayAlive()
{
//    qDebug()<<Q_FUNC_INFO;

    const char transmit1[2]={0xA0,0xC1};
    const char transmit2[2]={0x03,0xC2};
    const char transmit3[2]={0x04,0xC2};
    const char transmit4[2]={0x05,0xC2};

    socket.writeDatagram(transmit1,2,QHostAddress(_data),_data_port);
    socket.writeDatagram(transmit2,2,QHostAddress(_data),_data_port);
    socket.writeDatagram(transmit3,2,QHostAddress(_data),_data_port);
    socket.writeDatagram(transmit4,2,QHostAddress(_data),_data_port);

}
void radarTransmit::setControlValue(ControlType controlType, int value) {  // sends the command to the radar
    //  bool r = false;

    switch (controlType)
    {
    case CT_REFRESHRATE:
    case CT_BEARING_ALIGNMENT:
    {
        // to be consistent with the local bearing alignment of the pi
        // this bearing alignment works opposite to the one an a Lowrance display
        if (value < 0)
        {
            value += 360;
        }
        int v = value * 10;
        int v1 = v / 256;
        int v2 = v & 255;
        UINT8 cmd[4] = {0x05, 0xc1, (UINT8)v2, (UINT8)v1};
        qDebug()<<Q_FUNC_INFO<<"Bearing alignment:"<<v;
        socket.writeDatagram((const char *)cmd,4,QHostAddress(_data),_data_port);
        break;
    }
    case CT_GAIN:
    {
        if (value < 0)
        {  // AUTO gain
            UINT8 cmd[] =
            {
                0x06, 0xc1, 0, 0, 0, 0, 0x01, 0, 0, 0, 0xad  // changed from a1 to ad
            };
            qDebug()<<Q_FUNC_INFO<<"AUTO gain";
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        else
        {  // Manual Gain
            int v = (value + 1) * 255 / 100;
            if (v > 255)
            {
                v = 255;
            }
            UINT8 cmd[] = {0x06, 0xc1, 0, 0, 0, 0, 0, 0, 0, 0, (UINT8)v};
            qDebug()<<Q_FUNC_INFO<<"manual gain"<<value;
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        break;
    }

    case CT_SEA:
    {
        if (value < 0)
        {  // Sea Clutter - Auto
            UINT8 cmd[11] = {0x06, 0xc1, 0x02, 0, 0, 0, 0x01, 0, 0, 0, 0xd3};
            qDebug()<<Q_FUNC_INFO<<"Auto Sea";
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        else
        {  // Sea Clutter
            int v = (value + 1) * 255 / 100;
            if (v > 255)
            {
                v = 255;
            }
            UINT8 cmd[] = {0x06, 0xc1, 0x02, 0, 0, 0, 0, 0, 0, 0, (UINT8)v};
            qDebug()<<Q_FUNC_INFO<<"manual Sea"<<value;
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        break;
    }

    case CT_RAIN:
    {  // Rain Clutter - Manual. Range is 0x01 to 0x50
        int v = (value + 1) * 255 / 100;
        if (v > 255)
        {
            v = 255;
        }
        UINT8 cmd[] = {0x06, 0xc1, 0x04, 0, 0, 0, 0, 0, 0, 0, (UINT8)v};
        qDebug()<<Q_FUNC_INFO<<"Manual rain"<<value;
        socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        break;
    }

    case CT_SIDE_LOBE_SUPPRESSION:
    {
        if (value < 0)
        {
            UINT8 cmd[] = {// SIDE_LOBE_SUPPRESSION auto
                           0x06, 0xc1, 0x05, 0, 0, 0, 0x01, 0, 0, 0, 0xc0};
            qDebug()<<Q_FUNC_INFO<<"auto SIDE_LOBE_SUPPRESSION";
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        else
        {
            int v = (value + 1) * 255 / 100;
            if (v > 255)
            {
                v = 255;
            }
            UINT8 cmd[] = {0x6, 0xc1, 0x05, 0, 0, 0, 0, 0, 0, 0, (UINT8)v};
            qDebug()<<Q_FUNC_INFO<<"manual SIDE_LOBE_SUPPRESSION"<<value;
            socket.writeDatagram((const char *)cmd,11,QHostAddress(_data),_data_port);
        }
        break;
    }
    case CT_INTERFERENCE_REJECTION:
    {
        UINT8 cmd[] = {0x08, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_INTERFERENCE_REJECTION"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }

    case CT_TARGET_EXPANSION:
    {
        UINT8 cmd[] = {0x09, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_TARGET_EXPANSION"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }

    case CT_TARGET_BOOST:
    {
        UINT8 cmd[] = {0x0a, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_TARGET_BOOST"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }
    case CT_LOCAL_INTERFERENCE_REJECTION:
    {
        if (value < 0) value = 0;
        if (value > 3) value = 3;
        UINT8 cmd[] = {0x0e, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_LOCAL_INTERFERENCE_REJECTION"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }

    case CT_SCAN_SPEED:
    {
        UINT8 cmd[] = {0x0f, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_SCAN_SPEED"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }
    case CT_NOISE_REJECTION:
    {
        UINT8 cmd[] = {0x21, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_NOISE_REJECTION"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }

    case CT_TARGET_SEPARATION:
    {
        UINT8 cmd[] = {0x22, 0xc1, (UINT8)value};
        qDebug()<<Q_FUNC_INFO<<"CT_TARGET_SEPARATION"<<value;
        socket.writeDatagram((const char *)cmd,3,QHostAddress(_data),_data_port);
        break;
    }
    case CT_ANTENNA_HEIGHT:
    {
        int v = value * 1000;  // radar wants millimeters, not meters :-)
        int v1 = v / 256;
        int v2 = v & 255;
        UINT8 cmd[10] = {0x30, 0xc1, 0x01, 0, 0, 0, (UINT8)v2, (UINT8)v1, 0, 0};
        qDebug()<<Q_FUNC_INFO<<"CT_ANTENNA_HEIGHT"<<value;
        socket.writeDatagram((const char *)cmd,10,QHostAddress(_data),_data_port);
        break;
    }
    }
}



/*************************ADSB************************************/


ADSBManager::ADSBManager(QObject *parent, QString addr, uint port)
    : QObject(parent)
{
//    if(!checkHddId())
//        exit(1);

    adsb_obj_map.clear();

    adsbReceive = new ADSBReceiver(this,addr,port);
    connect(adsbReceive,SIGNAL(signal_call_sign(QByteArray,QString,quint8)),
            this,SLOT(handler_call_sign(QByteArray,QString,quint8)));
    connect(adsbReceive,SIGNAL(signal_pos(QByteArray,quint8,bool,quint32,bool,bool,double,double)),
            this,SLOT(handler_pos(QByteArray,quint8,bool,quint32,bool,bool,double,double)));
    connect(adsbReceive,SIGNAL(signal_vel(QByteArray,quint8,bool,quint8,bool,quint32,double,double)),
             this,SLOT(handler_vel(QByteArray,quint8,bool,quint8,bool,quint32,double,double)));

    adsbReceive->start();
}
void ADSBManager::handler_vel(QByteArray addr, quint8 st, bool ic, quint8 nac, bool vert_src,
                              quint32 vert_rate,double vel, double crs)
{
    ADSBObject obj;
    if(adsb_obj_map.contains(addr))
        obj = adsb_obj_map.take(addr);
    else
        obj = createObject(addr);

    obj.ST = st;
    obj.IC = ic;
    obj.NAC = nac;
    obj.Vert_src = vert_src;
    obj.vert_rate = vert_rate;
    obj.time_tag = QDateTime::currentMSecsSinceEpoch();

    if(obj.ST == 1)
    {
        obj.speed = vel;
        obj.course = crs;
    }
    if(obj.ST == 3)
    {
        if(crs >= 0)
            obj.air_dir = crs;

        obj.air_speed = vel;
        obj.TAS = vel >= 0;
    }
    adsb_obj_map.insert(addr,obj);
}

void ADSBManager::handler_pos(QByteArray addr, quint8 ss, bool nic, quint32 alt,
                              bool time, bool odd, double lat, double lon)
{
    ADSBObject obj;
    if(adsb_obj_map.contains(addr))
        obj = adsb_obj_map.take(addr);
    else
        obj = createObject(addr);

    obj.altitude = alt*0.000305;
    obj.ss = ss;
    obj.nic = nic;
    obj.time = time;

    double dLat,dLon;
    double var1,var2,var3;
    qint8 index_lat = -1;
    qint16 mod;
    if((obj.lat_even_cpr >= 0) && (obj.lat_even_cpr <= 1) && (obj.lon_odd_cpr >= 0) && (obj.lon_odd_cpr <= 1))
        index_lat = floor(59.0*obj.lat_even_cpr-60.0*obj.lat_odd_cpr+0.5);

    if(odd)
    {
        obj.lat_odd_cpr = lat;
        obj.lon_odd_cpr = lon;
        obj.time_tag_epoch_odd = QDateTime::currentMSecsSinceEpoch();

        dLat = 360.0/59.0; //6.101
        mod = index_lat-59*floor(index_lat/59); //18
        obj.lat_odd = dLat*(mod+obj.lat_odd_cpr);
        obj.lat_odd = obj.lat_odd >= 270 ? obj.lat_odd-360.0 : obj.lat_odd; //115.16

        var1 = pow(cos(M_PI*obj.lat_odd/180.0),2);
        var2 = 1-cos(M_PI/30.0);
        var3 = acos(1-var2/var1);

        obj.NL_odd = floor(2*M_PI/var3);
    }
    else
    {
        obj.lat_even_cpr = lat;
        obj.lon_even_cpr = lon;
        obj.time_tag_epoch_even = QDateTime::currentMSecsSinceEpoch();

        dLat = 360.0/60.0;
        mod = index_lat-60*floor(index_lat/60);
        obj.lat_even = dLat*(mod+obj.lat_even_cpr);
        obj.lat_even = obj.lat_even >= 270 ? obj.lat_even-360.0 : obj.lat_even;

        var1 = pow(cos(M_PI*obj.lat_even/180.0),2);
        var2 = 1-cos(M_PI/30.0);
        var3 = acos(1-var2/var1);

        obj.NL_even = floor(2*M_PI/var3);
    }

    quint8 ni;
    quint16 m;
    if(obj.NL_odd == obj.NL_even)
    {
        if(obj.time_tag_epoch_even > obj.time_tag_epoch_odd)
        {
            obj.lat = obj.lat_even;

            ni = qMax((const quint8)obj.NL_even,(const quint8)1);
            dLon = 360.0/ni;
            m = floor(obj.lon_even_cpr*(obj.NL_even-1)-(obj.lon_odd_cpr*obj.NL_even)+0.5);
            mod = m-ni*floor(m/ni);
            obj.lon = dLon*(mod+obj.lon_even_cpr);
            obj.lon = obj.lon >= 180 ? obj.lon-360 : obj.lon;
        }
        else
        {
            obj.lat = obj.lat_odd;

            ni = qMax((const quint8)(obj.NL_odd-1),(const quint8)1);
            dLon = 360.0/ni;
            m = floor(obj.lon_even_cpr*(obj.NL_odd-1)-(obj.lon_odd_cpr*obj.NL_odd)+0.5);
            mod = m-ni*floor(m/ni);
            obj.lon = dLon*(mod+obj.lon_odd_cpr);
            obj.lon = obj.lon >= 180 ? obj.lon-360 : obj.lon;
        }
        obj.time_tag = QDateTime::currentMSecsSinceEpoch();
        /*todo calculate global unambigous position*/
    }
//    qDebug()<<Q_FUNC_INFO<<obj.NL_even<<obj.NL_odd<<obj.lat<<obj.lon;
    adsb_obj_map.insert(addr,obj);
}
ADSBObject ADSBManager::createObject(QByteArray addr)
{
    ADSBObject obj;
//    QSettings config(QDir::homePath()+"/.simrad/radar.conf",QSettings::IniFormat);
//    QByteArray m_addr = QByteArray::fromHex(addr);
//    char msb_cc [2];
//    msb_cc[0] = m_addr.at(0);
//    msb_cc[1] = m_addr.at(1) & 0xFC;
//    m_addr = QByteArray((const char*)msb_cc).toHex();
//    QString cc = QString(m_addr.left(4));

    obj.lat_odd = 10000.0;
    obj.lat_even = 10000.0;
    obj.lat = 10000.0;
    obj.lon = 10000.0;
    obj.NL_even = 1;
    obj.NL_odd = 0;
    obj.speed = 0.0;
    obj.course = 0.0;
    obj.air_dir = 0.0;
    obj.air_speed = 0.0;
    obj.TAS = true;
    obj.altitude = 0;
    obj.vert_rate = 0;
    obj.ST = 1;
    obj.IC = false;
    obj.NAC = 0;
    obj.Vert_src = 0;
    obj.emmitter_cat = 0;
    obj.time_tag = QDateTime::currentMSecsSinceEpoch();
    obj.icao = addr; //first 14 bit for country code??
    obj.call_sign = "";
//    obj.country=config.value("CC/"+cc).toString();
    obj.ss = 0;
    obj.nic = false;
    obj.time = false;
//    qDebug()<<cc;

    return obj;
}
 void ADSBManager::handler_call_sign(QByteArray addr, QString call_sign, quint8 EC)
{
//    qDebug()<<Q_FUNC_INFO<<addr<<call_sign<<EC;
     ADSBObject obj;
    if(!adsb_obj_map.contains(addr))
        obj = createObject(addr);
    else
        obj = adsb_obj_map.take(addr);

    obj.call_sign = call_sign;
    obj.icao = addr;
    obj.emmitter_cat = EC;
    obj.time_tag = QDateTime::currentMSecsSinceEpoch();

    adsb_obj_map.insert(addr,obj);
}

ADSBManager::~ADSBManager()
{
}



ADSBReceiver::ADSBReceiver(QObject *parent,QString addr, uint port)
    : QThread(parent),_addr(addr),_port(port)
{
    connected = false;
}
void ADSBReceiver::exitReq()
{
    mutex.lock();
    exit_req = true;
    mutex.unlock();
}
bool ADSBReceiver::isConnected()
{
    bool connect;
    mutex.lock();
    connect = connected;
    mutex.unlock();

    return connect;
}
#define SBS
#include <QTcpSocket>

void ADSBReceiver::run()
{
    QTcpSocket socketDataReceive;
    socketDataReceive.connectToHost(QHostAddress(_addr),_port);
    socketDataReceive.waitForConnected(1000);

    exit_req = false;

    forever
    {
        if(exit_req)
            break;
        if(socketDataReceive.state()==QAbstractSocket::ConnectedState)
        {
            while (socketDataReceive.waitForReadyRead(1000))
            {

                mutex.lock();
                if(!connected)
                    connected = true;
                mutex.unlock();

                if(exit_req)
                    break;

#ifndef SBS
                int adsb_data_len;
                adsb_data_len = 14;
#endif
//                QByteArray datagram = socketDataReceive.read(adsb_data_len);
                QByteArray datagram = socketDataReceive.readAll();

//                qDebug() << Q_FUNC_INFO << datagram.size();
//                qDebug() << Q_FUNC_INFO << datagram.toHex();
                //check data size

                bool byPass = true;
#ifndef SBS
                const unsigned char* data_adsb = (const unsigned char*)datagram.constData();
#else

                const unsigned char* data_adsb = (const unsigned char*)datagram.mid(7,14).constData();
                if(datagram.size()>2)
                    byPass = (datagram.at(2) == 0x01)/* || (datagram.at(2) == 0x05)*/;
#endif
                if(byPass)
                {
                    //header check
                    uint8_t DF = (uint8_t)((data_adsb[0] & 0b11111000)>>3);

                    if(DF != 17 && DF != 20)
                    {
                        qDebug()<<"unproper header";
                        continue;
                    }

                    //CRC check
                    /*
                    */
                    if(DF==17)
                    {
                        if(!isCRCValid(data_adsb,14))
                        {
                            qDebug()<<"crc not valid";
                            continue;
                        }
                    }

                    //ICAO (aircraft address)
#ifndef SBS
                    QByteArray icao = datagram.mid(1,3).toHex();
                    if(DF==20)
                        icao = getMODESICAO(data_adsb,adsb_data_len);
#else
                    QByteArray icao = datagram.mid(8,3).toHex();
//                    if(DF==20)
//                        icao = getMODESICAO(data_adsb,14);
#endif
    //                qDebug()<<icao;

                    //Type Code
                    uint8_t TC = (uint8_t)((data_adsb[4] & 0b11111000)>>3);
                    if(TC < 5)
                        decode_ID(icao,data_adsb);
                    else if(TC >= 5 && TC < 9)
                        continue; //implement next
                    else if(TC >= 9 && TC < 19)
                        decode_Pos(icao,data_adsb);
                    else if(TC == 19)
                        decode_Velocity(icao,data_adsb);

                }

//                qDebug()<<Q_FUNC_INFO<<"Receive datagram with size "<<datagram.size();
            }
        }
        else if(socketDataReceive.state()==QAbstractSocket::UnconnectedState)
        {
            socketDataReceive.connectToHost(QHostAddress(_addr),_port);
            socketDataReceive.waitForConnected(1000);

            mutex.lock();
            if(connected)
                connected = false;
            mutex.unlock();

        }

//        qDebug()<<"state"<<socketDataReceive.state();

    }
    qDebug()<<Q_FUNC_INFO<<"thread terminated";
}
void ADSBReceiver::decode_Velocity(QByteArray addr, const unsigned char *data)
{
    quint8 ST = data[4] & 0x07; //subtype velocity
    bool IC = data[5] & 0x80; //inter change flag
    quint8 NAC = (data[5] & 0x38)>>3; //velocity uncertainly
    bool Vert_Src = data[8] & 0x10; //vertical rate source
    bool Vert_sign = data[8] & 0x08; //vertical rate sign
    quint16 Vert_rate = ((data[8] & 0x07)<<6) | ((data[9] & 0xFC)>>2); //vertical rate
//    bool S_diff = data[10] & 0x80; //diff sign
//    quint8 diff = data[10] & 0x7F; //diff
    qint32 vertical_rate = Vert_sign ? -64*(Vert_rate-1) : 64*(Vert_rate-1);

    double vel;
    double crs = -475;
    if(ST == 1)
    {
        bool S_ew = data[5] & 0x04; //east-west sign
        quint16 V_ew = ((data[5] & 0x03)<<8) | data[6]; //velocity east-west
        bool S_ns = data[7] & 0x80; //north-south sign
        quint16 V_ns = ((data[7] & 0x7F)<<3) | ((data[8] & 0xE0)>>5); //velocity north-south

        double Vwe,Vsn;
        Vwe = S_ew ? -(V_ew-1) : (V_ew-1);
        Vsn = S_ns ? -(V_ns-1) : (V_ns-1);
        vel = sqrt(pow(Vwe,2)+pow(Vsn,2));
        crs=atan2(Vwe,Vsn)*360.0/(2*M_PI);
        crs = crs < 0 ? crs+360 : crs;
//        qDebug()<<Q_FUNC_INFO;
    }
    else if(ST == 3)
    {
        bool crs_stat = data[5] & 0x04; //heading status
        quint16 heading = ((data[5] & 0x03)<<8) | data[6]; //heading
        bool TAS = data[7] & 0x80; //true air speed/Indicated air speed
        vel = (double)(((data[7] & 0x7F)<<3) | ((data[8] & 0xE0)>>5)); //air speed
        vel = TAS ? vel : -vel;

        if(crs_stat)
            crs = heading*360.0/1024;
//        qDebug()<<Q_FUNC_INFO;
    }
    emit signal_vel(addr,ST,IC,NAC,Vert_Src,vertical_rate,vel,crs);

//    qDebug()<<Q_FUNC_INFO;
}

void ADSBReceiver::decode_Pos(QByteArray addr, const unsigned char *data)
{
    //surveillance status
    uint8_t ss = (uint8_t)(data[4] & 0b00000110);

    //NIC suplement-B
    bool nic = (bool)(data[4] & 0b00000001);

    //Altitude
    uint32_t alt = (data[5] << 8) | (data[6] & 0xF0);
    alt >>= 4;
    bool qbit = alt & 0x00000010;
    uint32_t after_qbit = alt & 0x0000000F;
    alt >>= 1;
    alt &= 0xFFFFFFF0;
    alt |= after_qbit;
    alt = qbit ? (alt*25)-1000 : (alt*1000)-1000;
//    alt = alt * 0.000305;

    //time??
    bool time = (bool) (data[6] & 0x08);

    //position
    bool odd = (bool) (data[6] & 0x04);
    qint32 raw_lat,raw_lon;
    quint8 last_data;
    raw_lat = data[6] & 0x00000003;
    raw_lat <<= 15;
    raw_lat |= (data[7] & 0x000000FF)<<7;
    last_data = data[8] & 0xFE;
    last_data >>= 1;
    raw_lat |= (last_data & 0x000000FF);

    raw_lon = data[8] & 0x00000001;
    raw_lon <<= 16;
    raw_lon |= (data[9] & 0x000000FF)<<8;
    raw_lon |= (data[10] & 0x000000FF);

    double lat = (double)raw_lat/131072;
    double lon = (double)raw_lon/131072;

    emit signal_pos(addr,ss,nic,alt,time,odd,lat,lon);
//    qDebug()<<Q_FUNC_INFO<<ss<<nic<<qbit<<alt<<time<<odd<<raw_lat<<raw_lon<<lat<<lon;
}

void ADSBReceiver::decode_ID(QByteArray addr,const unsigned char *data)
{
    //Emitter category
    uint8_t EC = (uint8_t)(data[4] & 0b00000111);

    //call sign
    const char MAP [] = {'#','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
                         '#','#','#','#','#','_','#','#','#','#','#','#','#','#','#','#','#','#','#','#','#',
                         '0','1','2','3','4','5','6','7','8','9','#','#','#','#','#','#'};
    char cs[8];
    uint64_t buf_data = 0x0000000000000000;
    uint64_t res_data = 0x0000000000000000;
    for(int i=0;i<6;i++)
    {
        buf_data = (data[5+i] & 0x00000000000000FF);
        buf_data <<= (7-i)*8;
        res_data |= buf_data;
    }
    const uint64_t MASK = 0xFC00000000000000;
    uint8_t chr;
    for(int i=0;i<8;i++)
    {
        buf_data = MASK & (res_data << (i*6));
        chr = (uint8_t)(buf_data >> 58);
        cs[i] = MAP[chr];
    }
    QString call_sign((const char*)cs);
    call_sign.remove('#');

    emit signal_call_sign(addr,call_sign,(quint8)EC);
}

bool ADSBReceiver::isCRCValid(const unsigned char *data, int len)
{
#ifndef SBS
    const long crc_received = ((data[len-3] & 0x0000FF) << 16) | ((data[len-2] & 0x0000FF) << 8) | (data[len-1] & 0x0000FF);
    const long GEN = 0x1FFF409L;
    long crc = 0x000000L;
    int i;

    len = 11;
    while(len--)
    {
        crc ^= (*data++) << 16;
        for(i=0;i<8;i++)
        {
            crc <<= 1;
            if(crc & 0x1000000)
                crc ^= GEN;
        }
    }
    crc &= 0xFFFFFFFFL;

    return crc == crc_received;
#else
//    qDebug()<<data[len-3]<<data[len-2]<<data[len-1];
    return !(data[len-3] && data[len-2] && data[len-1]);
#endif
}
QByteArray ADSBReceiver::getMODESICAO(const unsigned char *data, int len)
{
    const long crc_received = ((data[len-3] & 0x0000FF) << 16) | ((data[len-2] & 0x0000FF) << 8) | (data[len-1] & 0x0000FF);
    const long GEN = 0x1FFF409L;
    long crc = 0x000000L;
    int i;

    len = 11;
    while(len--)
    {
        crc ^= (*data++) << 16;
        for(i=0;i<8;i++)
        {
            crc <<= 1;
            if(crc & 0x1000000)
                crc ^= GEN;
        }
    }
    crc &= 0xFFFFFFFFL;
    const long icao = crc ^ crc_received; //956558
    char ptr[3];
    ptr[2] = (char)(icao & 0x000000FF);
    ptr[1] = (char)((icao >> 8) & 0x000000FF);
    ptr[0] = (char)((icao >> 16) & 0x000000FF);

    return QByteArray((const char*)ptr);
}

ADSBReceiver::~ADSBReceiver()
{
}

