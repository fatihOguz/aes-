/******************************************************************************************

Chipper keyden aldığım ilk round key ile 

9 rounddan oluşan 
	SubBytes
	ShiftRows
	MixColumns
	ve son olarak yeni bir anahtar oluşturup döngü devam ettirilir.

Final Round 
	SubBytes
	shiftRows
	addroundkey
Sonuç--> Chipper Text


	Step1
	Substitute Bytes:
	Orjinal mesaj matrisin 8 bitlik bilgilerini Sbox a yerleştirilme işlemini yapar
	
	Step2
	Shift Rows:
	matrisin satırının index numarasınca sola shift etme işlemi

	Step3
	Mix Matrix:
	matrisin 1.colon ile bir matris ile çarpılıp kendi kolanuna konulması


	Step4
	AddRoundKey:
	matrisimizin anahtar matrisi ile xor lanması işlemi


*********************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
# include <assert.h> 

// matrisler için size bilgileri 
#define KEY_SIZE 4
#define STATE_SIZE 4
#define SBOX_SIZE 16
#define MAX_ROUNDS 11
#define SBOX_LOOKUP(lookup_box, num) lookup_box[(num) >> 4][(num) & 0x0F];


// anahtar matrisi
uint8_t static key[KEY_SIZE][KEY_SIZE];
// state matrisi
uint8_t static state[STATE_SIZE][STATE_SIZE];
// orginal mesajımı tutan matrisim
uint8_t static orig_msg[STATE_SIZE][STATE_SIZE];
// substitute box matrisi
uint8_t static sbox[SBOX_SIZE][SBOX_SIZE];
// deşifrelemede kullandığım substitute box matrisi
uint8_t static inv_sbox[SBOX_SIZE][SBOX_SIZE];
// roundlara göre anahtar matrisi
uint8_t static sub_keys [MAX_ROUNDS][KEY_SIZE][KEY_SIZE];
int initialize_called;


/**
	command arguman line ile alınan file ları matris yapar
	anahtar üretimini gerçekleştirip aes şifreleme algoritmasının başlangıç durumuna hazırlar
	*/
void initialize(char * key_file, char * state_file, char* sbox_file, char* inv_sbox_file);
/**
	SubBytes
	ShiftRows
	MixColumns
	addRoundKey
	şeklinde 9 round ve final round unda bu işlemden mix columns haricinde bir kere daha 
	gerçekleyip chipper text e ulaşır.
	*/
void encrypt();
/**
	encrypt fonksiyonunun geriye yönelik işlemlerini yapıp orjinal metne ulaşır.
	*/
void decrypt();

uint8_t * getState();
/**
	ekrana state basar
	*/
void printState();
/**
	ekrena subkeys basar
	*/
void printSubKeys();
/**
	programın başarılı bi şekilde bitip bitmediği bilgisini ekranda gösterir.
	*/
void assertStateIsOrigMesg();
/**
	subkeys ve s box matrisleri ile işleme girip bir anahtar üretir
	*/
void generateSubkeys();
/**
	command argumant line dan aldığı file ları uygun bir şekilde matris's çevirir.
*/
void initFromFile(int size, uint8_t matrix[size][size], char * file_name);
/**
Step4
	AddRoundKey:
	matrisimizin anahtar matrisi ile xor lanması işlemi
*/
void addRoundKey(int round);
/**
Shift Rows:
	matrisin satırının index numarasınca sola shift etme işlemi
	bu fonksiyon şifreleme için kullanılır
	deşifrelemede 1 sağ yapılmalı*/	
void shiftRows();
/**
Shift Rows:
	matrisin satırının index numarasınca sağa shift etme işlemi
	bu fonksiyon deşifreleme için kullanılır
	şifrelemede 1 sola yapılmalı*/
void invShiftRows();
/** 
	Shift row işlemi için yardımcı fonksiyondur.
	1 kere sola shift etme işlemini yapar
	*/
void helperShiftRow(int row);
/**
Substitute Bytes:
	Orjinal mesaj matrisin 8 bitlik bilgilerini Sbox a yerleştirilme işlemini yapar
	*/
void subByte(uint8_t sbox_to_use[SBOX_SIZE][SBOX_SIZE]);
/**
Step3
	Mix Matrix:
	matrisin 1.colon ile bir matris ile çarpılıp kendi kolanuna konulması

*/
void mixColumns();
/**
	mix Columns işleminin tersini gerçekleştirir
	deşifrelemede kullanılır
	*/
void invMixColumns();
/**matrisi ekrana basar*/
void printMatrix(int size, uint8_t matrix[size][size]);
// https://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t gmult(uint8_t a, uint8_t b);




/**********************************************************************************************/

int main(int argc, char *argv[])
{
    if(argc < 5) {
        printf("ERROR: expecting 4 paths \"key_file, plaintext_file, sbox_file, inv_sbox_file\"\n");
        exit(-1);
    }

    char* key_file = NULL, *state_file = NULL, *sbox_file = NULL, *inv_sbox_file = NULL;
    key_file = argv[1];
    state_file = argv[2];
    sbox_file = argv[3];
    inv_sbox_file = argv[4];

    initialize(key_file, state_file, sbox_file, inv_sbox_file);
    encrypt();
    decrypt();
    assertStateIsOrigMesg();

   
    return 0;
}


/**********************************************************************************************/




void initialize(char * key_file, char * state_file, char* sbox_file, char* inv_sbox_file) {
    initFromFile(KEY_SIZE, key, key_file);
    initFromFile(STATE_SIZE, state, state_file);
    initFromFile(SBOX_SIZE, sbox, sbox_file);
    initFromFile(SBOX_SIZE, inv_sbox, inv_sbox_file);
    memcpy(orig_msg, state, sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    generateSubkeys();
    initialize_called = 1;
}
/**********************************************************************************************/

void encrypt() {

    assert(initialize_called);

    printf("\nENCRYPTION PROCESS\n");
    printf("------------------\n");

    // curr_round kaçıncı round olduğunu tutar 
    int curr_round = 0;
    // state durumunu ekrana basar
    printState(curr_round);


    // başlangıç round u
    addRoundKey(curr_round);
    curr_round += 1;
    printState(curr_round);

    // 9 defa round tekrarlanır
    while (curr_round < 10) {
        subByte(sbox);
        shiftRows();
        mixColumns();
        addRoundKey(curr_round);
        curr_round += 1;
        printState(curr_round);
    }

    // final round
    subByte(sbox);
    shiftRows();
    addRoundKey(curr_round);
    curr_round += 1;
    printState(curr_round);
}

/**********************************************************************************************/
void decrypt() {
    printf("\n\nDECRYPTION PROCESS\n");
    printf("------------------\n");

    // start at 11 to print cipher first
    int curr_round = MAX_ROUNDS;

     printState(curr_round);
    curr_round -= 1;

    // final round
    addRoundKey(curr_round);
    invShiftRows();
    subByte(inv_sbox);
    printState(curr_round);
    curr_round -= 1;

    // 9 rounds
    while (curr_round > 0) {
        addRoundKey(curr_round);
        invMixColumns();
        invShiftRows();
        subByte(inv_sbox);
        printState(curr_round);
        curr_round -= 1;
    }

    // initial round
    addRoundKey(curr_round);
    printState(curr_round);
    printf("\nEND of Decryption\n------------------\n");
}
/**********************************************************************************************/

uint8_t * getState() {
    uint8_t * state_array = malloc(sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    for(int r=0; r<STATE_SIZE; r++) {
        for(int c=0; c<STATE_SIZE; c++) {
            state_array[r * STATE_SIZE + c] = state[r][c];
        }
    }
    return state_array;
}
/**********************************************************************************************/
/* hangi roundda olduğumuzu eğer başlamadıysak metnimizi roundlar bitti ise şifreli metni bastırır */
void printState(int curr_round) {
    if(curr_round == 0)
        printf("\nPlain Text:\n");
    else if(curr_round == 1)
        printf("\nInital Round (Only AddRoundkey):\n-----------\n");
    else if(curr_round == MAX_ROUNDS)
        printf("\nCipherText (Last Round):\n");
    else
        printf("\nRound %d\n-----------\n", curr_round-1);
    for(int c=0; c<STATE_SIZE; c++) {
        for(int r=0; r<STATE_SIZE; r++) {
            printf("%02x ", state[r][c]);
        }
        printf("  ");
    }
    printf("\n");
}
/**********************************************************************************************/

void printSubKeys() {
    printf("\nKey Schedule:\n");
    for(int k=0; k<MAX_ROUNDS; k++) {
        for(int c=0; c<STATE_SIZE; c++) {
            for(int r=0; r<STATE_SIZE; r++) {
                printf("%x", sub_keys[k][r][c]);
            }
            printf(",");
        }
        printf("\n");
    }
    printf("\n");
}

/**********************************************************************************************/
void assertStateIsOrigMesg() {
    for(int r=0; r<STATE_SIZE; r++) {
        for(int c=0; c<STATE_SIZE; c++) {
            if (state[r][c] != orig_msg[r][c]){
                printf("\nAssertion Failure: State and original message are not same!\n");
                assert(state[r][c] == orig_msg[r][c]);
            }
        }
    }
    printf("\nAssertion Passed: State is same as original message\n");
}







/**********************************************************************************************/




/*anahtar üretimini gerçekleştirir*/
void generateSubkeys() {

    int curr_round = 0;

    // ilk round için key leri kopyala
    memcpy(sub_keys[curr_round], key, sizeof(uint8_t) * STATE_SIZE * STATE_SIZE);
    curr_round += 1;

    // round sabitleri
    uint8_t rci[11] = {0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

    /*çalışmakta olan round 10.rounda gelene kadar*/
    while (curr_round < MAX_ROUNDS) {

        // önceki roundları son sütuna kopyala ve üst baytı alta taşı
        sub_keys[curr_round][0][0] = sub_keys[curr_round-1][1][STATE_SIZE-1];
        sub_keys[curr_round][1][0] = sub_keys[curr_round-1][2][STATE_SIZE-1];
        sub_keys[curr_round][2][0] = sub_keys[curr_round-1][3][STATE_SIZE-1];
        sub_keys[curr_round][3][0] = sub_keys[curr_round-1][0][STATE_SIZE-1];
        
        // Sbox kullanarak ilk sütunu eşle
        sub_keys[curr_round][0][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][0][0]);
        sub_keys[curr_round][1][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][1][0]);
        sub_keys[curr_round][2][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][2][0]);
        sub_keys[curr_round][3][0] = SBOX_LOOKUP(sbox, sub_keys[curr_round][3][0]);

        
        sub_keys[curr_round][0][0] ^= rci[curr_round];

        // bir önceki roundların ilk sütunları ile xor lar
        sub_keys[curr_round][0][0] ^= sub_keys[curr_round-1][0][0];
        sub_keys[curr_round][1][0] ^= sub_keys[curr_round-1][1][0];
        sub_keys[curr_round][2][0] ^= sub_keys[curr_round-1][2][0];
        sub_keys[curr_round][3][0] ^= sub_keys[curr_round-1][3][0];

        // diğer 3 sütün işlemi
        for (int c=1; c<STATE_SIZE; c++){
            for (int r=0; r<STATE_SIZE; r++){
                // önceki roundun c sütunu ile önceki sütununu xor la
                sub_keys[curr_round][r][c] = sub_keys[curr_round][r][c-1] ^ sub_keys[curr_round-1][r][c];
            }
        }
        curr_round += 1;
    }

    printSubKeys();
}

/**********************************************************************************************/
void initFromFile(int size, uint8_t matrix[size][size], char * file_name) {
    FILE *file;
    if ((file = fopen(file_name, "r")) == NULL){
        printf("Error! opening file");
        exit(1);
    }

    // dosyayı okur
    unsigned int input_var;
    if (size == STATE_SIZE) { 
        for(int c=0; c<size; c++) {
            for(int r=0; r<size; r++) {
                fscanf(file, "%x", &input_var);
                // her değişken bir bit olmalı
                assert(input_var<=255);
                matrix[r][c] = (uint8_t)input_var;
            }
        }
    }    
    else {  // sbox
        for(int r=0; r<size; r++) {
            for(int c=0; c<size; c++) {
                fscanf(file, "%x", &input_var);
                // her değişken bir bit olmalı
                assert(input_var<=255);
                matrix[r][c] = (uint8_t)input_var;
            }
        }
    }
    fclose(file);
}
/**********************************************************************************************/

void addRoundKey(int round) {
	printf("add round key\n");
    for(int r=0; r<STATE_SIZE; r++) {
        for (int c=0; c<STATE_SIZE; c++) {
            state[r][c] ^= sub_keys[round][r][c];
        }
    }
}
/**********************************************************************************************/

void shiftRows() {
	printf("Shift Rows\n");
    // 1. satırı 1 byte kaydır
    helperShiftRow(1);
     // 2. satırı 2 byte kaydır
    helperShiftRow(2);
    helperShiftRow(2);
    // 3. satırı 3 byte kaydır
    helperShiftRow(3);
    helperShiftRow(3);
    helperShiftRow(3);
}
/**********************************************************************************************/
/* şifrelerken satır ile kaydırma sayısı aynı idi*/
/*ancak bu fonksiyon terse gidicek ve aynı yönde 1 ters yapabilmesi için*/
/*bu kaydırma işlemi 4 e tamamlanmalı*/
/*değerler 4 bit ile temsil ediliyor çünkü*/
void invShiftRows() {
	printf("shift rows\n");
     // 1. satırı 3 byte kaydır
    helperShiftRow(1);
    helperShiftRow(1);
    helperShiftRow(1);
     // 2. satırı 2 byte kaydır
    helperShiftRow(2);
    helperShiftRow(2);
     // 3. satırı 1 byte kaydır
    helperShiftRow(3);
}

/*satırı sadece 1 birim shift eder*/
void helperShiftRow(int row) {
   
    uint8_t temp = state[row][0];
    state[row][0] = state[row][1];
    state[row][1] = state[row][2];
    state[row][2] = state[row][3];
    state[row][3] = temp;
}

/**********************************************************************************************/
void subByte(uint8_t sbox_to_use[SBOX_SIZE][SBOX_SIZE]) {
	printf("subByte\n");
    for(int r=0; r<STATE_SIZE; r++) {
        for (int c=0; c<STATE_SIZE; c++) {
            state[r][c] = SBOX_LOOKUP(sbox_to_use, state[r][c]);
        }
    }
}




/**********************************************************************************************/
// matrisin her kolonunu matris ile çarpım kendi yerine koyma işlemini gerçekleştirir
void mixColumns() {
	printf("Mix Columns\n");
    uint8_t temp1, temp2, temp3, temp4;
    
    for (int c=0; c<STATE_SIZE; c++) {
        temp1 = gmult(2, state[0][c]) ^ gmult(3, state[1][c]) ^ gmult(1, state[2][c]) ^ gmult(1, state[3][c]);
        temp2 = gmult(1, state[0][c]) ^ gmult(2, state[1][c]) ^ gmult(3, state[2][c]) ^ gmult(1, state[3][c]);
        temp3 = gmult(1, state[0][c]) ^ gmult(1, state[1][c]) ^ gmult(2, state[2][c]) ^ gmult(3, state[3][c]);
        temp4 = gmult(3, state[0][c]) ^ gmult(1, state[1][c]) ^ gmult(1, state[2][c]) ^ gmult(2, state[3][c]);

        state[0][c] = temp1;
        state[1][c] = temp2;
        state[2][c] = temp3;
        state[3][c] = temp4;
    }
}





/**********************************************************************************************/
	// deşifreleme için mixColumns işlemini yapar
void invMixColumns() {
	printf("Mix Columns\n");
    uint8_t temp1, temp2, temp3, temp4;
    
    for (int c=0; c<STATE_SIZE; c++) {
        temp1 = gmult(0x0e, state[0][c]) ^ gmult(0x0b, state[1][c]) ^ gmult(0x0d, state[2][c]) ^ gmult(0x09, state[3][c]);
        temp2 = gmult(0x09, state[0][c]) ^ gmult(0x0e, state[1][c]) ^ gmult(0x0b, state[2][c]) ^ gmult(0x0d, state[3][c]);
        temp3 = gmult(0x0d, state[0][c]) ^ gmult(0x09, state[1][c]) ^ gmult(0x0e, state[2][c]) ^ gmult(0x0b, state[3][c]);
        temp4 = gmult(0x0b, state[0][c]) ^ gmult(0x0d, state[1][c]) ^ gmult(0x09, state[2][c]) ^ gmult(0x0e, state[3][c]);

  
        state[0][c] = temp1;
        state[1][c] = temp2;
        state[2][c] = temp3;
        state[3][c] = temp4;
    }
}
/**********************************************************************************************/

/*ekrana matrix basar*/
void printMatrix(int size, uint8_t matrix[size][size]) {
    printf("\n");
    for(int r=0; r<size; r++) {
        for(int c=0; c<size; c++) {
            printf("%02x ", matrix[r][c]);
        }
        printf("\n");
    }
    printf("\n");
}







// https://en.wikipedia.org/wiki/Finite_field_arithmetic
uint8_t gmult(uint8_t a, uint8_t b) {
	uint8_t p = 0; 
	while (a && b) {
            if (b & 1) 
                p ^= a; 

            if (a & 0x80) 
                a = (a << 1) ^ 0x11b; 
            else
                a <<= 1; 
            b >>= 1; 
	}
	return p;
}

