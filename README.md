# aes-
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


