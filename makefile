
main: aes.c
	gcc aes.c -o aes 
	./aes key.txt plainText1.txt sbox.txt invSbox.txt   

clean: 
	rm main