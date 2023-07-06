cli : client.c libmysock.a ser
	gcc -o client client.c -L. -lmysocket -lpthread -lm

ser : server.c libmysock.a 
	gcc -o server server.c -L. -lmysocket -lpthread -lm

libmysock.a : mysocket.o 
	ar rcs libmysock.a mysocket.o 

mysocket.o : mysocket.c
	gcc -c mysocket.c  -lpthread -lm 

clean :
	rm -f mysocket.o client server libmysock.a 
