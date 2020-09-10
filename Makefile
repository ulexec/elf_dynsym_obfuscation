all:
	gcc -N -static -nostdlib resolver.c -o egg
	gcc -g dsymobf.c libelfmaster.a -I /opt/elfmaster/include/ -o dsymobf
	gcc -no-pie test.c -s -o test
	gcc -no-pie test2.c -s -o test2 -lpthread
clean:
	rm -f egg
	rm -f test
	rm -f test2
	rm -f dsymobf
