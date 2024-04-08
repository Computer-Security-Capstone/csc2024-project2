all: 
	g++ mitm_attack.cpp Net.cpp -g -o mitm_attack -Wall -Wextra
	sudo ./mitm_attack enp0s17