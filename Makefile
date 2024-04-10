CC = g++
CFLAGS = -g -lpthread -Wall -Wextra
OBJS = mitm_attack.o pharm_attack.o Net.o
ELF = mitm_attack pharm_attack
.PHONY = all clear

all: $(ELF)
	
mitm_attack: Net.o mitm_attack.cpp
	$(CC) -o mitm_attack $^ $(CFLAGS)

pharm_attack: Net.o pharm_attack.cpp
	$(CC) -o pharm_attack $^ $(CFLAGS)

%.o: %.cpp
	$(CC) -o $@ $< $(CFLAGS) -c

clean:
	@rm -f $(OBJS) $(ELF)
