#
#         Europäisches Institut für Systemsicherheit
#   Proktikum "Kryptographie und Datensicherheitstechnik"
#
# Versuch 5:Keymanagement mit dem Kerberos-Protokoll
#
#-------------------------------------------------------------
#

include ../include/Makefile.Settings

SRC	= alice.c bob.c server.c kerberos.c
HEADER	= kerberos.h
OBJ	= $(SRC:%.c=%.o)
BINS	= alice bob server
LFLAGS	+= $(CURSESLIBS)

all:	$(BINS)

alice:		alice.o		kerberos.o
	$(CC) -o alice alice.o kerberos.o $(LFLAGS)
bob:		bob.o		kerberos.o
	$(CC) -obob bob.o kerberos.o $(LFLAGS)
server:		server.o	kerberos.o
	$(CC) -o server server.o kerberos.o $(LFLAGS)

alice.o:	alice.c		kerberos.h
bob.o:		bob.c		kerberos.h
server.o:	server.c	kerberos.h
kerberos.o:	kerberos.c	kerberos.h

#------------------------------------------------------------------------------

clean:
	-rm -f *.o *~ *% $(BINS)
