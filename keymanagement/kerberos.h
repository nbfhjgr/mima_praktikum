/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Praktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
**                                                           *
**************************************************************
**
** kerberos.h: Headerfile für alice, bob und den server.
**/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <network.h>

/* Lebensdauer der Nachrichten bzw. Schlüssel in 1/1000 Sekunden. Eine
 * Nachricht, die älter als LifeTime ist, könnte eine Replay-Attacke
 *  sein. */
#define LifeTime 1000*600

/* ErrorStr bezeichnet den Typ, der für die Übertragung von Fehlermeldungen
 * benutzt wird. */
typedef char ErrorStr[80];

/* Mögliche Nachrichtentypen zwischen Alice, Bob und dem Server */
typedef enum { Alice_Server, Server_Alice, Alice_Bob, Bob_Alice, Error } MsgType;

/* Daten vom Server zu Alice bzw. Bob. Diese bestehen aus einem
 * TimeStamp, einer Lifetime-Angabe, dem Namen des Empfängers und dem
 * Schlüssel, der für die Kommunikation zwischen Alice und Bob benutzt
 * werden soll */
typedef struct {
  int TimeStamp;
  DES_key Key_AB; /* Schlüssel, vom Server generiert */
  NetName Receiver;
} ServerData;


/* Die Authdaten werden zwischen Alice und Bob ausgetaucht, um zu
 * überprüfen, ob die andere Seite wirklich auch im Besitzt von KEY_ab
 * ist. */
typedef struct {
  NetName Name;  /* Name des Partners */
  int Rand;      /* für die Authentifikation */
} AuthData;


/* Die eigentliche Nachricht besteht aus einem Typ-Feld (TYP), welches
 * eine Variante eines Union, die diesen Nachrichtentyp repräsentiert,
 * selektiert. */
typedef struct {
  MsgType typ;
  union {
    struct { /* Alice an den Server: Eigener Name und der gewünschte Partner */
      NetName A,B;
    } Alice_Server;
    struct { /* Server an Alice (verschlüsselt mit KEY_as) : Server-
	      * Data für Alice und für Bob (verschlüsselt mit KEY_BS) */
      ServerData Serv_A1, Serv_B1;
    } Server_Alice;
    struct { /* Alice an Bob: ServerDaten (verschlüsselt mit KEY_bs) und
	      * Authentifikationsdaten (verschlüsselt mit KEY_ab) */
      ServerData Serv_B2;
      AuthData Auth_A2;
    } Alice_Bob;
    struct { /* Bob an Alice: "beantwortete" Authentifikations-Daten,
	      * verschlüsselt mit KEY_ab */
      AuthData Auth_B3;
    } Bob_Alice;
    struct { /* Fehlermeldung als Klartext-String, wenn irgend etwas
	      * schief gegangen ist. */
      ErrorStr ErrorText;
    } Error;
  } body;
} Message;

extern void  PutMessage(const NetName name, Connection con, Message *m);
extern void  GetMessage(const NetName name, Connection con, Message *m, MsgType typ);
extern int   SwitchRandNum(int x);

