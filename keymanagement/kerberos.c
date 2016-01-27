/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
 **                                                           *
 **************************************************************
 **
 ** kerberos.c: Hilfsroutinen für den Keymanagement-Versuch
 **/

#include "kerberos.h"
#include <pwd.h>

/*
 * Sendet die Nachricht M über die Connection CON. Treten dabei keine
 * Fehler auf, liefert die Funktion 1 zurück. Kommt es zu einem
 * (Kommunikations-) Fehler, wird eine Fehlermeldung ausgegeben und
 * das Programm terminiert.  NAME ist der Netname des Adressaten
 * der Nachricht. NAME wird nur für die Ausgabe einer eventuellen
 * Fehlermeldung benötigt.  
 */
void PutMessage(const NetName name, Connection con, Message *m) {
	int wcnt;

	wcnt = Transmit(con, m, sizeof(Message));
	if (wcnt != sizeof(Message)) {
		fprintf(stderr, "Fehler beim Senden an %s: %s\n", name,
				NET_ErrorText());
		exit(20);
	}
}

/*
 * Empfängt eine Nachricht von der Connection CON und speichert sie
 * in *M. 
 * Kommt es zu einem Kommunikationsfehler, ist der Nachrichtentyp falsch
 * oder ist die Nachricht selbst eine Fehlernachricht, wird eine
 * entsprechende Fehlermeldung ausgegegen und das Programm terminiert.
 *
 * NAME ist der Name des Senders der Nachricht. Er wird nur für die Ausgabe
 * der Fehlermeldung benötigt.
 */

void GetMessage(const NetName name, Connection con, Message *m, MsgType typ) {
	int rcnt;

	rcnt = Receive(con, m, sizeof(Message));
	if (rcnt != sizeof(Message)) {
		fprintf(stderr, "Fehler beim Empfangen von %s: %s\n", name,
				NET_ErrorText());
		exit(20);
	}

	if (m->typ == Error) {
		fprintf(stderr, "Fehlernachricht von %s: %s\n", name,
				m->body.Error.ErrorText);
		exit(20);
	}

	if (m->typ != typ) {
		fprintf(stderr, "Falsche Nachricht von %s empfangen.\n", name);
		exit(20);
	}
}

/*
 * SwitchRandNum(x) führt die "Fortschaltung" der Zufallszahl X durch
 */

int SwitchRandNum(int x) {
	/*>>>>                                                  <<<<*/
	/*>>>>  Aufgabe: Zufallszahl X 'geeignet' fortschalten  <<<<*/
	/*>>>>                                                  <<<<*/
	return x+1000;
}

char *MakeNetName2(const char *name)
{
  //const char *username = getlogin();
	struct passwd *pass=getpwuid(getuid());
	const char *username=pass->pw_name;
  char *res;
  int len;

  len = (name?strlen(name):0) + strlen(username)+2;

  if (!(res=malloc(len))) {
    fprintf(stderr,"FATAL ERROR in MakeNetName: out of memory\n");
    exit(20);
  }

  strcpy(res,username);
  if (name && *name) {
    strcat(res,"_");
    strcat(res,name);
  }

  return res;
}
