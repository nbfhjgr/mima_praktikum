/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
 **                                                           *
 **************************************************************
 **
 ** server.c: Hauptprogram für den Security-Server
 **/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *ServerName = "Server";
/* #define BADSERVER *//* wenn definiert, wird der Verkehr zwischen den beiden Partnern abgehört. */

struct UserEntry {
	const char *Name; /* name des Benutzers */
	DES_key Key; /* Geheimer Schlüssel */
};

/* tabelle der Benutzer mit ihren geheimen Schlüsseln */
const struct UserEntry UserTable[] = { { "Alice", { 0x12, 0x7f, 0x5f, 0xac,
		0x09, 0xf3, 0xd2, 0xa0 } }, { "Bob", { 0x7f, 0xab, 0x12, 0xa0, 0x4d,
		0xc6, 0x81, 0x02 } }, { "Carol", { 0x6f, 0x18, 0xa5, 0xcf, 0x11, 0x4e,
		0xab, 0xf0 } } };

DES_data phone_iv1, phone_iv2;
DES_ikey ikey_ab;

/* ------------------------------------------------------------------------------ */

static char DeCrypt1(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char m;
	DES_OFB(ikey_ab, phone_iv1, &c, sizeof(char), &m);
	return m;
}

static char DeCrypt2(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char m;
	DES_OFB(ikey_ab, phone_iv2, &c, sizeof(char), &m);
	return m;
}

void PhoneAbhoeren(NetName a, NetName b) {
	char buf1[256],buf2[256];
	int from1=0,from2=1;
	memset(&buf1,0,sizeof(char)*256);
	memset(&buf2,0,sizeof(char)*256);
	// try to abhören
	TapConnection TapCon = TapConnect(MakeNetName2(a), MakeNetName2(b));
	if (!TapCon){
		fprintf(stderr,"start to ABHÖREN failed!\n");
		return ;
	}

	// skip the initial data exchange
	VTapReceive(TapCon,buf1,sizeof(buf1),&from1);
	VTapReceive(TapCon,buf2,sizeof(buf2),&from2);

	// phone abhören
	PhoneTap_Init(a,b);
	PhoneTap(TapCon, a, b, DeCrypt1, DeCrypt2);
	printf("the session is closed! return to wait connection.\n");
}

/* ------------------------------------------------------------------------------ */
int main(int argc, char **argv) {
	Connection con; /* Verbindung vom Clienten d.h. Alice */
	PortConnection port; /* Das Port des Servers */
	Message msg1, msg2, msg_S2A;
	ULONG ts, key_high, key_low;			//timestamp, key_AB
	DES_key *key_sa, *key_sb;

	int i, a_pos, b_pos, badserver;
	char *ServerNetName ;

	/* Konstruktion eindeutiger Namen für das Netzwerksystem:
	 * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
	 * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
	 * Dieser Netzname wird nur für den Verbindungsaufbau über das
	 * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
	 * ausgetauschten Namen sind OutName, OthersName und ServerName!
	 */

	ServerNetName = MakeNetName2(ServerName);
	badserver = (argc > 1); /* Bei Argument: Bösen Server spielen! */
	if (badserver)
		printf("**** Warnung, dieser Server ist kompromitiert ****\n");

	/***************  Globales Port eröffnen  ***************/
	if (!(port = OpenPort(ServerNetName))) {
		fprintf(stderr, "Kann das Serverport nicht erzeugen: %s\n",
				NET_ErrorText());
		exit(20);
	}

	while (1) { /* Für immer ... */

		/**************  Auf Verbindung auf dem Port warten  ****************/
		printf("\nWarten auf eine Verbindung ....\n");
		if (!(con = WaitAtPort(port))) {
			fprintf(stderr, "WaitAtPort ging schief: %s\n", NET_ErrorText());
			exit(20);
		}

		/*****************  Request von 'Alice' einlesen  *******************/
		GetMessage("Clinet", con, &msg1, Alice_Server);
		printf("SERVER: Key-Request von %s für Verbindung mit %s\n",
				msg1.body.Alice_Server.A, msg1.body.Alice_Server.B);

		/* Suchen der beiden Partner in der Benutzertabelle */
		a_pos = b_pos = -1;
		for (i = 0; i < TABSIZE(UserTable); i++) {
			if (!strcmp(UserTable[i].Name, msg1.body.Alice_Server.A))
				a_pos = i;
			else if (!strcmp(UserTable[i].Name, msg1.body.Alice_Server.B))
				b_pos = i;
		}

		if (a_pos == -1) {
			printf("Fehler: Benutzer %s nicht gefunden.\n",
					msg1.body.Alice_Server.A);
			msg2.typ = Error;
			strcpy(msg2.body.Error.ErrorText, "Unbekannter Benutzer ");
			strcat(msg2.body.Error.ErrorText, msg1.body.Alice_Server.A);
			PutMessage("Client", con, &msg2);
		} else if (b_pos == -1) {
			printf("Fehler: Benutzer %s nicht gefunden.\n",
					msg1.body.Alice_Server.B);
			msg2.typ = Error;
			strcpy(msg2.body.Error.ErrorText, "Unbekannter Benutzer ");
			strcat(msg2.body.Error.ErrorText, msg1.body.Alice_Server.B);
			PutMessage("Client", con, &msg2);
		} else {
			/*>>>>                                                 <<<<*
			 *>>>> AUFGABE: - Schlüssel für Alice und Bob erzeugen <<<<*
			 *>>>>          - Antwortpaket an Alice senden         <<<<*
			 *>>>>          - Kommunikation abhören                <<<<*
			 *>>>>                                                 <<<<*/

			// Generieren den Key_AB Schlüssel
			key_high = RandomNumber();
			key_low = RandomNumber();
			DES_key key_ab;
			memcpy(&key_ab, &key_high, sizeof(ULONG));
			memcpy(&key_ab[4], &key_low, sizeof(ULONG));

			// Generieren TimeStamp
			ts = GetCurrentTime();

			// Generieren neue Antwort von Alice
			msg_S2A.typ = Server_Alice;
			memcpy(&msg_S2A.body.Server_Alice.Serv_A1.Key_AB, &key_ab,
					sizeof(DES_key));
			strcpy(msg_S2A.body.Server_Alice.Serv_A1.Receiver,
					msg1.body.Alice_Server.A);
			msg_S2A.body.Server_Alice.Serv_A1.TimeStamp = ts;

			memcpy(&msg_S2A.body.Server_Alice.Serv_B1.Key_AB, &key_ab,
					sizeof(DES_key));
			strcpy(msg_S2A.body.Server_Alice.Serv_B1.Receiver,
					msg1.body.Alice_Server.B);
			msg_S2A.body.Server_Alice.Serv_B1.TimeStamp = ts;

			// Verschlüsseln den Inhalt von Alice
			key_sa = &UserTable[a_pos].Key;
			DES_ikey ikey_sa;
			DES_GenKeys(*key_sa, 0, ikey_sa);
			DES_data iv;
			memset(&iv, 0, sizeof(DES_data));

			ServerData toEncData;
			memcpy(&toEncData, &msg_S2A.body.Server_Alice.Serv_A1,
					sizeof(ServerData));

			DES_OFB(ikey_sa, iv, &toEncData, sizeof(ServerData),
					&msg_S2A.body.Server_Alice.Serv_A1);

			// Verschlüsseln den Inhalt von Bob
			key_sb = &UserTable[b_pos].Key;
			DES_ikey ikey_sb;
			DES_GenKeys(*key_sb, 0, ikey_sb);
			memset(&iv, 0, sizeof(DES_data));

			memcpy(&toEncData, &msg_S2A.body.Server_Alice.Serv_B1,
					sizeof(ServerData));
			DES_OFB(ikey_sb, iv, &toEncData, sizeof(ServerData),
					&msg_S2A.body.Server_Alice.Serv_B1);

			PutMessage("Client", con, &msg_S2A);

			if (badserver) {
				DES_GenKeys(key_ab,0,ikey_ab);
				printf("start Abhörprogramm...\n");
				PhoneAbhoeren(msg1.body.Alice_Server.A,
						msg1.body.Alice_Server.B);
			}

		}

		/* Verbindung zu Alice abbauen */
		DisConnect(con);

	}

	return 0;
}
