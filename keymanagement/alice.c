/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
 **                                                           *
 **************************************************************
 **
 ** alice.c: Hauptprogram für den Kommunikationspartner ALICE
 **/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *OurName = "Alice";
const char *OthersName = "Bob";
const char *ServerName = "Server";

/* Der geheime, gemeinsame Schlüssel zwischen dem Server und Alice */
DES_key Key_AS = { 0x12, 0x7f, 0x5f, 0xac, 0x09, 0xf3, 0xd2, 0xa0 };

/* Der vom Server generierte Schlüssel für die Kommunikation mit Bob 
 * in der internen Darstellung (generiert mit DES_GenKeys() */
DES_ikey iKey_AB;

/* Zur Ver- und Entschlüsselung der ausgetauschten Daten wird der
 * DES im Output Feedback Mode eingesetzt, weil hier ohne großen
 * Aufwand auch Datenblöcke, deren Länge nicht durch 8 teilbar sind,
 * bearbeitet werden können. Die Initialisierungsvektoren IV für die
 * heweilige Verschlüsselung werden in IV1 und IV2 gespeichert. */
DES_data phone_iv1, phone_iv2;

/* ------------------------------------------------------------------------------ */

/*
 * EnCrypt(c) : Verschlüsselt C mit KEY_AB/PHONE_IV1
 */

static char EnCrypt(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char cipher;
	DES_OFB(iKey_AB, phone_iv1, &c, sizeof(char), &cipher);
	return cipher;
}

/*
 * DeCrypt(c) : Entschlüsselt C mit KEY_AB/PHONE_IV2
 */

static char DeCrypt(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char m;
	DES_OFB(iKey_AB, phone_iv2, &c, sizeof(char), &m);
	return m;
}

/* ------------------------------------------------------------------------------ */

int main(int argc, char **argv) {
	Connection con;
	Message msg1, msg2, msg3;
	char *OurNetName, *OthersNetName, *ServerNetName;

	/* Konstruktion eindeutiger Namen für das Netzwerksystem:
	 * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
	 * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
	 * Dieser Netzname wird nur für den Verbindungsaufbau über das
	 * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
	 * ausgetauschten Namen sind OutName, OthersName und ServerName!
	 */

	OurNetName = MakeNetName2(OurName);
	OthersNetName = MakeNetName2(OthersName);
	ServerNetName = MakeNetName2(ServerName);

	/***************  Verbindungsaufbau zum Server  ********************/
	/* Die Verbindung zum Server muß einen anderen "Quell"-Namen haben, als
	 * die zu Bob. Daher hängen wir einfach ein _S an! */
	if (!(con = ConnectTo(concatstrings(OurNetName, "_S", NULL), ServerNetName))) {
		fprintf(stderr,
				"ALICE: Kann keine Verbindung zum Server aufbauen: %s\n",
				NET_ErrorText());
		exit(20);
	}

	/******  Paket mit den beiden Namen erzeugen und Abschicken  *******/
	msg1.typ = Alice_Server;
	strcpy(msg1.body.Alice_Server.A, OurName);
	strcpy(msg1.body.Alice_Server.B, OthersName);
	PutMessage("Server", con, &msg1);

	/***********  Antwort des Servers lesen  ***********/
	GetMessage("Server", con, &msg1, Server_Alice);

	/****************  Verbindung zum Server abbauen  *************/
	DisConnect(con);

	/*>>>>                                         <<<<*
	 *>>>> AUFGABE: - Entschlüsseln der Nachricht  <<<<*
	 *>>>>          - Nachrichtenaustauch mit Bob  <<<<*
	 *>>>>          - Überprüfen der Bob-Nachricht <<<<*
	 *>>>>          - Schlüssel für Telefonieren   <<<<*
	 *>>>>                                         <<<<*/

	// Entschlüsseln der Nachricht
	DES_ikey ikey_sa;
	DES_GenKeys(Key_AS, 0, ikey_sa);
	DES_data iv;
	memset(&iv, 0, sizeof(DES_data));

	ServerData toDecServerData;
	memcpy(&toDecServerData, &msg1.body.Server_Alice.Serv_A1,
			sizeof(ServerData));
	DES_OFB(ikey_sa, iv, &toDecServerData, sizeof(ServerData),
			&msg1.body.Server_Alice.Serv_A1);

	// Analysierung der Nachricht
	DES_GenKeys(msg1.body.Server_Alice.Serv_A1.Key_AB, 0, iKey_AB);
	int TimeStamp = msg1.body.Server_Alice.Serv_A1.TimeStamp;
	int cur_time = GetCurrentTime();
	printf("%d\n",cur_time-TimeStamp);
	if (cur_time - TimeStamp < 0 || cur_time - TimeStamp > 30000) {		//set Time-out 30s
		fprintf(stderr, "TimeStamp check Error!\n");
		exit(20);
	}

	// Generierung neuer Nachricht zu Bob mit ServerData_B und AuthData_A
	msg2.typ = Alice_Bob;
	memcpy(&msg2.body.Alice_Bob.Serv_B2, &msg1.body.Server_Alice.Serv_B1,
			sizeof(ServerData));

	strcpy(&msg2.body.Alice_Bob.Auth_A2.Name,
			&msg1.body.Server_Alice.Serv_A1.Receiver);
	msg2.body.Alice_Bob.Auth_A2.Rand = RandomNumber();
	AuthData toEncAuthData;
	memset(&iv, 0, sizeof(DES_data));
	memcpy(&toEncAuthData, &msg2.body.Alice_Bob.Auth_A2, sizeof(AuthData));
	DES_OFB(iKey_AB, iv, &toEncAuthData, sizeof(AuthData),
			&msg2.body.Alice_Bob.Auth_A2);

	// Schick Bob die Nachricht
	if (!(con = ConnectTo(OurNetName, OthersNetName))) {
		fprintf(stderr, "ALICE: Kann keine Verbindung zum %s aufbauen: %s\n",
				OthersNetName, NET_ErrorText());
		exit(20);
	}
	PutMessage(OthersName, con, &msg2);

	// bekommen der Nachricht von Bob, enschlüsseln und überprüfen
	GetMessage(OthersName, con, &msg3, Bob_Alice);
	AuthData toDecAuthData;
	memset(&iv, 0, sizeof(DES_data));
	memcpy(&toDecAuthData, &msg3.body.Bob_Alice.Auth_B3, sizeof(AuthData));
	DES_OFB(iKey_AB, iv, &toDecAuthData, sizeof(AuthData),
			&msg3.body.Bob_Alice.Auth_B3);

	if (strcmp(msg3.body.Bob_Alice.Auth_B3.Name, OthersName) != 0) {
		fprintf(stderr, "Sender check Error!\n");
		exit(20);
	}

	if (msg3.body.Bob_Alice.Auth_B3.Rand != SwitchRandNum(toEncAuthData.Rand)) {
		fprintf(stderr, "Rand check Error!\n");
		exit(20);
	}

	printf("Keberos-Handshake successful!\n");

	/***********************  Phone starten  *****************************/
	Phone(con, OurName, OthersName, EnCrypt, DeCrypt);
	DisConnect(con);
	return 0;
}
