/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 5: Keymanagement mit dem Kerberos-Protokoll       *
 **                                                           *
 **************************************************************
 **
 ** bob.c: Hauptprogram für den Kommunikationspartner BOB
 **/

#include "kerberos.h"

/* Unser 'Netzwerk'-Name und die unserer Kommunikationspartner */
const char *OurName = "Bob";
const char *OthersName = "Alice";

/* Der geheime, gemeinsame Schlüssel zwischen dem Server und Bob */
DES_key Key_BS = { 0x7f, 0xab, 0x12, 0xa0, 0x4d, 0xc6, 0x81, 0x02 };

/* Der vom Server generierte Schlüssel für die Kommunikation mit Alice
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
 * EnCrypt(c) : Verschlüsselt C
 */

static char EnCrypt(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char cipher;
	DES_OFB(iKey_AB, phone_iv2, &c, sizeof(char), &cipher);
	return cipher;
}

/*
 * DeCrypt(c) : Entschlüsselt C
 */

static char DeCrypt(char c) {
	/*>>>>         <<<<*
	 *>>>> AUFGABE <<<<*
	 *>>>>         <<<<*/
	char m;
	DES_OFB(iKey_AB, phone_iv1, &c, sizeof(char), &m);
	return m;
}

/* -------------------------------------------------------------------------------- */

int main(int argc, char **argv) {
	Connection con;
	Message msg1, msg2;
	char *OurNetName, *OthersNetName;

	/* Konstruktion eindeutiger Namen für das Netzwerksystem:
	 * OurName, OthersName und ServerName wird der Gruppenname vorangestellt.
	 * So gibt es KEINE Kollisionen zwischen den einzelnen Gruppen!
	 * Dieser Netzname wird nur für den Verbindungsaufbau über das
	 * E.I.S.S.-Network-Playfield benutzt. Die im Rahmen des Protokolls
	 * ausgetauschten Namen sind OutName, OthersName und ServerName!
	 */

	OurNetName = MakeNetName2(OurName);
	OthersNetName = MakeNetName2(OthersName);

	/***************  Verbindungsaufbau zu Alice  ********************/

	if (!(con = ConnectTo(OurNetName, OthersNetName))) {
		fprintf(stderr, "Kann keine Verbindung zu %s aufbauen: %s\n",
				OthersNetName, NET_ErrorText());
		exit(20);
	}

	/***********  Paket von Alice mit Server- und Auth-Daten lesen **********/
	GetMessage(OthersName, con, &msg1, Alice_Bob);

	/*>>>>                                       <<<<*
	 *>>>> AUFGABE: - Paket von Alice auspaken   <<<<*
	 *>>>>          - Antwort erzeugen           <<<<*
	 *>>>>          - Schlüssel für telefonieren <<<<*
	 *>>>>                                       <<<<*/

	// Entschlüsseln die Nachricht von Alice mit Key_SB
	DES_ikey ikey_sb;
	DES_GenKeys(Key_BS, 0, ikey_sb);
	DES_data iv;
	memset(&iv, 0, sizeof(DES_data));

	ServerData toDecServerData;
	memcpy(&toDecServerData, &msg1.body.Alice_Bob.Serv_B2, sizeof(ServerData));
	DES_OFB(ikey_sb, iv, &toDecServerData, sizeof(ServerData),
			&msg1.body.Alice_Bob.Serv_B2);

	// Überprüfen den Inhalt
	if (strcmp(msg1.body.Alice_Bob.Serv_B2.Receiver, OurName) != 0) {
		fprintf(stderr, "Receiver check Error!\n");
		exit(20);
	}
	int TimeStamp = msg1.body.Alice_Bob.Serv_B2.TimeStamp;
	int cur_time = GetCurrentTime();
	if (cur_time - TimeStamp < 0 || cur_time - TimeStamp > 30000) {		//set Time-out 30s
		fprintf(stderr, "TimeStamp check Error!\n");
		exit(20);
	}
	DES_GenKeys(msg1.body.Alice_Bob.Serv_B2.Key_AB, 0, iKey_AB);

	// Entschlüsslen den Auth-Inhalt mit iKey_AB
	AuthData toDecAuthData;
	memset(&iv, 0, sizeof(DES_data));
	memcpy(&toDecAuthData, &msg1.body.Alice_Bob.Auth_A2, sizeof(AuthData));
	DES_OFB(iKey_AB, iv, &toDecAuthData, sizeof(AuthData),
			&msg1.body.Alice_Bob.Auth_A2);

	if (strcmp(msg1.body.Alice_Bob.Auth_A2.Name, OthersName) != 0) {
		fprintf(stderr, "Sender check Error!\n");
		exit(20);
	}

	// Generieren neue Nachricht für Überprüfung, versclüsselt mit iKey_AB
	AuthData toEncAuthData;
	msg2.typ = Bob_Alice;
	msg2.body.Bob_Alice.Auth_B3.Rand = SwitchRandNum(
			msg1.body.Alice_Bob.Auth_A2.Rand);
	strcpy(msg2.body.Bob_Alice.Auth_B3.Name, OurName);
	memset(&iv, 0, sizeof(DES_data));
	memcpy(&toEncAuthData, &msg2.body.Bob_Alice.Auth_B3, sizeof(AuthData));
	DES_OFB(iKey_AB, iv, &toEncAuthData, sizeof(AuthData),
			&msg2.body.Bob_Alice.Auth_B3);

	// Senden die Nachricht
	PutMessage(OthersName, con, &msg2);

	printf("Keberos-Handshake successful!\n");

	/***********************  Phone starten  *****************************/
	Phone(con, OurName, OthersName, EnCrypt, DeCrypt);
	DisConnect(con);
	return 0;
}

