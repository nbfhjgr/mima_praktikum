/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** getreport.c: Rahmenprogramm für den Signatur-Versuch
 **/

/* 
 * OverrideNetName: Hier den Gruppennamen einsetzen, falls der nicht 
 *                  mit dem Accountnamen uebereinstimmt
 *                  Andernfalls leerer String
 */

static const char *OverrideNetName = "";

#include "sign.h"

static longnum p, w;

/*
 * Verify_Sign(mdc,r,s,y) :
 *
 *  überprüft die El-Gamal-Signatur R/S zur MDC. Y ist der öffentliche
 *  Schlüssel des Absenders der Nachricht
 *
 * RETURN-Code: 1, wenn Signatur OK, 0 sonst.
 */

static int Verify_Sign(const_longnum_ptr mdc, const_longnum_ptr r,
		const_longnum_ptr s, const_longnum_ptr y) {
	/*>>>>                                               <<<<*
	 *>>>> AUFGABE: Verifizieren einer El-Gamal-Signatur <<<<*
	 *>>>>                                               <<<<*/

	longnum gleich_links, gleich_rechts;

	LInitNumber(&gleich_links, NBITS(&p), 0);
	LInitNumber(&gleich_rechts, NBITS(&p), 0);

	LModMultExp(y, r, r, s, &gleich_links, &p);
	LModExp(&w, mdc, &gleich_rechts, &p);

	if (!LCompare(&gleich_links, &gleich_rechts))
		return 1;
	else
		return 0;
}

/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(const_longnum_ptr m, longnum_ptr r, longnum_ptr s,
		const_longnum_ptr x) {
	/*>>>>                                           <<<<*
	 *>>>> AUFGABE: Erzeugen einer El-Gamal-Signatur <<<<*
	 *>>>>                                           <<<<*/
	longnum k, pMinusEins, kInvert, gtt, us, vs;
	int sign = 0;

	LInitNumber(&k, NBITS(&p), 0);
	LInitNumber(&pMinusEins, NBITS(&p), 0);
	LInitNumber(&kInvert, NBITS(&p), 0);
	LInitNumber(&gtt, NBITS(&p), 0);
	LInitNumber(&us, NBITS(&p), 0);
	LInitNumber(&vs, NBITS(&p), 0);

	LCpy(&pMinusEins, &p);
	LAddq(-1, &pMinusEins);

	//Generate zufalls zahl k
	while (1) {
		LRand(&pMinusEins, &k);
		LggT(&k, &pMinusEins, &gtt, &us, &vs, &sign);
		if (!LIntCmp(1, &gtt))
			break;
	}
	LModExp(&w, &k, r, &p);

	LModMult(r, x, s, &pMinusEins);
	LNegMod(s, &pMinusEins);
	LAddMod(m, s, &pMinusEins);
	LCpy(&kInvert, &k);
	LInvert(&kInvert, &pMinusEins);
	LModMult(s, &kInvert, s, &pMinusEins);

}

void generateMsg(Message *msg) {
	printf("Beginnen die Message zu erzeugen.\n");

	strcpy(msg->body.ReportResponse.Report[0],
			"  **********************************************");
	strcpy(msg->body.ReportResponse.Report[1],
			"  * Auskunft über den Punktestand im Praktikum *");
	strcpy(msg->body.ReportResponse.Report[2],
			"  *  Kryptographie und Datensicherheitstechnik *");
	strcpy(msg->body.ReportResponse.Report[3],
			"  **********************************************");
	strcpy(msg->body.ReportResponse.Report[4], " ");
	sprintf(msg->body.ReportResponse.Report[5], " Stand: %s", "10.Feb");
	sprintf(msg->body.ReportResponse.Report[6],
			"Der Teilnehmer %s hat in den Versuchen",
			msg->body.ReportRequest.Name);
	strcpy(msg->body.ReportResponse.Report[7], "1 bis 7 bestanden!");
	strcpy(msg->body.ReportResponse.Report[8], "Gratulation!");
	strcpy(msg->body.ReportResponse.Report[9], " ");
	strcpy(msg->body.ReportResponse.Report[10],
			"Diese Auskunft ist elektronisch unterschrieben und");
	strcpy(msg->body.ReportResponse.Report[11],
			"daher gültig --- gez. Sign_Daemon");
	msg->body.ReportResponse.NumLines = 12;
}

void getRegOfMDC(const Message *msg, DES_data reg, int is_new) {
	static const DES_key key =
			{ 0x7f, 0x81, 0x5f, 0x92, 0x1a, 0x97, 0xaf, 0x18 };
	DES_ikey ikey;
	DES_data desout;

	int i, j, len;
	const UBYTE *ptr;

	DES_GenKeys(key, 0, ikey);
	switch (msg->typ) {

	case ReportResponse:
		ptr = (const UBYTE *) &msg->body.ReportResponse.Report;
		len = sizeof(String) * msg->body.ReportResponse.NumLines;
		break;
	case VerifyRequest:
		ptr = (const UBYTE *) &msg->body.VerifyRequest.Report;
		len = sizeof(String) * msg->body.VerifyRequest.NumLines;
		break;
	default:
		fprintf(stderr, "GENERATE_MDC: Illegaler Typ von Nachricht!\n");
		exit(20);
		break;
	}
	for (i = 0; i < DES_DATA_WIDTH; i++)
		reg[i] = 0;

	/***************   MDC berechnen   ***************/
	while (len >= DES_DATA_WIDTH) {
		DES_Cipher(ikey, reg, desout);
		for (j = 0; j < DES_DATA_WIDTH; j++)
			reg[j] = desout[j] ^ *ptr++;
		len -= DES_DATA_WIDTH;
		if (len == DES_DATA_WIDTH && is_new) {
			return;
		}
	}

}

void toFitMDC(Message *msg, Message *old_msg) {
	static const DES_key key =
			{ 0x7f, 0x81, 0x5f, 0x92, 0x1a, 0x97, 0xaf, 0x18 };
	DES_ikey ikey;
	DES_data msg_mdc_reg, old_msg_mdc_reg, desout, last8Bytes;
	int i;

	printf("Beginnen den bestimmten MDC zu erzeugen.\n");

	getRegOfMDC(msg, msg_mdc_reg, 1);
	getRegOfMDC(old_msg, old_msg_mdc_reg, 0);

	DES_GenKeys(key, 0, ikey);
	DES_Cipher(ikey, msg_mdc_reg, desout);
	for (i = 0; i < DES_DATA_WIDTH; i++) {
		last8Bytes[i] = old_msg_mdc_reg[i] ^ desout[i];
	}

	int len = msg->body.VerifyRequest.NumLines;
	memcpy((UBYTE*) &(msg->body.VerifyRequest.Report[len]) - DES_DATA_WIDTH,
			last8Bytes, DES_DATA_WIDTH);

}

int main(int argc, char **argv) {
	Connection con;
	int cnt, ok;
	Message msg, new_msg;
	longnum x, Daemon_y, mdc, new_mdc;
	const char *OurName = "mima";

	/**************  Laden der öffentlichen und privaten Daten  ***************/
	if (!Get_Privat_Key(NULL, &p, &w, &x)
			|| !Get_Public_Key(DAEMON_NAME, &Daemon_y))
		exit(0);
	LSeed(GetCurrentTime());

	/********************  Verbindung zum Dämon aufbauen  *********************/
	//OurName = MakeNetName(NULL); /* gibt in Wirklichkeit Unix-Gruppenname zurück! */
	if (strlen(OverrideNetName) > 0) {
		OurName = OverrideNetName;
	}
	if (!(con = ConnectTo(OurName, DAEMON_NAME))) {
		fprintf(stderr, "Kann keine Verbindung zum Daemon aufbauen: %s\n",
				NET_ErrorText());
		exit(20);
	}

	/***********  Message vom Typ ReportRequest initialisieren  ***************/
	msg.typ = ReportRequest; /* Typ setzten */
	strcpy(msg.body.ReportRequest.Name, OurName); /* Gruppennamen eintragen */
	Generate_MDC(&msg, &p, &mdc); /* MDC generieren ... */
	Generate_Sign(&mdc, &msg.sign_r, &msg.sign_s, &x); /* ... und Nachricht unterschreiben */

	/*************  Nachricht abschicken, Antwort einlesen  *******************/
	if (Transmit(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Fehler beim Senden des 'ReportRequest': %s\n",
				NET_ErrorText());
		exit(20);
	}

	if (Receive(con, &msg, sizeof(msg)) != sizeof(msg)) {
		fprintf(stderr, "Fehler beim Empfang des 'ReportResponse': %s\n",
				NET_ErrorText());
		exit(20);
	}

	/******************  Überprüfen der Dämon-Signatur  ***********************/
	printf("Nachricht vom Dämon:\n");
	for (cnt = 0; cnt < msg.body.ReportResponse.NumLines; cnt++) {
		printf("\t%s\n", msg.body.ReportResponse.Report[cnt]);
	}

	Generate_MDC(&msg, &p, &mdc);
	ok = Verify_Sign(&mdc, &msg.sign_r, &msg.sign_s, &Daemon_y);
	if (ok)
		printf("Dämon-Signatur ist ok!\n");
	else {
		printf("Dämon-Signatur ist FEHLERHAFT!\n");
		return 0;
	}

	/*>>>>                                      <<<<*
	 *>>>> AUFGABE: Fälschen der Dämon-Signatur <<<<*
	 *>>>>                                      <<<<*/

	printf("Begin zu fälshen:\n");
	memset(&new_msg, 0, sizeof(Message));
	new_msg.typ = VerifyRequest;


	generateMsg(&new_msg);
	toFitMDC(&new_msg, &msg);

	Generate_MDC(&new_msg, &p, &new_mdc);

	if (!LCompare(&mdc, &new_mdc)) {
		printf("Fälschung fertig!\n");

		LCpy(&new_msg.sign_r, &msg.sign_r);
		LCpy(&new_msg.sign_s, &msg.sign_s);
		if (!(con = ConnectTo(OurName, DAEMON_NAME))) {
			fprintf(stderr, "Kann keine Verbindung zum Daemon aufbauen: %s\n",
					NET_ErrorText());
			exit(20);
		}

		if (Transmit(con, &new_msg, sizeof(new_msg)) != sizeof(new_msg)) {
			fprintf(stderr, "Fehler beim Senden des 'VerifyRequest': %s\n",
					NET_ErrorText());
			exit(20);
		}

		if (Receive(con, &msg, sizeof(msg)) != sizeof(msg)) {
			fprintf(stderr, "Fehler beim Empfang des 'VerifyResponse': %s\n",
					NET_ErrorText());
			exit(20);
		}
		printf("Nachricht vom Dämon:\n");
		printf("\t%s\n", msg.body.VerifyResponse.Res);

	} else
		printf("Fälschung gescheitert\n");

	return 0;
}

