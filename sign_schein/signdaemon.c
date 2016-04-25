/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Proktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 7: El-gamal-Signatur                              *
 **                                                           *
 **************************************************************
 **
 ** daemon.c: Signatur-Daemon
 **/

#include <unistd.h>
#include <time.h>
#include "sign.h"

static longnum p, w;
static int Debug = 0;

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
	/* Der Rumpf dieser Prozedur wird absichtlich nicht gezeigt! */
}

/*
 * Generate_Sign(m,r,s,x) : Erzeugt zu der MDC M eine El-Gamal-Signatur 
 *    in R und S. X ist der private Schlüssel
 */

static void Generate_Sign(const_longnum_ptr m, longnum_ptr r, longnum_ptr s,
		const_longnum_ptr x) {
	/* Der Rumpf dieser Prozedur wird absichtlich nicht gezeigt! */
}

/* ----------------------------------------------------------------------------------- */

int main(int argc, char **argv) {
	char c;
	const char *datafile, *name, *other, *now, *root;
	Connection con;
	PortConnection port;
	Message msg, reply;
	longnum Daemon_x, Daemon_y, y, mdc;
	int i, DestroySign;

	if (!(root = getenv("PRAKTROOT")))
		root = "";
	datafile = concatstrings(root, "/loesungen/sign_schein/Sign_Daemon.data",
			NULL);

	name = DAEMON_NAME;
	Debug = 0;
	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	while ((c = getopt(argc, argv, "df:n:")) != -1) {
		switch (c) {
		case 'd':
			Debug = 1;
			break;
		case 'f':
			datafile = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		default:
			fprintf(stderr, "USAGE: signdaemon [-d] [-f datafile]\n");
			exit(5);
			break;
		}
	}

	if (!Get_Privat_Key(datafile, &p, &w, &Daemon_x)) {
		fprintf(stderr, "Kann die geheimen Dämon-Daten aus %s nicht lesen.\n",
				datafile);
		exit(20);
	}
	if (!Get_Public_Key(DAEMON_NAME, &Daemon_y)) {
		fprintf(stderr, "Kann die öffentlichen Dämon-Daten nicht lesen.\n");
		exit(20);
	}

	RESTART:

	/***************  Globales Port eröffnen  ***************/
	if (!(port = OpenPort(name))) {
		fprintf(stderr,
				"SIGN_DAEMON: Kann das Dämon-Port \"%s\" nicht erzeugen: %s\n",
				name, NET_ErrorText());
		exit(20);
	}

	LSeed(i = time(NULL));

	/******************* Hauptschleife **********************/
	DestroySign = 1;
	while (1) {

		/**************  Auf Verbindung auf dem Port warten  ****************/
		if (!(con = WaitAtPort(port))) {
			fprintf(stderr, "SIGN_DAEMON: WaitAtPort ging schief: %s\n",
					NET_ErrorText());
			exit(20);
		}
		other = PeerName(port);
		now = Now();

		/***************  Nachricht entgegennehmen  *****************/
		if ((i = Receive(con, &msg, sizeof(msg))) != sizeof(msg)) {
			DisConnect(con);
			ClosePort(port);
			if (i)
				printf("%s <%s>: Short message received: %s\n", now, other,
						NET_ErrorText());
			else
				printf("%s <%s>: Got EOF, connection shut down\n", now, other);
			goto RESTART;
		}
		if (msg.typ == ReportRequest) {
			reply.typ = ReportResponse;
			Generate_MDC(&msg, &p, &mdc);
			if (!Get_Public_Key(msg.body.ReportRequest.Name, &y)) {
				printf("%s <%s>: Unbekannter Benutzer \"%s\"\n", now, other,
						msg.body.ReportRequest.Name);
				sprintf(reply.body.ReportResponse.Report[0],
						"Benutzer %s ist unbekannt",
						msg.body.ReportRequest.Name);
				reply.body.ReportResponse.NumLines = 1;
			} else if (NBITS(&msg.sign_r) != NBITS(&y)
					|| NBITS(&msg.sign_s) != NBITS(&y)) {
				printf("%s <%s>: R oder S keine gültige Langzahl\n", now,
						other);
				strcpy(reply.body.ReportResponse.Report[0],
						"R oder S ist keine gültige Langzahl!");
				reply.body.ReportResponse.NumLines = 1;
			} else if (!Verify_Sign(&mdc, &msg.sign_r, &msg.sign_s, &y)) {
				printf("%s <%s>: Ungültige Signatur über %s\n", now, other,
						msg.body.ReportRequest.Name);
				printf("\tR = %s\n", LLong2Hex(&msg.sign_r, NULL, 0, 0));
				printf("\tS = %s\n", LLong2Hex(&msg.sign_s, NULL, 0, 0));
				strcpy(reply.body.ReportResponse.Report[0],
						"Signatur ist nicht gültig!");
				reply.body.ReportResponse.NumLines = 1;
			} else {
				DestroySign = !DestroySign;
				printf(
						"%s <%s>: Signatur OK, Reply mit %sgültiger Signatur wird erzeugt\n",
						now, other, DestroySign ? "un" : "");
				strcpy(reply.body.ReportResponse.Report[0],
						"  **********************************************");
				strcpy(reply.body.ReportResponse.Report[1],
						"  * Auskunft über den Punktestand im Praktikum *");
				strcpy(reply.body.ReportResponse.Report[2],
						"  *  Kryptographie und Datensicherheitstechnik *");
				strcpy(reply.body.ReportResponse.Report[3],
						"  **********************************************");
				strcpy(reply.body.ReportResponse.Report[4], " ");
				sprintf(reply.body.ReportResponse.Report[5], " Stand: %s", now);
				sprintf(reply.body.ReportResponse.Report[6],
						"Der Teilnehmer %s hat in den Versuchen",
						msg.body.ReportRequest.Name);
				strcpy(reply.body.ReportResponse.Report[7],
						"1 bis 7 noch NICHT die erforderliche Punkte-");
				strcpy(reply.body.ReportResponse.Report[8],
						"zahl erreich. Ein Schein kann daher nicht");
				strcpy(reply.body.ReportResponse.Report[9], "gewährt werden.");
				reply.body.ReportResponse.NumLines = 10;

				if (!DestroySign) {
					strcpy(reply.body.ReportResponse.Report[10], " ");
					strcpy(reply.body.ReportResponse.Report[11],
							"Diese Auskunft ist elektronisch unterschrieben und");
					strcpy(reply.body.ReportResponse.Report[12],
							"daher gültig --- gez. Sign_Daemon");
					reply.body.ReportResponse.NumLines = 13;
				}
			}
		} /* of 'if (msg.typ == ReportRequest)' */
		else if (msg.typ == VerifyRequest) {
			reply.typ = VerifyResponse;
			Generate_MDC(&msg, &p, &mdc);

			if (NBITS(&msg.sign_r) == NBITS(&Daemon_y)
					&& NBITS(&msg.sign_s) == NBITS(&Daemon_y)
					&& Verify_Sign(&mdc, &msg.sign_r, &msg.sign_s, &Daemon_y)) {
				strcpy(reply.body.VerifyResponse.Res,
						"Reply:  Die Daemon-Signatur ist gültig.");
				printf("%s <%s>: Verify-Request mit gültiger Dämon-Signatur:\n",
						now, other);
				if (msg.body.VerifyRequest.NumLines == 0)
					printf("aber die Nachricht hat die Laenge 0\n");
				for (i = 0; i < msg.body.VerifyRequest.NumLines; i++)
					printf("\t\"%s\"\n", msg.body.VerifyRequest.Report[i]);
			} else {
				strcpy(reply.body.VerifyResponse.Res,
						"Reply:  Die Daemon-Signatur ist UNGÜLTIG!");
				printf(
						"%s <%s>: Verify-Request mit UNGÜLTIGER Dämon-Signatur:\n",
						now, other);
			}
		} /* of 'else if (msg.typ == VerifyRequest)' */
		else {
			reply.typ = ReportResponse;
			sprintf(reply.body.ReportResponse.Report[0],
					"Unbekannter Pakettyp von Benutzer %s",
					msg.body.ReportRequest.Name);
			reply.body.ReportResponse.NumLines = 1;
		}

		/*****************  Reply unterschreiben und zurückschicken  ******************/
		Generate_MDC(&reply, &p, &mdc);
		Generate_Sign(&mdc, &reply.sign_r, &reply.sign_s, &Daemon_x);
		if (DestroySign)
			reply.sign_s.data.l[0] ^= 0xffffffff;

		if (Transmit(con, &reply, sizeof(reply)) != sizeof(reply)) {
			printf("%s <%s>: Error transmitting the reply: %s\n", now, other,
					NET_ErrorText());
			ClosePort(port);
			DisConnect(con);
			goto RESTART;
		}
		DisConnect(con);
	}

	return 0;
}
