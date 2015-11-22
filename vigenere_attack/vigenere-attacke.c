/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 1: Klassische Chiffrierverfahren                  *
 **                                                           *
 **************************************************************
 **
 ** vigenere_attacke.c: Brechen der Vigenere-Chiffre
 **/

#include <stdio.h>
#include <stdlib.h>
#define errno 1
#include <praktikum.h>

#define NUMCHARS    26       /* Anzahl der Zeichenm, die betrachtet werden ('A' .. 'Z') */
#define MaxFileLen  32768    /* Maximale Größe des zu entschlüsselnden Textes */

const char *StatisticFileName = "statistik.data"; /* Filename der Wahrscheinlichkeitstabelle */
const char *WorkFile = "testtext.ciph"; /* Filename des verschlüsselten Textes */
const char *OutputFile = "klartext.txt";

double PropTable[NUMCHARS]; /* Tabellke mit den Zeichenwahrscheinlichkeiten.
 * ProbTable[0] == 'A', PropTable[1] == 'B' usw. */
char TextArray[MaxFileLen]; /* die eingelesene Datei */
int TextLength; /* Anzahl der gültigen Zeichen in TextArray */

/*--------------------------------------------------------------------------*/

/*
 * GetStatisticTable(): Liest die Statistik-Tabelle aus dem File
 * STATISTICFILENAME in das globale Array PROPTABLE ein.
 */

static void GetStatisticTable(void) {
	FILE *inp;
	int i;
	char line[64];

	if (!(inp = fopen(StatisticFileName, "r"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				StatisticFileName, strerror(errno));
		exit(20);
	}

	for (i = 0; i < TABSIZE(PropTable); i++) {
		fgets(line, sizeof(line), inp);
		if (feof(inp)) {
			fprintf(stderr,
					"FEHLER: Unerwartetes Dateieine in %s nach %d Einträgen.\n",
					StatisticFileName, i);
			exit(20);
		}
		PropTable[i] = atof(line);
	}
	fclose(inp);
}

/*-------------------------------------------------------------------------*/

/* GetFile(void) : Ließt den verschlüsselten Text aus dem File
 *   WORKFILE zeichenweise in das globale Array TEXTARRAY ein und zählt
 *   TEXTLENGTH für jedes Zeichen um 1 hoch.
 *   Eingelesen werden nur Buchstaben. Satz- und Sonderzeichen werden weggeworfen,
 *   Kleinbuchstaben werden beim Einlesen in Großbuchstaben gewandelt.
 */

static void GetFile(void) {
	FILE *inp;
	char c;

	if (!(inp = fopen(WorkFile, "r"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				WorkFile, strerror(errno));
		exit(20);
	}

	TextLength = 0;
	while (!feof(inp)) {
		c = fgetc(inp);
		if (feof(inp))
			break;
		if (c >= 'a' && c <= 'z')
			c -= 32;
		if (c >= 'A' && c <= 'Z') {
			if (TextLength >= sizeof(TextArray)) {
				fprintf(stderr,
						"FEHLER: Eingabepuffer nach %d Zeichen übergelaufen!\n",
						TextLength);
				exit(20);
			}
			TextArray[TextLength++] = c;
		}
	}
	fclose(inp);
}

/*--------------------------------------------------------------------------*/

/*
 * CountChars( int start, int offset, int h[] )
 *
 * CountChars zählt die Zeichen (nur Buchstaben!) im globalen Feld
 * TEXTARRAY. START gibt an, bei welchen Zeichen (Offset vom Begin der
 * Tabelle) die Zählung beginnen soll und OFFSET ist die Anzahl der
 * Zeichen, die nach dem 'Zählen' eines Zeichens weitergeschaltet
 * werden soll. 'A' wird in h[0], 'B' in h[1] usw. gezählt.
 *  
 *  Beispiel:  OFFSET==3, START==1 --> 1,  4,  7,  10, ....
 *             OFFSET==5, START==3 --> 3,  8, 13,  18, ....
 *
 * Man beachte, daß das erste Zeichen eines C-Strings den Offset 0 besitzt!
 */

static void CountChars(int start, int offset, int h[NUMCHARS]) {
	int i;
	char c;

	for (i = 0; i < NUMCHARS; i++)
		h[i] = 0;

	/*****************  Aufgabe  *****************/

	for (i = start; i < TextLength; i += offset) {
		c = TextArray[i];
		h[c - 65]++;
	}

}

static void output(char klartexts[]) {
	FILE *inp1, *inp2;
	char c;
	int i = 0;

	if (!(inp1 = fopen(WorkFile, "r"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				WorkFile, strerror(errno));
		exit(20);
	}

	if (!(inp2 = fopen(OutputFile, "w"))) {
		fprintf(stderr, "FEHLER: File %s kann nicht geöffnet werden: %s\n",
				OutputFile, strerror(errno));
		exit(20);
	}

	TextLength = 0;
	while (!feof(inp1)) {
		c = fgetc(inp1);
		if (c < 'A' || c > 'Z' && c < 'a' || c > 'z')
			fputc(c, inp2);
		else
			fputc(klartexts[i++], inp2);
	}
	fclose(inp1);
	fclose(inp2);
}

/*------------------------------------------------------------------------------*/

int main(int argc, char **argv) {

	GetStatisticTable(); /* Wahrscheinlichkeiten einlesen */
	GetFile(); /* zu bearbeitendes File einlesen */

	/*****************  Aufgabe  *****************/

	int periode = 1, r, i, j, sumCounts, flag = 0, offset = 0;
	int h[NUMCHARS]; //h[0] ist die Zahl 'A',h[1] ist die Zahl 'B' usw.
	char schluessel[MaxFileLen], klartexts[MaxFileLen]; //Schlüssel
	double curPro, nxt5Pro, nxt6Pro, max;
	double indexC = 0, tempIndexC = 0;

//zuerst berechnen indexC=sum(PropTable[i]²)
	for (i = 0; i < NUMCHARS; ++i)
		indexC += PropTable[i] * PropTable[i];

// anhand der verschiedenen Schlüsselsleange wird indexC jedesmal berechnet
// falls flag==1 bleibend, dann wir haben die richtige Laenge gefunden
	while (periode < TextLength && flag == 0) {
		flag = 1;
		for (i = 0; i < periode; i++) {
			sumCounts = 0;
			CountChars(i, periode, h);
			for (j = 0; j < NUMCHARS; j++)
				sumCounts += h[j]; //gesamte chars in Leange periode

			tempIndexC = 0;
			for (j = 0; j < NUMCHARS; j++) {
				curPro = h[j] / (double) sumCounts;
				tempIndexC += curPro * curPro;
			}

			if (tempIndexC - indexC > 0.01 || tempIndexC - indexC < -0.01) {
				// tempIndexC ist derzeit noch nicht gueltig
				flag = 0;
				break;
			}

		}
		periode++;
	}

// zur Festlegung des Offsets in jedem Caesar-Chiffrat
	periode--;
	if (flag == 1 && periode < TextLength) {
		fprintf(stdout, "Richtige Periode=%d\n", periode);
		for (i = 0; i < periode; i++) {
			CountChars(i, periode, h);
			sumCounts = 0;
			for (j = 0; j < NUMCHARS; j++)
				sumCounts += h[j];

			// Wir feststellen zuerst die Position der max Char-Counts, und naechstes fuenfte und sechste Char-Counts
			// Weil die Frequenz der fünfte und sechste Chars nach dem hauefigste Char sehr niedrig sind.
			max = 0;
			for (j = 0; j < NUMCHARS; j++) {
				flag = 1;
				curPro = h[j] / (double) sumCounts;
				nxt5Pro = h[(j + 5) % NUMCHARS] / (double) sumCounts;
				nxt6Pro = h[(j + 6) % NUMCHARS] / (double) sumCounts;
				if (max < curPro && (nxt5Pro) < 0.02 && (nxt6Pro) < 0.02) {
					max = curPro;
					offset = j;
				}
			}
			if (flag == 1) {
				schluessel[i] = 'A' + (offset + NUMCHARS - 4) % NUMCHARS;
			}
		}

		printf("Richtiger Schlüssel: %s\n", schluessel);
		r = 0;
		for (i = 0; i < TextLength; i++) {
			klartexts[i] = (NUMCHARS + TextArray[i] - schluessel[r]) % NUMCHARS
					+ 'A';
			r = (r + 1) % periode;
		}

	} else
		printf("kein Schlüssel gesucht!\n");

// klartexts output
	output(klartexts);

	return 0;
}
