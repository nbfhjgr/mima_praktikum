/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 4: Brechen der Blockchiffre FEAL                  *
 **                                                           *
 **************************************************************
 **
 ** feal.h Headerfile für den Feal-Versuch
 **/

#include <stdio.h>
#include <stdlib.h>

#include "feal.h"

ubyte s1 = 0x01, s2 = 0xfe;

static ubyte rotr(ubyte a) {
	return ((a >> 2) | (a << 6)) & 0xff;
}

static ubyte rot2(ubyte a) {
	return ((a << 2) | (a >> 6)) & 0xff;
}

static ubyte calc_f(ubyte u, ubyte v) {
	int overflow;
	ubyte r;

	r = Feal_GS(u, v, &overflow);
	if (overflow) {
		fprintf(stderr, "FEHLER: Schlüssel-Überlauf, u=%02x, v=%02x\n", u, v);
		exit(20);
	}

	return r;
}

/* --------------------------------------------------------------------------- */

ubyte bitsCheck(ubyte u, ubyte v) {
	return (s1 << 1) & rotr(calc_f(u, v));
}

void bCheck(ubyte *u, ubyte *v) {
	int flag = 0;
	ubyte t1, t;
	*u &= s2;
	*v &= s2;
	t1 = bitsCheck(*u, *v);

	*u &= s2;
	*v |= s1;
	t = bitsCheck(*u, *v);
	if (t != t1) {
		flag = 1;
	}

	*u |= s1;
	*v &= s2;
	t = bitsCheck(*u, *v);

	if (t == t1 && flag == 0) {
		*u |= s1;
		*v |= s1;
		return;
	} else if (t == t1 && flag == 1) {
		*u &= s2;
		*v |= s1;
		return;
	} else if (flag == 0) {
		*u |= s1;
		*v &= s2;
		return;
	} else {
		*u &= s2;
		*v &= s2;
	}
	return;
}

int main(int argc, char **argv) {
	ubyte k1 = 0, k2 = 0, k3 = 0;
	Feal_NewKey();
	/*>>>>                                                      <<<<*/
	/*>>>>  Aufgabe: Bestimmen der geheimen Schlüssel k1,k2,k3  <<<<*/
	/*>>>>                                                      <<<<*/

	ubyte u = 0, v = 0, w = 0;

	int i;
	for (i = 1; i <= 7; i++) {
		bCheck(&u, &v);
		if (i % 2 == 0) {
			k1 += (s1 & (~u));
			k2 += (s1 & (~v));
		} else {
			k1 += (s1 & u);
			k2 += (s1 & v);
		}
		s1 <<= 1;
		s2 = (s2 << 1) | 1;
	}

	//if (bitsCheck(u, v) >> 7 == 1)
	//	v = 0x80 | v;

	//printf("%0x,%0x\n", u, v);
	w = calc_f(u, v);
	k3 = w ^ rot2(((u ^ k1) + (v ^ k2) + 1) % 256);

	//printf("%x,",w);
	//printf("%x\n",Feal_G(k1,k2,k3,u,v));

	printf("Lösung: $%02x $%02x $%02x: %s", k1, k2, k3,
			Feal_CheckKey(k1, k2, k3) ? "OK!" : "falsch");
	return 0;
}

