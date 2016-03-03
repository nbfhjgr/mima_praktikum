/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 6: Langzahlarithmetik und Diffie-Hellmann         *
 **            Key Exchange                                   *
 **                                                           *
 **************************************************************
 **
 ** exp.c: Implementierung Modulo-Exponentation.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <praktikum.h>
#include <longint.h>

#include "versuch.h"

/*
 * doexp(x,y,z,p) : Berechnet z := x^y mod p
 *
 * Hinweise: LModSquare(a,z,p)    z := a^2 mod p
 *           LModMult(a,b,z,p)    z := a*b mod p
 *           LInt2Long(i,z)       z (longnum) := i (integer) (z muß zuvor mit  n
 *                                initialisiert werden!!)
 *           LGetBit(y,bitpos)    Gibt bit BITPOS der Lanzahl Y zurück.
 *                                Bit 0 ist das niederwertigste Bit.
 */

longnum table[512];

int exp2(int x) {
	int i = 0, y = 1;
	for (i = 0; i < x; i++) {
		y *= 2;
	}
	return y;
}

int calc(int n) {
	float s = 1.0;
	const float ln2 = 0.69314718056;
	s *= exp2(n - 1);
	s *= n * n * ln2;
	s += n * n / 2.0;
	return (int) s;
}

int intervalDetermine(int rest) {
	// N = ln2*2^(n-1)*n²+n²/2
	int i = 1;
	while (!(calc(i) < rest && calc(i + 1) > rest))
		i++;
	return i;
}

void initialTable(const_longnum_ptr x, const_longnum_ptr p, int bits) {
	int i;
	LInitNumber(&table[0], NBITS(p), 0);
	LInt2Long(1, &table[0]);
	for (i = 1; i < 512; i++) {
		LInitNumber(&table[i], NBITS(p), 0);
		LInt2Long(1, &table[i]);
	}

}

void createTable(int interval, const_longnum_ptr x, const_longnum_ptr p) {
	int i, max_index;

	initialTable(x, p, interval);

	max_index = exp2(interval - 1);

	for (i = 1; i <= max_index; i++) {
		LModMult(&table[i - 1], x, &table[i], p);
	}

	for (i = 0; i < max_index; i++) {
		LModMult(&table[i], &table[max_index], &table[i], p);
	}

}

const_longnum_ptr searchTable(int x, int interval) {
	x ^= exp2(interval - 1);
	return &table[x];
}

void cal_rest(int xx, longnum_ptr rst, const_longnum_ptr x, const_longnum_ptr p) {
	int i;
	LInitNumber(rst, NBITS(p), 0);
	LInt2Long(1, rst);

	for (i = 0; i < xx; i++)
		LModMult(rst, x, rst, p);
}

void doexp(const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z,
		const_longnum_ptr p) {
	/*>>>>                                                   <<<<*
	 *>>>> AUFGABE: Implementierung der Modulo-Exponentation <<<<*
	 *>>>>                                                   <<<<*/

	// Die Nullbits von links zu rechts prüfen
	//long y_test = 50000;
	//LInt2Long(y_test, y);
	int bits = NBITS(y);
	int nb = 0;

	while (!LGetBit(y, bits - nb - 1))
		nb++;

	int interval = intervalDetermine(bits - nb);

	createTable(interval, x, p);

	int cur_interval = 0;
	int rest_bits = bits - nb;

	int part_e = 0;
	int bit = 0;

	LInitNumber(z, NBITS(p), 0);
	LInt2Long(1, z);

	while (rest_bits > 0) {
		bit = LGetBit(y, rest_bits - 1);
		if (bit) {
			part_e = (part_e << 1) | 1;
			cur_interval++;
		} else if (cur_interval == 0) {
			LModSquare(z, z, p);
			rest_bits--;
			continue;
		} else {
			part_e = part_e << 1;
			cur_interval++;
		}
		LModSquare(z, z, p);
		if (cur_interval == interval) {

			LModMult(z, searchTable(part_e, interval), z, p);
			part_e = 0;
			cur_interval = 0;
		}
		rest_bits--;
	}

	if (cur_interval > 0) {
		longnum rst;
		cal_rest(part_e, &rst, x, p);
		LModMult(z, &rst, z, p);
	}
	//printf(" my answer = %s\n", LLong2Hex(z, NULL, 0, 0));
	//exit(0);
}
