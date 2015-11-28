/*************************************************************
 **         Europäisches Institut für Systemsicherheit        *
 **   Praktikum "Kryptographie und Datensicherheitstechnik"   *
 **                                                           *
 ** Versuch 3: Brechen von EC-Karten PINs                     *
 **                                                           *
 **************************************************************
 **
 ** pin.c Headerfile für den PIN-Versuch
 **/

#include <stdio.h>
#include <stdlib.h>

#include "pin.h"

int diff1, diff2;

int pin[9000], prob[9000], try[9000];

static int PIN_D1[10] = { 0, 4, 2, 2, 2, 2, 1, 1, 1, 1 };
static int PIN_OtherD[10] = { 2, 2, 2, 2, 2, 2, 1, 1, 1, 1 };

void adjust(int* max_prob, int *pins) {
	int i = 1, loc = 0, temp_pin;
	float temp;
	while (i <= 100 && i << 1 <= 100) {
		if (max_prob[i << 1] < max_prob[(i << 1) + 1])
			loc = i << 1;
		else
			loc = (i << 1) + 1;
		if ((i << 1) + 1 > 100)
			loc = i << 1;
		if (max_prob[i] > max_prob[loc]) {
			temp = max_prob[i];
			max_prob[i] = max_prob[loc];
			max_prob[loc] = temp;

			temp_pin = pins[i - 1];
			pins[i - 1] = pins[loc - 1];
			pins[loc - 1] = temp_pin;

			i = loc;
		} else
			return;
	}
}

void attack(void) {

	/*>>>>                                                      <<<<*/
	/*>>>>  Aufgabe: Bestimmen die PIN                          <<<<*/
	/*>>>>                                                      <<<<*/

	int Off1[4], Off2[4];
	int counts_dig[4][10];
	int sum_counts_dig[4];
	int index = 0;

	int pins[100];
	int max_prob[101], sum = 0;

	int i, j, x, y, k, l;

	for (i = 0; i < 4; i++)
		for (j = 0; j < 10; j++)
			counts_dig[i][j] = 0;

	x = diff1;
	y = diff2;

	for (i = 3; i >= 0; i--) {
		Off1[i] = x % 10;
		Off2[i] = y % 10;
		x /= 10;
		y /= 10;
	}

	for (i = 0; i < 4; i++)
		sum_counts_dig[i] = 0;

	for (i = 0; i < 10; i++) {
		counts_dig[0][i] = PIN_D1[i] * PIN_OtherD[(i + 10 - Off1[0]) % 10]
				* PIN_OtherD[(i + 10 - Off2[0]) % 10];
		sum_counts_dig[0] += counts_dig[0][i];
	}

	for (k = 1; k < 4; k++)
		for (i = 0; i < 10; i++) {
			counts_dig[k][i] = PIN_OtherD[i]
					* PIN_OtherD[(i + 10 - Off1[k]) % 10]
					* PIN_OtherD[(i + 10 - Off2[k]) % 10];
			sum_counts_dig[k] += counts_dig[k][i];
		}

	for (i = 1; i < 10; i++)
		for (j = 0; j < 10; j++)
			for (k = 0; k < 10; k++)
				for (l = 0; l < 10; l++)
					prob[(i - 1) * 1000 + j * 100 + k * 10 + l] =
							counts_dig[0][i] * counts_dig[1][j]
									* counts_dig[2][k] * counts_dig[3][l];

	memset(max_prob, 0, 101 * sizeof(float));
	for (i = 0; i < 9000; i++) {
		if (prob[i] > max_prob[1]) {
			max_prob[1] = prob[i];
			pins[0] = i + 1000;
		}
		adjust(max_prob, pins);
	}

	for (i=0;i<100;i++)
		sum+=pins[i];

	printf("%.4f\n",
			(float) sum
					/ (sum_counts_dig[0] * sum_counts_dig[1] * sum_counts_dig[2]
							* sum_counts_dig[3]));

	index = try_pins(pins, try_max());
	if (index != -1)
		printf("Die PIN ist: %d\n", pins[index]);
	else
		printf("Die PIN ist noch unbekannt!\n");

}

int main(void) {
	open_connection(0, &diff1, &diff2);
	attack();
	close_connection();
	exit(0);
}
