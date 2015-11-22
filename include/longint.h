/***************************************************************************
**                                                                         *
**      E.I.S.S. --- Toolbox-Project --- Modulare Langzahlarithmetik       *
**                                                                         *
****************************************************************************
**                                                                         *
**   LONGINT.H: Headerfile fur die modulare Langzahlarithmetik             *
**              Dokumentation siehe Longint-Tool-box-Dokumentation         *
**              !!!FROZEN VERSION für das KRYPTOPRAKTIKUM!!!               *
**                                                                         *
****************************************************************************
**                                                                         *
**    Filename: longint.h                                                  *
**     Version: 5.17, 16-Aug-94                                            *
**      Author: Steffen Stempel (SSA)                                      *
** Source-Host: Hades                                                      *
**    Modifier: ----                                                       *
**     Support: Peer Wichmann (Low-Byte-First)                             *
**    Machines: all, ifdef, Assembler-Source on local hosts                *
**       State: released                                                   *
**                                                                         *
***************************************************************************/


#ifndef LONGINT_H

#define LONGINT_H

#ifndef _PRAKTIKUM_H
#  include <praktikum.h>
#endif

/*
 * MAXNBITS gibt die maximale Größe von einfach genauen Langzahlen an.
 * Für interne Variablen wird Speicher für MAXNBITS viele Bits bereitgestellt.
 * Zur Verbesserung der Performance müssen für Langzahlen einige Randbedingungen
 * gelten: 1) Die Zahlen müssen eine minimale Länge von MINNBITS haben,
 *         2) Ihre Länge muß durch STEPNBITS teilbar sein.
 *
 * Diese Makros können auch von außen gesetzt werden.
 *
 * Daraus abgeleitet werden Makros entsprechender Namen, die für 16- und 32-Bit
 * Worte gedacht sind.
 */
#ifndef MAXNBITS
#  define MAXNBITS  4096
#endif
#ifndef MINNBITS
#  define MINNBITS    32
#endif
#ifndef STEPNBITS
#  define STEPNBITS   32
#endif

#define MAXNBYTES  (MAXNBITS/8)
#define MAXNWORDS  (MAXNBITS/16)
#define MAXNLONGS  (MAXNBITS/32)
#define MINNBYTES  (MINNBITS/8)
#define MINNWORDS  (MINNBITS/16)
#define MINNLONGS  (MINNBITS/32)
#define STEPNBYTES (STEPNBITS/8)
#define STEPNWORDS (STEPNBITS/16)
#define STEPNLONGS (STEPNBITS/32)


/*************  Langzahl und Doppelte Langzahl  ***********/
/*
 * Eine Langzahl besteht aus einem Feld, welches die tatsächliche Länge in
 * 32-Bit-Worten angibt und einer Union, die den Zugriff auf die einzelnen
 * Komponenten 8, 16 und 32 Bit breit zulassen.
 * Assembler-Routinen bekommen diese Struct NIE übergeben, da aus Alignment-
 * Gründen vor dem NLONGS Feld noch ein DOUBLE o.ä. eingefügt werden könnte!
 *
 * Die Datentypen longnum_(byte|word|long)_ptr sind Zeiger auf die zur Darstellung
 * benutzten Arrays, longnum(byte|word|long)array sind Arrays der entsprechenden Länge
 *
 * Die Form const_longnum(byte|word|long)ptr sind Zeiger auf READ-ONLY-Arrays
 * des entsprechenden Types.
 *
 * Der Aufbau von longnums und doublelongnums ist so gestaltet, daß auf eine longnum auch
 * als dooublelongnum zugegriffen werden kann, d.h. es wird garantiert, daß
 * der Datenbereich der Zahl immer AM ENDE der Struct liegt!
 */

typedef UBYTE longnum_byte_array[MAXNBYTES];
typedef UWORD longnum_word_array[MAXNWORDS];
typedef ULONG longnum_long_array[MAXNLONGS];
typedef UBYTE doublelongnum_byte_array[2*MAXNBYTES];
typedef UWORD doublelongnum_word_array[2*MAXNWORDS];
typedef ULONG doublelongnum_long_array[2*MAXNLONGS];

struct _longnum_ {
  double force_align;
  WORD  nlongs;          /* Anzahl der (gültigen) 32-Bit-Wrote */
  WORD  size;            /* Größe des Datenbereiches in Langworten */
  ULONG flags;           /* diverse Flags, z.Z. nur von LggT benutzt */
  union {
    longnum_byte_array b;
    longnum_word_array w;
    longnum_long_array l;
  } data;
};
typedef struct _longnum_ longnum, *longnum_ptr;
typedef const struct _longnum_ *const_longnum_ptr;

struct _doublelongnum_ {
  double force_align;
  WORD  nlongs;          /* Anzahl der (gültigen) 32-Bit-Wrote */
  WORD  size;            /* Größe des Datenbereiches in Langworten */
  ULONG flags;           /* diverse Flags, z.Z. nur von LggT benutzt */
  union {
    doublelongnum_byte_array b;
    doublelongnum_word_array w;
    doublelongnum_long_array l;
  } data;
};
typedef struct _doublelongnum_ doublelongnum, *doublelongnum_ptr;
typedef const struct _doublelongnum_ *const_doublelongnum_ptr;

typedef UBYTE *longnum_byte_ptr;
typedef const UBYTE *const_longnum_byte_ptr;
typedef UWORD *longnum_word_ptr;
typedef const UWORD *const_longnum_word_ptr;
typedef ULONG *longnum_long_ptr;
typedef const ULONG *const_longnum_long_ptr;
typedef UBYTE *doublelongnum_byte_ptr;
typedef const UBYTE *const_doublelongnum_byte_ptr;
typedef UWORD *doublelongnum_word_ptr;
typedef const UWORD *const_doublelongnum_word_ptr;
typedef ULONG *doublelongnum_long_ptr;
typedef const ULONG *const_doublelongnum_long_ptr;

/*
 * NBITS, NBYTES, NWORDS, NLONGS, geben die Anzahl der entsprechende Teile
 * einer Langzxahl x zurück
 */

#define NBITS(x)    ((x)->nlongs*32)
#define NBYTES(x)   ((x)->nlongs*4)
#define NWORDS(x)   ((x)->nlongs*2)
#define NLONGS(x)   ((x)->nlongs)


/*
 * Deklaration diverses Funktions-Zeiger:
 *    randfuncptr : Zeiger auf eine Funktion, die als Alternativer Zufallszahlen-
 *                  generator verwendet werden kann. Diese Funktion muß die
 *                  selben Parameter wie LRand() bearbeiten.
 * errtrapfuncptr : Zeiger auf eine applikationsspezifische Fehlerfunktion,
 *                  die von den Arithmetik-Routinen im Fehlerfall aufgerufen wird.
 *                  Diese Funktion bekommt als Parameter die Nummer der den Fehler
 *                  auslösenden Funktion, den Fehlercode, sowie Namen und Wert des
 *                  ersten und zweiten fehlerhaften Parameters übergeben. Diese letzten
 *                  4 Parameter dürfen auch NULL sein.
 */

typedef void (*randfuncptr)    ( const_longnum_ptr maximum, longnum_ptr x );
typedef void (*errtrapfuncptr) ( int function, int errcode,
				 const char *n1, const_longnum_ptr v1,
				 const char *n2, const_longnum_ptr v2 );

/*
 * Prototypes der exportierten Funktionen
 */
int  LAdd              ( const_longnum_ptr x, longnum_ptr y );
int  LAdd3             ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z );
int  LAddq             ( long i, longnum_ptr x );
int  LChangeSize       ( longnum_ptr y, const_longnum_ptr x, int n );
int  LCompare          ( const_longnum_ptr x, const_longnum_ptr y );
int  LDivMod           ( const_doublelongnum_ptr u, const_longnum_ptr v, 
			longnum_ptr r, doublelongnum_ptr q );
int  LGetBit           ( const_longnum_ptr x, int pos );
int  LHex2DoubleLong   ( const char *str, doublelongnum_ptr x );
int  LHex2Long         ( const char *str, longnum_ptr x );
int  LInitDoubleNumber ( doublelongnum_ptr x, int nbits, int flags );
int  LInitNumber       ( longnum_ptr x, int nbits, int flags );
int  LIntCmp           ( ULONG i, const_longnum_ptr x );
int  LInvert           ( longnum_ptr a, const_longnum_ptr n );
int  LIsFastModulus    ( const_longnum_ptr x );
int  LIsPrim           ( const_longnum_ptr n, int errprop, randfuncptr randfunc );
int  LIsPrimElem       ( const_longnum_ptr x, const_longnum_ptr p );
int  LLong2Int         ( ULONG *i, const_longnum_ptr x );
int  LPrimDIV2IsPrim   ( const_longnum_ptr p, int errprop, randfuncptr randfunc );
int  LSub              ( const_longnum_ptr x, longnum_ptr y );
int  LSub3             ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z );
void LggT              ( const_longnum_ptr u, const_longnum_ptr v, longnum_ptr ggt, 
			longnum_ptr US, longnum_ptr VS, int *sign );
char *LDoubleLong2Hex  ( const_doublelongnum_ptr x, char *str, int grouping, int zeroflg );
char *LLong2Hex        ( const_longnum_ptr x, char *str, int grouping, int zeroflg );
void LAddMod           ( const_longnum_ptr x, longnum_ptr y, const_longnum_ptr n );
void LCpy              ( longnum_ptr x, const_longnum_ptr y );
void LDiv2             ( longnum_ptr x );
void LFastModMult      ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z, 
			const_longnum_ptr d, const_longnum_ptr n );
void LFastModReduce    ( doublelongnum_ptr w, longnum_ptr z, const_longnum_ptr d, 
			const_longnum_ptr n );
void LFastModSquare    ( const_longnum_ptr a, longnum_ptr x, const_longnum_ptr d, 
			const_longnum_ptr n );
void LFromHiByteFirst  ( longnum_ptr x );
void LFromLowByteFirst ( longnum_ptr x );
void LGenDLPPrim       ( longnum_ptr x, int errprop, randfuncptr randfunc );
void LGenPrim          ( longnum_ptr x, int errprop, randfuncptr randfunc );
void LInt2Long         ( ULONG i, longnum_ptr x );
void LMakeZero         ( longnum_ptr x );
void LModMult          ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z, 
			const_longnum_ptr n );
void LModExp           ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z, 
			const_longnum_ptr n );
void LModMultExp       ( const_longnum_ptr a, const_longnum_ptr b, const_longnum_ptr c, const_longnum_ptr d, longnum_ptr r, 
			const_longnum_ptr n );
void LModReduce        ( doublelongnum_ptr w, longnum_ptr z, const_longnum_ptr n );
void LModSquare        ( const_longnum_ptr a, longnum_ptr x, const_longnum_ptr n );
void LMult             ( const_longnum_ptr x, const_longnum_ptr y, doublelongnum_ptr z );
void LNeg              ( longnum_ptr x );
void LNegMod           ( longnum_ptr x, const_longnum_ptr n );
void LRand             ( const_longnum_ptr maximum, longnum_ptr x );
void LSeed             ( ULONG seed );
void LSetBit           ( longnum_ptr x, int pos, int value );
void LSquare           ( const_longnum_ptr a, doublelongnum_ptr z );
void LStdModMult       ( const_longnum_ptr x, const_longnum_ptr y, longnum_ptr z, 
			const_longnum_ptr d, const_longnum_ptr n );
void LStdModReduce     ( doublelongnum_ptr w, longnum_ptr z, const_longnum_ptr d, 
			const_longnum_ptr n );
void LStdModSquare     ( const_longnum_ptr a, longnum_ptr x, const_longnum_ptr d, 
			const_longnum_ptr n );
void LSubMod           ( const_longnum_ptr x, longnum_ptr y, const_longnum_ptr n );
void LToHiByteFirst    ( longnum_ptr x );
void LToLowByteFirst   ( longnum_ptr x );
int  LLog2             ( const_longnum_ptr x );
int  LAdjustSize       ( int flag, ... );

const char *LFunction2Name        ( int function );
const char *LError2Name           ( int errcode );
errtrapfuncptr LSetErrorTrap      ( errtrapfuncptr newtrap );
   
/*
 * Nummern der einzelnen Funktionen. Diese sind für den
 *   Error-Handler von Bedeutung
 */

#define FUNCTION_LAdd                           1
#define FUNCTION_LAdd3                          2
#define FUNCTION_LAddq                          3
#define FUNCTION_LChangeSize                    4
#define FUNCTION_LCompare                       5
#define FUNCTION_LDivMod                        6
#define FUNCTION_LGetBit                        7
#define FUNCTION_LHex2DoubleLong                8
#define FUNCTION_LHex2Long                      9
#define FUNCTION_LInitDoubleNumber              10
#define FUNCTION_LInitNumber                    11
#define FUNCTION_LInvert                        12
#define FUNCTION_LIsFastModulus                 13
#define FUNCTION_LIsPrim                        14
#define FUNCTION_LIsPrimElem                    15
#define FUNCTION_LLong2Int                      16
#define FUNCTION_LPrimDIV2IsPrim                17
#define FUNCTION_LSub                           18
#define FUNCTION_LSub3                          19
#define FUNCTION_LggT                           20
#define FUNCTION_LDoubleLong2Hex                21
#define FUNCTION_LLong2Hex                      22
#define FUNCTION_LAddMod                        23
#define FUNCTION_LCpy                           24
#define FUNCTION_LDiv2                          25
#define FUNCTION_LFastModMult                   26
#define FUNCTION_LFastModReduce                 27
#define FUNCTION_LFastModSquare                 28
#define FUNCTION_LFromHiByteFirst               29
#define FUNCTION_LFromLowByteFirst              30
#define FUNCTION_LGenDLPPrim                    31
#define FUNCTION_LGenPrim                       32
#define FUNCTION_LInt2Long                      33
#define FUNCTION_LMakeZero                      34
#define FUNCTION_LModExp                        35
#define FUNCTION_LModMult                       36
#define FUNCTION_LModReduce                     37
#define FUNCTION_LModSquare                     38
#define FUNCTION_LMult                          39
#define FUNCTION_LNeg                           40
#define FUNCTION_LNegMod                        41
#define FUNCTION_LRand                          42
#define FUNCTION_LSeed                          43
#define FUNCTION_LSetBit                        44
#define FUNCTION_LSquare                        45
#define FUNCTION_LStdModMult                    46
#define FUNCTION_LStdModReduce                  47
#define FUNCTION_LStdModSquare                  48
#define FUNCTION_LSubMod                        49
#define FUNCTION_LToHiByteFirst                 50
#define FUNCTION_LToLowByteFirst                51
#define FUNCTION_LIntCmp                        52
#define FUNCTION_LFunction2Name                 53
#define FUNCTION_LError2Name                    54
#define FUNCTION_LSetErrorTrap                  55
#define FUNCTION_LModMultExp                    56
#define FUNCTION_KERNEL                         57 /* stellvertreter f"ur alle Kernel-Funktionen */
#define FUNCTION_LLog2                          58
#define FUNCTION_LAdjustSize                    59

/*
 * Fehler-Code-Definitionen. Diese Fehlercode werden an die
 * Error-Trap zusammen mit der FUnktionsnummer gelemldet.
 */

#define ERROR_IllegalCharacter                  1 /* FROMHEX: Unerlaubtes Zeichen in Hexadezimaler Langzahl */
#define ERROR_TooManyHexDigits                  2 /* FROMHEX: Hex-String zu Lang für langzahlenwandlung */
#define ERROR_DivideByZero                      3 /* LDIVMOD: Division durch 0 */
#define ERROR_ResultTooLarge                    4 /* LCHANGESIZE: Ergebnis ist größser als Eingaben */
#define ERROR_IllegalBitPosition                5 /* LGETBIT/LSETBIT: ungültige Bit-Position */
#define ERROR_IllegalNumberLength               6 /* LChanegSize/LInitNumber: Illegale Zahlenlänge */
#define ERROR_LengthInconsistence               7 /* versch. Parameter haben unetrschiedliche Zahlenänge */
#define ERROR_TooManyParameters                 9 /* Zu viele Parameter in LAdjustSize() */

/*
 * Als Makros realisierte Funktionen
 */

#define LIsZero(x)  (LIntCmp(0,(x))==0)
#define LIsOne(x)   (LIntCmp(1,(x))==0)


/*
 * Makros für den Zugriff auf einzelne Komponenten einer Langzahl und
 *   Schleifenbildung über die Teile einer Langzahl.
 *
 *  LONGNUM_GET_(BYTE|WORD|LONG)(x,i) : Gibt das i. Byte/Wort/Langwort (0. ist LSW) 
 *        der Langzahl x zurück. Der Ausruck kann auch auf der linken Seite einer
 *        Zuweisung auftauchen.
 *                         
 *  LONGNUM_GET_(BYTE|WORD|LONG)_INDEX(i) : Wie oben, gibt jedoch nur den INDEX in das
 *        Datenarray zurück.
 *
 *  LONGNUM_FOR_(BYTE|WORD|LONG)_L2H(nw,index,start,end) : Läßt die Laufvariable 
 *         INDEX vom Byte/Wort/Langwort #START (niederwertig) bis einschließlich zum 
 *         #END (höherwertig) laufen. Es muß unbedingt start <= end gelten!
 *         Die Laufvariable INDEX wird direkt zum Zugriff auf longnum.data.x benutzt!
 *         NW ist die Anzahl der gültigen 16-Bit-Worte.
 *         START/END müssen BYTE|WORD|LONG-Index-Angaben sein und es muß immer start<=end gelten!
 *
 *  LONGNUM_FOR_(BYTE|WORD|LONG)_H2L(...) : Wie oben, läuft jedoch in der anderen Richtung
 *         START/END müssen BYTE|WORD|LONG-Index-Angaben sein und es muß immer start>=end gelten!
 */

#ifdef LOWBYTEFIRST

#  define LONGNUM_GET_BYTE(x,i) (x)->data.b[i]
#  define LONGNUM_GET_WORD(x,i) (x)->data.w[i]
#  define LONGNUM_GET_LONG(x,i) (x)->data.l[i]

#  define LONGNUM_FOR_BYTE_L2H(nw,index,start,end) \
   for (index=(start); index<=(end); index++)
#  define LONGNUM_FOR_WORD_L2H(nw,index,start,end) \
   for (index=(start); index<=(end); index++)
#  define LONGNUM_FOR_LONG_L2H(nw,index,start,end) \
   for (index=(start); index<=(end); index++)

#  define LONGNUM_FOR_BYTE_H2L(nw,index,start,end) \
   for (index=(start); index>=(end); index--)
#  define LONGNUM_FOR_WORD_H2L(nw,index,start,end) \
   for (index=(start); index>=(end); index--)
#  define LONGNUM_FOR_LONG_H2L(nw,index,start,end) \
   for (index=(start); index>=(end); index--)

#else

#  define LONGNUM_GET_BYTE(x,i) (x)->data.b[(x)->nlongs*4-1-(i)]
#  define LONGNUM_GET_WORD(x,i) (x)->data.w[(x)->nlongs*2-1-(i)]
#  define LONGNUM_GET_LONG(x,i) (x)->data.l[(x)->nlongs  -1-(i)]

#  define LONGNUM_FOR_BYTE_L2H(nw,index,start,end)  \
   for (index=((nw)*2-1)-(start); index>=((nw)*2-1)-(end); index--)
#  define LONGNUM_FOR_WORD_L2H(nw,index,start,end)  \
   for (index=((nw)-1)-(start);   index>=((nw)-1)-(end);   index--)
#  define LONGNUM_FOR_LONG_L2H(nw,index,start,end)  \
   for (index=((nw)/2-1)-(start); index>=((nw)/2-1)-(end); index--)

#  define LONGNUM_FOR_BYTE_H2L(nw,index,start,end)  \
   for (index=((nw)*2-1)-(start); index<=((nw)*2-1)-(end); index++)
#  define LONGNUM_FOR_WORD_H2L(nw,index,start,end)  \
   for (index=((nw)-1)-(start);   index<=((nw)-1)-(end);   index++)
#  define LONGNUM_FOR_LONG_H2L(nw,index,start,end)  \
   for (index=((nw)/2-1)-(start); index<=((nw)/2-1)-(end); index++)

#endif

#endif


