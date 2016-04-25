/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**   Proktikum "Kryptographie und Datensicherheitstechnik"   *
**                                                           *
** Versuch 7: El-Gamal-Signatur                              *
**                                                           *
**************************************************************
**
** signsupport.c: Laden der Personendaten und Erzeugen des MDC
**/

#include "sign.h"

/*
 * Generate_MDC( msg, P, mdc ) :
 *
 *   Berechnet die MDC zur Nachricht MSG. Der zu unterschreibende Teil 
 *   von MSG (ist abhängig vom Typ) wird als Byte-Array interpretiert
 *   und darüber der MDC berechnet. P ist der globale El-Gamal-Modulus.
 *
 * ACHTUNG: msg.type muß unbedingt richtig gesetzt sein!
 */

void Generate_MDC( const Message *msg, const_longnum_ptr p, longnum_ptr mdc)
  {
    static const DES_key key = { 0x7f,0x81,0x5f,0x92,0x1a,0x97,0xaf,0x18 };
    DES_data reg,desout;
    DES_ikey ikey;
    int i,j,len;
    const UBYTE *ptr;

    switch (msg->typ) {
      case ReportRequest:
        ptr = (const UBYTE *) &msg->body.ReportRequest;
	len = sizeof(msg->body.ReportRequest.Name);
	break;
      case ReportResponse:
	ptr = (const UBYTE *) &msg->body.ReportResponse.Report;
	len = sizeof(String)*msg->body.ReportResponse.NumLines;
	break;
      case VerifyRequest:
	ptr = (const UBYTE *) &msg->body.VerifyRequest.Report;
	len = sizeof(String)*msg->body.VerifyRequest.NumLines;
	break;
      case VerifyResponse:
	ptr = (const UBYTE *) &msg->body.VerifyResponse.Res;
	len = sizeof(msg->body.VerifyResponse.Res);
	break;
      default :
	fprintf(stderr,"GENERATE_MDC: Illegaler Typ von Nachricht!\n");
	exit(20);
	break;
    }

    DES_GenKeys( key,0,ikey);
    for (i=0; i<DES_DATA_WIDTH; i++) reg[i]=0;

    /***************   MDC berechnen   ***************/
    while (len>=DES_DATA_WIDTH) {
      DES_Cipher(ikey,reg,desout);
      for (j=0; j<DES_DATA_WIDTH; j++)
	reg[j] = desout[j] ^ *ptr++;
      len -= DES_DATA_WIDTH;
    }

    if (len>0) { /* LEN ist KEIN Vielfaches von 8 ! */
      DES_Cipher(ikey,reg,desout);
      for (j=0; j<len; j++)
	reg[j] = desout[j] ^ *ptr++;
      for (j=len; j<DES_DATA_WIDTH; j++)
	reg[j] = desout[j];
    }

    /***************  MDC konvertieren  ***************/
    LInitNumber(mdc,nbits,0);
    LMakeZero(mdc);
    for (j=0; j<DES_DATA_WIDTH; j++)
      mdc->data.b[j] = reg[j];

    for (j=0; j<8; j++)
      LModSquare(mdc,mdc,p);
  }



/*
 * Get_Public_Key(name,y) :
 *
 *  Sucht in der systemweiten Tabelle den öffentlichen Schlüssel des
 *  Teilnehmers NAME und speichert ihn in Y.
 *  
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Public_Key( const String name, longnum_ptr y)
  {
    FILE *f;
    PublicData pd;
    char *filename;
    const char *root;

    if (!(root=getenv("PRAKTROOT"))) root="";
    filename=concatstrings(root,"/loesungen/sign_schein/public_keys.data",NULL);
    if (!(f=fopen(filename,"r"))) {
      fprintf(stderr,"GET_PUBLIC_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
      exit(20);
    }
    free(filename);

    while (!feof(f) && fread(&pd,sizeof(pd),1,f)==1) {
      if (!strcmp(pd.name,name)) {
        LCpy(y,&pd.y);
	fclose(f);
	return 1;
      }
    }
    fclose(f);

    fprintf(stderr,"GET_PUBLIC_KEY: Benutzer \"%s\" nicht gefunden\n",name);
    return 0;
  }


/*
 * Get_Privat_Key(filename,p,w,x) :
 *
 *  Läd den eigenen geheimen Schlüssel nach X. Die globalen (öffentlichen)
 *  Daten P und W werden ebenfalls aus dieser Datei geladen.
 *  FILENAME ist der Name der Datei, in der der geheime Schlüssel gespeichert
 *  ist. Wird NULL angegeben, so wird die Standarddatei "./privat_key.data" benutzt.
 *
 * RETURN-Code: 1 bei Erfolg, 0 sonst.
 */

int Get_Privat_Key(const char *filename, longnum_ptr p, longnum_ptr w, longnum_ptr x)
  {
    FILE *f;
    SecretData sd;

    if (!filename) filename = concatstrings(getenv("HOME"),"/private_key.data",NULL);
    if (!(f=fopen(filename,"r"))) {
      fprintf(stderr,"GET_PRIVAT_KEY: Kann die Datei %s nicht öffnen: %s\n",filename,strerror(errno));
      return 0;
    }

    if (fread(&sd,sizeof(sd),1,f)!=1) {
      fprintf(stderr,"GET_PRIVAT_KEY: Fehler beim Lesen der Datei %s\n",filename);
      fclose(f);
      return 0;
    }
    fclose(f);
    LCpy(x,&sd.x);
    LCpy(p,&sd.p);
    LCpy(w,&sd.w);

    return 1;
  }


