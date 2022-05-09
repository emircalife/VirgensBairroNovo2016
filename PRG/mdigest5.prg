
DEFINE CLASS MD5 AS Custom OLEPUBLIC
**********************************************************************************************************************
* Written in VFP by GILLES Patrick (C) IKOONET SARL www.ikoonet.com
* Une implémention en Visual Foxpro de l'algorithme MD5 message digest tel que definis dans le RFC 1321 par R. RIVEST
* de la sociét?RSA DATA SECURTY & MIT Laboratory for Computer Science
* A VFP implementation of the RSA Data Security, Inc. MD5 Message Digest Algorithm, as defined in RFC 1321.
**********************************************************************************************************************
* Usage (sample)
* SET PROCEDURE TO mdigest5
* MD5=CREATEOBJECT("MD5")
* MD5.tohash="abc"
* ? MD5.compute()
*******************************
tohash=""
DIMENSION SinusArray(64)
#DEFINE MAX_UINT 4294967296
#DEFINE NUMBEROFBIT 8 && UNICODE 16 (unicode not tested)


PROCEDURE init
  LOCAL I
  FOR I = 1 TO 64
    this.SinusArray(I)=TRANSFORM(MAX_UINT*ABS(SIN(I)),"@0")
    this.SinusArray(I)=BITAND(EVALUATE(this.SinusArray(I)),0xFFFFFFFF) &&CAST
  ENDFOR
RETURN .T.

PROCEDURE bourre
  LOCAL NBR_BIT_BOURRE, BOURRAGE
  Bourrage = CHR(128)+REPLICATE(CHR(0),63)
  NBR_BIT_BOURRE=(448-(LEN(THIS.TOHASH)*NUMBEROFBIT)%512)/NUMBEROFBIT
  IF (LEN(THIS.TOHASH)*NUMBEROFBIT)%512>=448
    NBR_BIT_BOURRE=(448+((512-LEN(THIS.TOHASH)*NUMBEROFBIT)%512))/NUMBEROFBIT
  ENDIF

RETURN LEFT(bourrage,NBR_BIT_BOURRE)


PROCEDURE acompleter
  LOCAL retour,decalage
  decalage=TRANSFORM(LEN(this.tohash)* NUMBEROFBIT,"@0")
  retour=""
  retour=retour+CHR(EVALUATE("0x"+SUBSTR(decalage,9,2)))
  retour=retour+CHR(EVALUATE("0x"+SUBSTR(decalage,7,2)))
  retour=retour+CHR(EVALUATE("0x"+SUBSTR(decalage,5,2)))
  retour=retour+CHR(EVALUATE("0x"+SUBSTR(decalage,3,2)))
  retour=retour+REPLICATE(CHR(0),4)
RETURN RETOUR


PROCEDURE MD5_F
LPARAMETERS x,y,z
RETURN BITOR(BITAND(X,Y),BITAND(BITNOT(X),Z))

PROCEDURE MD5_G
LPARAMETERS x,y,z
RETURN BITOR(BITAND(X,Z),BITAND(Y,BITNOT(Z)))

PROCEDURE MD5_H
LPARAMETERS x,y,z
RETURN BITXOR(X,Y,Z)

PROCEDURE MD5_I
LPARAMETERS x,y,z
RETURN BITXOR(Y,BITOR(X,BITNOT(Z)))

PROCEDURE ROTATE_LEFT
LPARAMETERS pivot, npivot
RETURN BITOR(BITLSHIFT(pivot,npivot),BITRSHIFT(pivot,32-Npivot))

procedure ronde1
LPARAMETERS PA,PB,PC,PD,PE,PF,PG
RETURN PB+this.ROTATE_LEFT(PA+this.MD5_F(PB,PC,PD)+PE+PG,PF)

procedure ronde2
LPARAMETERS PA,PB,PC,PD,PE,PF,PG
RETURN PB+this.ROTATE_LEFT(PA+this.MD5_G(PB,PC,PD)+PE+PG,PF)

PROCEDURE ronde3
LPARAMETERS PA,PB,PC,PD,PE,PF,PG
RETURN PB+this.ROTATE_LEFT(PA+this.MD5_H(PB,PC,PD)+PE+PG,PF)

PROCEDURE ronde4
LPARAMETERS PA,PB,PC,PD,PE,PF,PG
RETURN PB+this.ROTATE_LEFT(PA+this.MD5_I(PB,PC,PD)+PE+PG,PF)

PROCEDURE compute
  LOCAL tocompute,CPT_I,CPT_J,CPT_L,TMP_STRING,AA,BB,CC,DD,a,b,c,d,aa,bb,cc,dd
  
  A=BITAND(0x67452301,0xFFFFFFFF)
  B=BITAND(0xEFCDAB89,0xFFFFFFFF)
  C=BITAND(0x98BADCFE,0xFFFFFFFF)
  D=BITAND(0x10325476,0xFFFFFFFF)

  DIMENSION T_X(16)
  
  tocompute=this.tohash+this.bourre()+this.acompleter()
  
  lentocompute=LEN(tocompute)/64

  OldA=A
  OldB=B
  OldC=C
  OldD=D
  
  FOR CPT_I=0 TO lentocompute-1
    FOR CPT_J=0 TO 15
      T_X(CPT_J+1)=""
      T_X(CPT_J+1)=T_X(CPT_J+1)+RIGHT(TRANSFORM(ASC(SUBSTR(tocompute,(CPT_I*64)+(CPT_J*4)+4,1)),"@0"),2)
      T_X(CPT_J+1)=T_X(CPT_J+1)+RIGHT(TRANSFORM(ASC(SUBSTR(tocompute,(CPT_I*64)+(CPT_J*4)+3,1)),"@0"),2)
      T_X(CPT_J+1)=T_X(CPT_J+1)+RIGHT(TRANSFORM(ASC(SUBSTR(tocompute,(CPT_I*64)+(CPT_J*4)+2,1)),"@0"),2)
      T_X(CPT_J+1)=T_X(CPT_J+1)+RIGHT(TRANSFORM(ASC(SUBSTR(tocompute,(CPT_I*64)+(CPT_J*4)+1,1)),"@0"),2)

      T_X(CPT_J+1)=BITAND(EVALUATE("0x"+T_X(CPT_J+1)),0xFFFFFFFF) && CAST
      *? TRANSFORM(T_X(CPT_J+1),"@0")
      *?
    ENDFOR

    OldA=A
    OldB=B
    OldC=C
    OldD=D

    && Ronde1
    a=this.ronde1(a,b,c,d,T_X( 1), 7,this.sinusarray( 1))
    d=this.ronde1(d,a,b,c,T_X( 2),12,this.sinusarray( 2))
    c=this.ronde1(c,d,a,b,T_X( 3),17,this.sinusarray( 3))
    b=this.ronde1(b,c,d,a,T_X( 4),22,this.sinusarray( 4))

    a=this.ronde1(a,b,c,d,T_X( 5), 7,this.sinusarray( 5))
    d=this.ronde1(d,a,b,c,T_X( 6),12,this.sinusarray( 6))
    c=this.ronde1(c,d,a,b,T_X( 7),17,this.sinusarray( 7))
    b=this.ronde1(b,c,d,a,T_X( 8),22,this.sinusarray( 8))

    a=this.ronde1(a,b,c,d,T_X( 9), 7,this.sinusarray( 9))
    d=this.ronde1(d,a,b,c,T_X(10),12,this.sinusarray(10))
    c=this.ronde1(c,d,a,b,T_X(11),17,this.sinusarray(11))
    b=this.ronde1(b,c,d,a,T_X(12),22,this.sinusarray(12))

    a=this.ronde1(a,b,c,d,T_X(13), 7,this.sinusarray(13))
    d=this.ronde1(d,a,b,c,T_X(14),12,this.sinusarray(14))
    c=this.ronde1(c,d,a,b,T_X(15),17,this.sinusarray(15))
    b=this.ronde1(b,c,d,a,T_X(16),22,this.sinusarray(16))
    && ronde 2
    a=this.ronde2(a,b,c,d,T_X( 2), 5,this.sinusarray(17))
    d=this.ronde2(d,a,b,c,T_X( 7), 9,this.sinusarray(18))
    c=this.ronde2(c,d,a,b,T_X(12),14,this.sinusarray(19))
    b=this.ronde2(b,c,d,a,T_X( 1),20,this.sinusarray(20))

    a=this.ronde2(a,b,c,d,T_X( 6), 5,this.sinusarray(21))
    d=this.ronde2(d,a,b,c,T_X(11), 9,this.sinusarray(22))
    c=this.ronde2(c,d,a,b,T_X(16),14,this.sinusarray(23))
    b=this.ronde2(b,c,d,a,T_X( 5),20,this.sinusarray(24))

    a=this.ronde2(a,b,c,d,T_X(10), 5,this.sinusarray(25))
    d=this.ronde2(d,a,b,c,T_X(15), 9,this.sinusarray(26))
    c=this.ronde2(c,d,a,b,T_X( 4),14,this.sinusarray(27))
    b=this.ronde2(b,c,d,a,T_X( 9),20,this.sinusarray(28))

    a=this.ronde2(a,b,c,d,T_X(14), 5,this.sinusarray(29))
    d=this.ronde2(d,a,b,c,T_X( 3), 9,this.sinusarray(30))
    c=this.ronde2(c,d,a,b,T_X( 8),14,this.sinusarray(31))
    b=this.ronde2(b,c,d,a,T_X(13),20,this.sinusarray(32))

    && ronde 3
    a=this.ronde3(a,b,c,d,T_X( 6), 4,this.sinusarray(33))
    d=this.ronde3(d,a,b,c,T_X( 9),11,this.sinusarray(34))
    c=this.ronde3(c,d,a,b,T_X(12),16,this.sinusarray(35))
    b=this.ronde3(b,c,d,a,T_X(15),23,this.sinusarray(36))

    a=this.ronde3(a,b,c,d,T_X( 2), 4,this.sinusarray(37))
    d=this.ronde3(d,a,b,c,T_X( 5),11,this.sinusarray(38))
    c=this.ronde3(c,d,a,b,T_X( 8),16,this.sinusarray(39))
    b=this.ronde3(b,c,d,a,T_X(11),23,this.sinusarray(40))

    a=this.ronde3(a,b,c,d,T_X(14), 4,this.sinusarray(41))
    d=this.ronde3(d,a,b,c,T_X( 1),11,this.sinusarray(42))
    c=this.ronde3(c,d,a,b,T_X( 4),16,this.sinusarray(43))
    b=this.ronde3(b,c,d,a,T_X( 7),23,this.sinusarray(44))

    a=this.ronde3(a,b,c,d,T_X(10), 4,this.sinusarray(45))
    d=this.ronde3(d,a,b,c,T_X(13),11,this.sinusarray(46))
    c=this.ronde3(c,d,a,b,T_X(16),16,this.sinusarray(47))
    b=this.ronde3(b,c,d,a,T_X( 3),23,this.sinusarray(48))

    && ronde 4
    a=this.ronde4(a,b,c,d,T_X( 1), 6,this.sinusarray(49))
    d=this.ronde4(d,a,b,c,T_X( 8),10,this.sinusarray(50))
    c=this.ronde4(c,d,a,b,T_X(15),15,this.sinusarray(51))
    b=this.ronde4(b,c,d,a,T_X( 6),21,this.sinusarray(52))

    a=this.ronde4(a,b,c,d,T_X(13), 6,this.sinusarray(53))
    d=this.ronde4(d,a,b,c,T_X( 4),10,this.sinusarray(54))
    c=this.ronde4(c,d,a,b,T_X(11),15,this.sinusarray(55))
    b=this.ronde4(b,c,d,a,T_X( 2),21,this.sinusarray(56))

    a=this.ronde4(a,b,c,d,T_X( 9), 6,this.sinusarray(57))
    d=this.ronde4(d,a,b,c,T_X(16),10,this.sinusarray(58))
    c=this.ronde4(c,d,a,b,T_X( 7),15,this.sinusarray(59))
    b=this.ronde4(b,c,d,a,T_X(14),21,this.sinusarray(60))

    a=this.ronde4(a,b,c,d,T_X( 5), 6,this.sinusarray(61))
    d=this.ronde4(d,a,b,c,T_X(12),10,this.sinusarray(62))
    c=this.ronde4(c,d,a,b,T_X( 3),15,this.sinusarray(63))
    b=this.ronde4(b,c,d,a,T_X(10),21,this.sinusarray(64))

    a=a+olda
    b=b+oldb
    c=c+oldC
    d=d+oldd
  ENDFOR
  
  a=TRANSFORM(BITAND(a,0xFFFFFFFF),"@0") && cast
  b=TRANSFORM(BITAND(b,0xFFFFFFFF),"@0") && cast
  c=TRANSFORM(BITAND(c,0xFFFFFFFF),"@0") && cast
  d=TRANSFORM(BITAND(d,0xFFFFFFFF),"@0") && cast
  
  a=SUBSTR(a,9,2)+SUBSTR(a,7,2)+SUBSTR(a,5,2)+SUBSTR(a,3,2)
  b=SUBSTR(b,9,2)+SUBSTR(b,7,2)+SUBSTR(b,5,2)+SUBSTR(b,3,2)
  c=SUBSTR(c,9,2)+SUBSTR(c,7,2)+SUBSTR(c,5,2)+SUBSTR(c,3,2)
  d=SUBSTR(d,9,2)+SUBSTR(d,7,2)+SUBSTR(d,5,2)+SUBSTR(d,3,2)

RETURN a+b+c+d

PROCEDURE testsuite
&& return true if all the reference value are true
  LOCAL test
  
  test = .T.
  
  this.tohash=""
  IF LOWER(this.compute())#"d41d8cd98f00b204e9800998ecf8427e"
    RETURN this.tohash
  ENDIF
  
  this.tohash="a"
  IF LOWER(this.compute())#"0cc175b9c0f1b6a831c399e269772661"
    RETURN this.tohash
  ENDIF
  
  this.tohash="abc"
  IF LOWER(this.compute())#"900150983cd24fb0d6963f7d28e17f72"
    RETURN this.tohash
  ENDIF
  
  this.tohash="message digest"
  IF LOWER(this.compute())#"f96b697d7cb7938d525a2f31aaf161d0"
    RETURN this.tohash
  ENDIF
  
  this.tohash="abcdefghijklmnopqrstuvwxyz"
  IF LOWER(this.compute())#"c3fcd3d76192e4007dfb496cca67e13b"
    RETURN this.tohash
  ENDIF
  
  this.tohash="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
  IF LOWER(this.compute())#"d174ab98d277d9f5a5611c2c9f419d9f"
    RETURN this.tohash
  ENDIF
  
  this.tohash="12345678901234567890123456789012345678901234567890123456789012345678901234567890"
  IF LOWER(this.compute())#"57edf4a22be3c955ac49da2e2107b67a"
    RETURN this.tohash
  ENDIF
  
  RETURN test
ENDDEFINE