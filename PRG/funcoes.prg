PROCEDURE AnosDesfile(aiIdVirgem, acCracha, aiAno)
	IF(NOT Seek(aiIdVirgem+aiAno, 'ANOSDESFILE', 'VIRGEMANO'))
		APPEND BLANK IN ANOSDESFILE
		REPLACE	IDVIRGEM	WITH	aiIdVirgem	IN	ANOSDESFILE
		REPLACE	CRACHA	WITH	acCracha		IN	ANOSDESFILE
		REPLACE	ANO		WITH	aiAno			IN	ANOSDESFILE
	ENDIF
ENDPROC

FUNCTION GetChaveUnica(aiAno, acNome, aiIdVirgem)
	LOCAL lcChaveUnicaDescr	AS	STRING
	LOCAL lcChaveUnicaCript	AS	STRING
	
	lcChaveUnicaDescr = AllTrim(Str(aiAno)) + AllTrim(acNome) + AllTrim(Str(aiIdVirgem))
	
	
	RETURN lcChaveUnicaCript
ENDFUNC

PROCEDURE EnviaMail(aHost, aPorta, aUsuario, aSenha, aAssunto, aMensagem, aEmailVirgens, aEmailDestino, aAnexo)
	LOCAL loConfig AS CDO.Configuration
	LOCAL	loFlds	AS	Object
	LOCAL	loMsg		AS	CDO.Message

	loConfig = CreateObject("CDO.Configuration")
	loFlds = loConfig.Fields
	
	WITH loFlds
		.Item("http://schemas.microsoft.com/cdo/configuration/sendusing") 				= 2
		.Item("http://schemas.microsoft.com/cdo/configuration/smtpserver") 				= aHost
		.Item("http://schemas.microsoft.com/cdo/configuration/smtpserverport") 			= aPorta
		.Item("http://schemas.microsoft.com/cdo/configuration/smtpconnectiontimeout") = 10
		.Item("http://schemas.microsoft.com/cdo/configuration/smtpusessl") 				= .T.
		.Item("http://schemas.microsoft.com/cdo/configuration/sendusername") 			= aEmailVirgens
		.Item("http://schemas.microsoft.com/cdo/configuration/sendpassword") 			= aSenha
		.Item("http://schemas.microsoft.com/cdo/configuration/smtpauthenticate") 		= 3
		.Item("http://schemas.microsoft.com/cdo/configuration/cdoURLProxyServer") 		= "smtp.mail.yahoo.com"
		.Update()
	ENDWITH
	
	loMsg = CreateObject("CDO.Message")
	WITH loMsg
		.Configuration =	loConfig
		.To            =	aEmailDestino
		.From				=	aEmailVirgens
		.Subject			=	aAssunto

		XHTML	=	"<TABLE><TR><TD>" +	StrTran(aMensagem, "*","</TD></TR><TR><TD>") + "</TD></TR></TABLE>"
		.HTMLBody	=	XHTML
		
		IF NOT EMPTY(aAnexo)
      	.AddAttachment(aAnexo)
*        .AddAttachment()     && Hay que agregar una línea AddAttachment() por cada archivo adjunto
      ENDIF
      
		TRY
			.Send()
		CATCH TO oErr
			MessageBox(oErr.Message)
			Exit
		ENDTRY
			MessageBox("Email enviado com sucesso!")
	ENDWITH
ENDPROC

FUNCTION Conectar
	*** conexao = "Driver={MySQL ODBC 8.0 ANSI Driver};Server=localhost;Port=3306;User=root;Password=1234;Option=16;"
	*** nHandler = SQLSTRINGCONNECT(conexao)

	pNomServer = 'localhost'
	pNomDatabase = 'pessoasdb'
	pUser = 'root'
	pPwd = '1234'
	pOption = '16'
	nHandler = 0

	ConnectionString = "DRIVER={MySQL ODBC 8.0 ANSI Driver};" + ;
	                   "SERVER=" + Alltrim(pNomServer) + ";" + ;
	                   "DATABASE=" + Alltrim(pNomDatabase) + ";" + ;
	                   "USER=" + Alltrim(pUser) + ";" + ;
	                   "PASSWORD=" + Alltrim(pPwd) + ";" + ;
	                   "OPTION=" + Alltrim(pOption) + ";"

	nHandler = SqlStringConnect(ConnectionString)

	RETURN nHandler
ENDFUNC