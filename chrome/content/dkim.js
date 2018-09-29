var personalDKIM =
{
 _Prefs: Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.pdkim."),
 _Passes:  Components.classes["@mozilla.org/login-manager;1"].getService(Components.interfaces.nsILoginManager),
 _msgcomposeWindow: null,
 init: function()
 {
  personalDKIM._msgcomposeWindow = document.getElementById("msgcomposeWindow");
  personalDKIM._msgcomposeWindow.addEventListener("compose-send-message", personalDKIM.sending, true);
 },
 terminate: function()
 {
  personalDKIM._msgcomposeWindow.removeEventListener("compose-send-message", personalDKIM.sending, true);
 },
 _loadKey: function(keyData, pass)
 {
  if (keyData.indexOf("BEGIN RSA PRIVATE KEY") > -1)
  {
   if (keyData.indexOf("Proc-Type: 4,ENCRYPTED") > -1)
   {
    //5
    if (pass == "")
    {
     console.log("PKDIM: Private Key is encrypted. No password provided. Is the password null?");
     return false;
    }
    return KEYUTIL.getKey(keyData, pass);
   }
   else
   {
    //1
    return KEYUTIL.getKey(keyData);
   }
  }
  else if (keyData.indexOf("BEGIN PRIVATE KEY") > -1)
  {
   //8 (unencrypted)
   return KEYUTIL.getKey(keyData);
  }
  else if (keyData.indexOf("BEGIN ENCRYPTED PRIVATE KEY") > -1)
  {
   //8 (encrypted)
   if (pass == "")
   {
    console.log("PKDIM: Private Key is encrypted. No password provided. Is the password null?");
    return false;
   }
   return KEYUTIL.getKey(keyData, pass);
  }
  return false;
 },
 _hex2bin: function(hex)
 {
  var bytes = [];
  for(var i=0; i< hex.length-1; i+=2)
  {
   bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return String.fromCharCode.apply(String, bytes);    
 },
 _cleanFrom: function(sFrom)
 {
  if (sFrom.indexOf("<") < 0)
   return sFrom;
  sFrom = sFrom.substring(sFrom.indexOf("<") + 1);
  if (sFrom.indexOf(">") > -1)
   sFrom = sFrom.substring(0, sFrom.indexOf(">"));
  return sFrom;
 },
 _canonBody: function(body)
 {
  body = body.replace(/[ \t]+\r\n/g, "\r\n");
  body = body.replace(/[ \t]{2,}/g, " ");
  body = body.replace(/(\r\n)+$/g, "");
  return body + "\r\n";
 },
 _wrapText: function(body, len = 72)
 {
  var out = "";
  var sLines = body.split("\r\n");
  for (var i = 0; i < sLines.length; i++)
  {
   var sLine = sLines[i];
   if (sLine.length <= len)
   {
    out += sLine + "\r\n";
    continue;
   }
   do
   {
    var segment = sLine.substring(0, len);
    if (sLine.substring(len, len + 1) == " ")
     segment += " ";
    var segSpace = segment.lastIndexOf(" ");
    if (segSpace == -1)
    {
     segSpace = sLine.indexOf(" ");
     segment = sLine.substring(0, segSpace) + " ";
     sLine = sLine.substring(segSpace + 1);
    }
    else
    {
     segment = segment.substring(0, segSpace) + " ";
     sLine = sLine.substring(segSpace + 1);
    }
    out += segment + "\r\n";
   }
   while (sLine.length > len);
   out += sLine + "\r\n";
  }
  return out;
 },
 sending: function(evt)
 {
  var msg_type = personalDKIM._msgcomposeWindow.getAttribute( "msgtype" );  
  if( !(msg_type == nsIMsgCompDeliverMode.Now || msg_type == nsIMsgCompDeliverMode.Later) )  
   return true;

  var domain = "example.net";
  if (personalDKIM._Prefs.prefHasUserValue("domain"))
   domain   = personalDKIM._Prefs.getCharPref("domain");
  if (domain == "example.net")
  {
   console.log("PDKIM: No Domain set");
   return true;
  }

  var privKey = "";
  if (personalDKIM._Prefs.prefHasUserValue("key"))
   privKey = decodeURIComponent(personalDKIM._Prefs.getCharPref("key"));
  if (privKey == "")
  {
   console.log("PDKIM: No Private Key selected");
   return true;
  }

  var selector = "key";
  if (personalDKIM._Prefs.prefHasUserValue("selector"))
   selector = personalDKIM._Prefs.getCharPref("selector");

  var keyPass = "";
  var logins = personalDKIM._Passes.findLogins({}, "chrome://PersonalDKIM", null, "Private Key");
  for (var i = 0; i < logins.length; i++)
  {
		 if (logins[i].username == "DKIM")
   {
			 keyPass = logins[i].password;
			 break;
		 }
	 }

  var signKey = personalDKIM._loadKey(privKey, keyPass);
  if (signKey == false)
  {
   console.log("PDKIM: Failed to load Private Key");
   return true;
  }

  var algoHash = "SHA256";
  if (personalDKIM._Prefs.prefHasUserValue("algohash"))
   algoHash = personalDKIM._Prefs.getCharPref("algohash");

  var algoSign = "RSA";
  switch (signKey.type)
  {
   case "RSA":
    algoSign = "RSA";
    break;
   case "DSA":
    algoSign = "DSA";
    break;
   case "EC":
    algoSign = "ECDSA";
    break;
  }

  var timeNow = Math.round((new Date()).getTime() / 1000);
  var headerLst = "from:to";
  var headerStr = "from:" + gMsgCompose.compFields.from + "\r\n" +
                  "to:" + gMsgCompose.compFields.to + "\r\n";
  if (gMsgCompose.compFields.subject != "")
  {
   headerLst += ":subject";
   headerStr += "subject:" + gMsgCompose.compFields.subject + "\r\n";
  }
  if (gMsgCompose.compFields.organization != "")
  {
   headerLst += ":organization";
   headerStr += "organization:" + gMsgCompose.compFields.organization + "\r\n";
  }
  if (gMsgCompose.compFields.replyTo != "")
  {
   headerLst += ":reply-to";
   headerStr += "reply-to:" + gMsgCompose.compFields.replyTo + "\r\n";
  }
  if (gMsgCompose.compFields.cc != "")
  {
   headerLst += ":cc";
   headerStr += "cc:" + gMsgCompose.compFields.cc + "\r\n";
  }
  if (gMsgCompose.compFields.messageId != "")
  {
   headerLst += ":message-id";
   headerStr += "message-id:" + gMsgCompose.compFields.messageId + "\r\n";
  }
  var body = null;
  var bodyHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
  var bodyLen = "l=0; ";
  var msgType = "Unknown";
  if ('deliveryFormat' in gMsgCompose.compFields)
  {
   if (gMsgCompose.compFields.deliveryFormat === 1)
    msgType = "Plain";
   else if (gMsgCompose.compFields.deliveryFormat === 2)
    msgType = "HTML";
   else if (gMsgCompose.compFields.deliveryFormat === 3)
    msgType = "Plain+HTML";
   else if (gMsgCompose.compFields.deliveryFormat === 4)
   {
    if (gMsgCompose.compFields.forcePlainText == true)
     msgType = "Plain";
    else
     msgType = "HTML";
   }
  }
  if (msgType == "Plain")
  {
   if (gMsgCompose.compFields.attachments.hasMoreElements())
   {
    /*
    body = gMsgCompose.editor.outputToString('text/plain', 1600);
    body = personalDKIM._canonBody(body);
    
    while (gMsgCompose.compFields.attachments.hasMoreElements())
    {
     console.log (gMsgCompose.compFields.attachments.getNext());
    }

    bodyLen = "";
    bodyHash = btoa(personalDKIM._hex2bin(KJUR.crypto.Util.hashString(body, algoHash)));
    */
   }
   else
   {
    /*
    body = gMsgCompose.editor.outputToString('text/plain', (0x20000 | 0x400 | 0x200 | 0x40 | 0x02));
    body = personalDKIM._wrapText(body, gMsgCompose.wrapLength);
    body = personalDKIM._canonBody(body);
    bodyLen = "";
    bodyHash = btoa(personalDKIM._hex2bin(KJUR.crypto.Util.hashString(body, algoHash)));
    */
   }
  }
  /*
  else if (msgType == "HTML")
  {
   body = gMsgCompose.editor.outputToString('text/html', 1794);
   body = personalDKIM._canonBody(body);
   bodyLen = "";
   bodyHash = btoa(personalDKIM._hex2bin(KJUR.crypto.Util.hashString(body, algoHash)));
  }
  */
  var dkimSig = "v=1; " +
   "a=" + algoSign.toLowerCase() + "-" + algoHash.toLowerCase() + "; " +
   "d=" + domain + "; " +
   "i=" + personalDKIM._cleanFrom(gMsgCompose.compFields.from) + "; " +
   "s=" + selector + "; " +
   "c=relaxed/relaxed; " +
   "q=dns/txt; " +
   bodyLen +
   "t=" + timeNow + "; " +
   "x=" + (timeNow + 2592000) + "; " +
   "h=" + headerLst + "; " +
   "bh=" + bodyHash + "; " +
   "b=;";
  headerStr += "dkim-signature:" + dkimSig;
  var sig = new KJUR.crypto.Signature({"alg": algoHash + "with" + algoSign});
  sig.init(signKey);
  var sOut = sig.signString(headerStr);
  var signed = personalDKIM._hex2bin(sOut);
  var finalSig = dkimSig.replace("b=;", "b=" + btoa(signed) + ";");
  gMsgCompose.compFields.setHeader('DKIM-Signature', finalSig);
 }
};
addEventListener('load', function (e) {if (e.target == document) personalDKIM.init(); }, true);
addEventListener('unload', function (e) { if (e.target == document) personalDKIM.terminate();}, true);
