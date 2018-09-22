var personalDKIMOptions =
{
 _Prefs:   Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefService).getBranch("extensions.pdkim."),
 _Passes:  Components.classes["@mozilla.org/login-manager;1"].getService(Components.interfaces.nsILoginManager),
 initOptions: function()
 {
  var domain = "example.net";
  if (personalDKIMOptions._Prefs.prefHasUserValue("domain"))
   domain = personalDKIMOptions._Prefs.getCharPref("domain");
  var selector = "key";
  if (personalDKIMOptions._Prefs.prefHasUserValue("selector"))
   selector = personalDKIMOptions._Prefs.getCharPref("selector");
  var key = "";
  if (personalDKIMOptions._Prefs.prefHasUserValue("key"))
   key = decodeURIComponent(personalDKIMOptions._Prefs.getCharPref("key"));
  var keyPass = "";
  var logins = personalDKIMOptions._Passes.findLogins({}, "chrome://PersonalDKIM", null, "Private Key");
  for (var i = 0; i < logins.length; i++)
  {
		 if (logins[i].username == "DKIM")
   {
			 keyPass = logins[i].password;
			 break;
		 }
	 }
  var algoHash = "SHA256";
  if (personalDKIMOptions._Prefs.prefHasUserValue("algohash"))
   algoHash = personalDKIMOptions._Prefs.getCharPref("algohash");
  document.getElementById("domainInput").value = domain;
  document.getElementById("selectorInput").value = selector;
  document.getElementById("keyInput").value = key;
  document.getElementById("keyPass").value = keyPass;
  var cmbHash = document.getElementById("algoHash");
  switch (algoHash)
  {
   case 'MD5':
    cmbHash.selectedIndex = 0;
    break;
   case 'SHA1':
    cmbHash.selectedIndex = 1;
    break;
   case 'SHA224':
    cmbHash.selectedIndex = 2;
    break;
   case 'SHA384':
    cmbHash.selectedIndex = 4;
    break;
   case 'SHA512':
    cmbHash.selectedIndex = 5;
    break;
   case 'RIPEMED160':
    cmbHash.selectedIndex = 6;
    break;
   default:
    cmbHash.selectedIndex = 3;
    break;
  }
  personalDKIMOptions.changeDomain();
  personalDKIMOptions.changeKey();
 },
 saveOptions: function()
 {
  var domain   = document.getElementById("domainInput").value;
  var selector = document.getElementById("selectorInput").value;
  var keyData  = document.getElementById("keyInput").value;
  var keyPass  = document.getElementById("keyPass").value;

  var keyCheck = personalDKIMOptions._testKey(keyData, keyPass)
  if (keyCheck != true)
  {
   alert("There was an error validating your Private Key:\n\n" + keyCheck);
   return false;
  }

  var algoSign = personalDKIMOptions._getKeyAlgo(keyData, keyPass);
  if (algoSign == false)
  {
   alert("Unknown Private Key Algorithm. Please make sure your Private Key is RSA, DSA, or ECDSA.");
   return false;
  }

  var algoHash = "SHA256";
  switch (document.getElementById("algoHash").selectedIndex)
  {
   case 0:
    if (algoSign == "DSA")
    {
     alert("DSA is not compatible with MD5.");
     return false;
    }
    algoHash = "MD5";
    break;
   case 1:
    algoHash = "SHA1";
    break;
   case 2:
    algoHash = "SHA224";
    break;
   case 4:
    if (algoSign == "DSA")
    {
     alert("DSA is not compatible with SHA-384.");
     return false;
    }
    algoHash = "SHA384";
    break;
   case 5:
    if (algoSign == "DSA")
    {
     alert("DSA is not compatible with SHA-512.");
     return false;
    }
    algoHash = "SHA512";
    break;
   case 6:
    if (algoSign == "DSA")
    {
     alert("DSA is not compatible with RIPEMED-160.");
     return false;
    }
    algoHash = "RIPEMED160";
    break;
  }

  personalDKIMOptions._Prefs.setCharPref("domain", domain);
  personalDKIMOptions._Prefs.setCharPref("selector", selector);
  personalDKIMOptions._Prefs.setCharPref("key", encodeURIComponent(keyData));
  personalDKIMOptions._Prefs.setCharPref("algohash", algoHash);
  var logins = personalDKIMOptions._Passes.findLogins({}, "chrome://PersonalDKIM", null, "Private Key");
  for (var i = 0; i < logins.length; i++)
  {
		 if (logins[i].username == "DKIM")
   {
    personalDKIMOptions._Passes.removeLogin(logins[i]);
			 break;
		 }
	 }
  if (keyPass != "")
  {
   var nsLoginInfo = new Components.Constructor("@mozilla.org/login-manager/loginInfo;1", Components.interfaces.nsILoginInfo, "init");
   var eLogin = new nsLoginInfo("chrome://PersonalDKIM", null, "Private Key", "DKIM", keyPass, "", "");
   personalDKIMOptions._Passes.addLogin(eLogin);
  }
 },
 _loadKey: function(keyFile)
 {
  Components.utils.import("resource://gre/modules/FileUtils.jsm");
  var oFile = new FileUtils.File(keyFile);
  var fileStream = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance(Components.interfaces.nsIFileInputStream);
  fileStream.init(oFile, 0x01, 0444, 0);
  var stream = Components.classes["@mozilla.org/intl/converter-input-stream;1"].createInstance(Components.interfaces.nsIConverterInputStream);
  stream.init(fileStream, "iso-8859-1", 16384, Components.interfaces.nsIConverterInputStream.DEFAULT_REPLACEMENT_CHARACTER);
  stream = stream.QueryInterface(Components.interfaces.nsIUnicharLineInputStream);
  var ret = '';
  var line = {value: null};
  while (stream.readLine(line))
  {
   ret += line.value + "\n";
  }
  ret += line.value;
  stream.close();
  return ret;
 },
 _parseKey: function(keyData, keyPass)
 {
  if (keyData.indexOf("BEGIN RSA PRIVATE KEY") != -1 || keyData.indexOf("BEGIN DSA PRIVATE KEY") != -1 || keyData.indexOf("BEGIN EC PRIVATE KEY") != -1)
  {
   if (keyData.indexOf("Proc-Type: 4,ENCRYPTED") != -1)
    return "5P";
   else
    return "1";
  }
  else if (keyData.indexOf("BEGIN PRIVATE KEY") != -1)
   return "8";
  else if (keyData.indexOf("BEGIN ENCRYPTED PRIVATE KEY") != -1)
   return "8P";
  return "?";
 },
 _testKey: function(keyData, pass)
 {
  if (keyData.indexOf("BEGIN RSA PRIVATE KEY") != -1 || keyData.indexOf("BEGIN DSA PRIVATE KEY") != -1 || keyData.indexOf("BEGIN EC PRIVATE KEY") != -1)
  {
   if (keyData.indexOf("Proc-Type: 4,ENCRYPTED") != -1)
   {
    try
    {
     if (pass == "")
      return "Please enter the password for this PKCS#5 Key.";
     var ret = KEYUTIL.getKey(keyData, pass);
     if (ret.isPrivate != true)
      return "This PKCS#5 Key is not a Private Key.";
     if (ret.e < 3 || ret.e > 131071)
      return "This PKCS#5 Key has a strange 'e' value. Please check the password you entered. If you're sure it's correct, please contact me.";
     if (!(ret.type == "RSA" || ret.type == "DSA" || ret.type == "EC"))
      return "This PKCS#5 Key is not an RSA, DSA, or ECDSA Private Key.";
     return true;
    }
    catch (e)
    {
     return "Unable to decode PKCS#5 Key: " + e;
    }
   }
   else
   {
    try
    {
     var ret = KEYUTIL.getKey(keyData);
     if (ret.isPrivate != true)
      return "This PKCS#1 Key is not a Private Key.";
     if (ret.e < 3 || ret.e > 131071)
      return "This PKCS#1 Key has a strange 'e' value. Please contact me.";
     if (!(ret.type == "RSA" || ret.type == "DSA" || ret.type == "EC"))
      return "This PKCS#1 Key is not an RSA, DSA, or ECDSA Private Key.";
     return true;
    }
    catch (e)
    {
     return "Unable to decode PKCS#1 Key: " + e;
    }
   }
  }
  else if (keyData.indexOf("BEGIN PRIVATE KEY") != -1)
  {
   try
   {
    var ret = KEYUTIL.getKey(keyData);
    if (ret.isPrivate != true)
     return "This PKCS#8 Key is not a Private Key.";
    if (ret.e < 3 || ret.e > 131071)
     return "This PKCS#8 Key has a strange 'e' value. Please contact me.";
    if (!(ret.type == "RSA" || ret.type == "DSA" || ret.type == "EC"))
     return "This PKCS#8 Key is not an RSA, DSA, or ECDSA Private Key.";
    return true;
   }
   catch (e)
   {
    return "Unable to decode PKCS#8 Key: " + e;
   }
  }
  else if (keyData.indexOf("BEGIN ENCRYPTED PRIVATE KEY") != -1)
  {
   try
   {
    if (pass == "")
     return "Please enter the password for this PKCS#8 Key.";
    var ret = KEYUTIL.getKey(keyData, pass);
    if (ret.isPrivate != true)
     return "This PKCS#8 Key is not a Private Key.";
    if (ret.e < 3 || ret.e > 131071)
     return "This PKCS#8 Key has a strange 'e' value. Please check the password you entered. If you're sure it's correct, please contact me.";
    if (!(ret.type == "RSA" || ret.type == "DSA" || ret.type == "EC"))
     return "This PKCS#8 Key is not an RSA, DSA, or ECDSA Private Key.";
    return true;
   }
   catch (e)
   {
    return "Unable to decode PKCS#8 Key: " + e;
   }
  }
  else
  {
   try
   {
    var ret = KEYUTIL.getKey(keyData);
    if (ret.isPrivate != true)
     return "This Key is not a Private Key.";
    if (ret.e < 3 || ret.e > 131071)
     return "This Key has a strange 'e' value. Please check the password you entered. If you're sure it's correct, please contact me.";
    if (!(ret.type == "RSA" || ret.type == "DSA" || ret.type == "EC"))
     return "This Key is not an RSA, DSA, or ECDSA Private Key.";
    return true;
   }
   catch (e)
   {
    return "Unable to decode Key: " + e;
   }
  }
  return "Unknown type of Private Key.";
 },
 _getKeyAlgo: function(keyData, keyPass)
 {
  if (keyPass == "")
  {
   try
   {
    var ret = KEYUTIL.getKey(keyData);
    switch (ret.type)
    {
     case "RSA":
      return "RSA";
      break;
     case "DSA":
      return "DSA";
      break;
     case "EC":
      return "ECDSA";
      break;
    }
   }
   catch (e) {}
  }
  else
  {
   try
   {
    var ret = KEYUTIL.getKey(keyData, keyPass);
    switch (ret.type)
    {
     case "RSA":
      return "RSA";
      break;
     case "DSA":
      return "DSA";
      break;
     case "EC":
      return "ECDSA";
      break;
    }
   }
   catch (e) {}
  }
  return false;
 },
 changeKey: function()
 {
  var keyInput = document.getElementById("keyInput");
  var keyInfo = document.getElementById("keyInfo");
  var keyPass = document.getElementById("keyPass");
  var kInfo = personalDKIMOptions._parseKey(keyInput.value, keyPass.value);
  if (kInfo === false)
  {
   keyInfo.innerHTML = "No Private Key";
   keyPass.value = "";
   keyPass.disabled = true;
   return;
  }
  if (kInfo.indexOf("P") == -1)
  {
   keyPass.value = "";
   keyPass.disabled = true;
  }
  else
   keyPass.disabled = false;
  switch (kInfo.substring(0, 1))
  {
   case "1":
    keyInfo.innerHTML = "PKCS#1 Private Key";
    break;
   case "5":
    keyInfo.innerHTML = "PKCS#5 Private Key";
    break;
   case "8":
    keyInfo.innerHTML = "PKCS#8 Private Key";
    break;
   default:
    keyInfo.innerHTML = "Unknown Private Key";
    break;
  }
 },
 changeDomain: function()
 {
  var domain   = document.getElementById("domainInput").value;
  var selector = document.getElementById("selectorInput").value;
  if (domain == "")
   domain = "[Host]";
  if (selector == "")
   selector = "[Selector]";
  document.getElementById("domainPreview").value = selector + "._domainkey." + domain;
 },
 importFile: function()
 {
  var picker = Components.classes["@mozilla.org/filepicker;1"].createInstance(Components.interfaces.nsIFilePicker);
  var fileLocator = Components.classes["@mozilla.org/file/directory_service;1"].getService(Components.interfaces.nsIProperties);
  picker.init(window, "Select Private Key File...", picker.modeOpen);
  picker.appendFilters(picker.filterAll);
  picker.displayDirectory = fileLocator.get("Desk", Components.interfaces.nsIFile);
  picker.open(
              function (rv)
              {
               if (rv == Components.interfaces.nsIFilePicker.returnOK || rv == Components.interfaces.nsIFilePicker.returnReplace)
               {
                var keyInput = document.getElementById("keyInput");
                var keyInfo = document.getElementById("keyInfo");
                var keyPass = document.getElementById("keyPass");
                var kData = personalDKIMOptions._loadKey(picker.file.path);
                keyInput.value = kData;
                personalDKIMOptions.changeKey();
               }
              }
             );
 }
};
