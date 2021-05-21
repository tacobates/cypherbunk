/****************************************************************************
* Author: Rob Bates
* Date: March 2021
* License: Do whatever you want, but please link to my site to give credit.
* Site: www.cypherbunk.com
****************************************************************************/

//if predefinedEncHash & predefinedDecHash exist, we use those precomputed keys


/***** 2 MDN Functions: %encoded-UTF8->raw-bytes->base64->no-padding vs bytestream->%encoded-UTF8->orig => https://stackoverflow.com/questions/30106476/using-javascripts-atob-to-decode-base64-doesnt-properly-decode-utf-8-strings *****/
function b64EncodeUnicode(txt) { var txt = btoa(encodeURIComponent(txt).replace(/%([0-9A-F]{2})/g, function toSolidBytes(match, p1) { return String.fromCharCode('0x' + p1); })); while("=" == txt.charAt(txt.length-1)) txt = txt.substring(0, txt.length - 1); return txt; }
function b64DecodeUnicode(txt) { return decodeURIComponent(atob(txt).split('').map(function(c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join('')); }


var cypherBunk = {
  /***************************** CONSTANTS *****************************/
  VERSION: 2076, //Check to ensure both parties are encrypting/decrypting with same version
  ACTION_DECRYPT: "decrypt",
  ACTION_ENCRYPT: "encrypt",
  B64_ALPHABET: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  CYPHER_CHUNK: 7, //7 digits in cypherMax, so 0000000 - 9999999
  CYPHER_MAX: 9999999,
//TODO: allow 1 Million above??? (if so, increase CYPHER_MAX & CYPHER_CHUNK)
  DEBUG: false,
  DEBUG_LEVEL: 2, //1 for basic, 2 for detail
  KEY_LEN_MAX: 100000, //We trim the key to this length for performance
  TAG_MESSAGE: "CypherBunk Encrypted Message. Go to www.cypherbunk.com to decrypt this message.",

  /***************************** VARIABLES *****************************/
  action: null,
  async: false, //true only if we are fetching key via a URL
  b64CharCount: {},
  dom: new Object(), //cache DOM elements here for quick manipulation
  fail: false, //Simple flag for error handling of Encrypt/Decrypt
  hashDec: new Map(), //Maps Cypher Text Character to B64 Decrypted Char
  hashEnc: new Map(), //Maps B64 Character to array of possible Cypher Characters
  key64: null, //Base 64 representation of this.keyText (or payload of keyUrl)
  keyText: null,
  keyUrl: null,
  precomputed: false, //If true, we don't need keys (use precomputed ones)
  message: null,
  tallyEnc: {}, //Counts how often a root cypher char (without modulus added) was used
  tallyTotal: 0, //Total number of cypher chars used (to calculate avg use deviation)
  undoText: "", //What was in this.dom.message before we replaced it

  /***************************** FUNCTIONS *****************************/
  cacheDom: function(){
    this.dom.keyUrl = document.getElementById("keyUrl");
    this.dom.keyText = document.getElementById("keyText");
    this.dom.message = document.getElementById("message");
    this.dom.predefinedJS = document.getElementById("predefinedJS");
    this.dom.warning = document.getElementById("warning");

    this.dom.d1 = document.getElementById('detail1');
    this.dom.d2 = document.getElementById('detail2');
    this.dom.d3 = document.getElementById('detail3');
    this.dom.d4 = document.getElementById('detail4');
    this.dom.s = document.getElementById('score_total');
    this.dom.s1 = document.getElementById('score1');
    this.dom.s2 = document.getElementById('score2');
    this.dom.s3 = document.getElementById('score3');
    this.dom.s4 = document.getElementById('score4');

    document.getElementById("version").innerHTML = "version " + this.VERSION;
    //Make Close Icons for Popup Cards
    var cards = document.querySelectorAll(".card");
    for(var i=0; i < cards.length; ++i) {
      var closer = document.createElement("div");
      closer.className = "cardClose";
      closer.innerHTML = "&times;";
      closer.onclick = function(){ cypherBunk.cardCloseAll(); };
      cards[i].prepend(closer);
    }

    //Look for Pre-Computed Hashes
    if (typeof predefinedDecHash !== 'undefined' && predefinedEncHash !== 'undefined') {
      this.hashDec = predefinedDecHash;
      this.hashEnc = predefinedEncHash;
      this.precomputed = true;
      //Make it obvious to user that we are pre-computing
      this.showWarning("Found Predefined Cypher Keys. Cypher Key Input Fields Hidden.");
      document.getElementById("keyWrap").style.display = "none";
    }

    //Default Message to one of our ASCII Logo
    if (typeof ASCII_LOGOS !== 'undefined')
      this.dom.message.value = b64DecodeUnicode(ASCII_LOGOS[Math.floor(Math.random() * ASCII_LOGOS.length)]);

this.DEBUG = true; //TODO: delete this line
    if (this.DEBUG) {
      this.debug("Setting Key Values, since Debug Enabled", 2);
      this.dom.keyText.value = "The Quick Red Fox Jumped Over the Lazy Brown Dog. <>,.?:;|{}[]~!@#$%^&*()_+=-0987654321`Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.".repeat(3);
      this.dom.keyUrl.value = "https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"
    }
  },

  /***** Calculates a Score for the latest Encryption *****/
  calculateScore: function(){
    this.cardShow('scoreCard');
    var scoreRunningTotal = 0;
    var scoreNumCategories = 4; //4 types of tests
    var loadMsg = "Calculating...";
    this.dom.s.innerHTML = "Calculating Overall Score...";
    this.dom.s1.innerHTML = this.dom.s2.innerHTML = this.dom.s3.innerHTML = loadMsg;
    this.dom.d1.innerHTML = this.dom.d2.innerHTML = this.dom.d3.innerHTML = "";

    //CALC Key Length
    var effectiveLen = this.key64.length > this.KEY_LEN_MAX ? this.KEY_LEN_MAX : this.key64.length;
    var scoreLen = effectiveLen / this.KEY_LEN_MAX;
    this.dom.s1.innerHTML = this.formatScore(scoreLen);
    var userLen = this.formatThousands(effectiveLen);
    var maxLen = this.formatThousands(this.KEY_LEN_MAX);
    this.dom.d1.innerHTML = "Effective length: " + userLen;
    scoreRunningTotal += scoreLen;
    this.debug("Score Running Total: " + scoreRunningTotal, 1);

    //CALC Key Diversity
    var desiredNum = 1000;
    var avgKeyVariants = totalKeyVariants = 0;
    for (var i=0; i < this.B64_ALPHABET.length; ++i) {
      var c = this.B64_ALPHABET.charAt(i);
      var tempVariants = this.hashEnc.get(c).length;
      if (tempVariants > desiredNum)
        tempVariants = desiredNum; //No Extra Credit (will throw off average)
      totalKeyVariants += tempVariants;
    }
    avgKeyVariants = (totalKeyVariants / this.B64_ALPHABET.length);
    variantScore = avgKeyVariants / desiredNum;
    this.dom.s2.innerHTML = this.formatScore(variantScore);
    this.dom.d2.innerHTML = "Average variants: " + Math.round(avgKeyVariants);
    scoreRunningTotal += variantScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 1);

    //CALC Message Homogeneity Simple
    var highPercent = highDigit = 0; //Set low to be overwritten
    var lowPercent = lowDigit = 100; //Set high to be overwritten
    var digitCounts = []; //Count how many times 0 was used, then 1, then 2, etc...
    var totalCount = 0;
    for (var i=0; i < 10; ++i) {
      var tempCount = this.message.split(i.toString()).length - 1;
      digitCounts[i] = tempCount;
      totalCount += tempCount;
    }
    this.debug(digitCounts, 1, "Digit Homogeneity Counts");
    var avgCount = totalCount / 10;
    var deviationTotal = 0;
    for (var i=0; i < 10; ++i) {
      var tempDeviation = digitCounts[i] / avgCount;
      this.debug("DeviationSimple: " + digitCounts[i] + " / " + avgCount + " = " + tempDeviation, 2);
      if (tempDeviation > highPercent) {
        highPercent = tempDeviation;
        highDigit = i;
      }
      if (tempDeviation < lowPercent) {
        lowPercent = tempDeviation;
        lowDigit = i;
      }
      //Get % Diff from expected, not % OF expected, so 120%=>20% and 10%=>90%
      tempDeviation = Math.abs(tempDeviation - 1);
      deviationTotal += tempDeviation;
    }
    var avgDeviation = deviationTotal / 10;
    var deviationScore = 1 - avgDeviation;
    this.debug("Avg Deviation Simple: 1 - (" + deviationTotal + " / 10) = " + deviationScore, 2);
    var percentRange = Math.abs(highPercent - 1) + Math.abs(lowPercent - 1);
    this.dom.s3.innerHTML = this.formatScore(deviationScore);
    this.dom.d3.innerHTML = "Heterogeny range: " + this.formatScore(percentRange, 2, false);
    scoreRunningTotal += deviationScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 1);


    //CALC Message Homogeneity Complex
    var highKey = lowKey = "";
    var numTallyKeys = Object.keys(this.tallyEnc).length;
    var avgUsage = this.tallyTotal / numTallyKeys;
    this.debug(this.tallyTotal + " / " + numTallyKeys + " = " + avgUsage, 2, "Complex Homogeneity");
    deviationTotal = 0;
    highPercent = 0; //Set low to be overwritten
    lowPercent = 100; //Set high to be overwritten
    for (var tallyKey in this.tallyEnc) {
      var tempUsage = this.tallyEnc[tallyKey];
      var tempDeviation = tempUsage / avgUsage;
      this.debug("DeviationComplex: " + tempUsage + " / " + avgUsage + " = " + tempDeviation, 2);
      if (tempDeviation > highPercent) {
        highPercent = tempDeviation;
        highKey = tallyKey;
      }
      if (tempDeviation < lowPercent) {
        lowPercent = tempDeviation;
        lowKey = tallyKey;
      }
      //Get % Diff from expected, not % OF expected, so 120%=>20% and 10%=>90%
      tempDeviation = Math.abs(tempDeviation - 1);
      deviationTotal += tempDeviation;
    }
    avgDeviation = deviationTotal / numTallyKeys;
    deviationScore = 1 - avgDeviation;
    this.debug("Avg Deviation Complex: 1 - (" + deviationTotal + " / 10) = " + deviationScore, 2);
    percentRange = Math.abs(highPercent - 1) + Math.abs(lowPercent - 1);
    this.dom.s4.innerHTML = this.formatScore(deviationScore);
    this.dom.d4.innerHTML = "Heterogeny range: " + this.formatScore(percentRange, 2, false);
    scoreRunningTotal += deviationScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 1);

    //Overall Score
    var overallScore = scoreRunningTotal / scoreNumCategories;
    this.dom.s.innerHTML = "Overall Score: " + this.formatScore(overallScore);
  },

  /***** Decrypt the cypherText (hashDec must be computed beforehand) *****/
  decrypt: function(cypherText){
    var b64 = "";
    if (this.hashDec.size == 0) {
      alert("ERROR: Cannot Decrypt. Cypher Key was not set.");
      return;
    }
    if (cypherText.match(/[^0-9]/g)) {
      //this.showWarning("Cyphertext should only contain numbers.<br/>Removed non-digits, and attempting to decrypt anyway.");
      //Don't show warning, as we now allow obfuscation with letter interlacing
      cypherText = cypherText.replace(/[^0-9]/g, "");
//TODO: make a checkbox to add letter interlacing (50% chance to append an a-zA-Z after each number that is appended)
    }
    var mod = cypherText.length % this.CYPHER_CHUNK;
    if (mod != 0) {
      this.showWarning("Cyphertext is an incorrect length.<br/>Removing the final corrupt character, and attempting to decrypt anyway.");
      cypherText = cypherText.substring(0, cypherText.length - mod);
    }

    var numChunks = cypherText.length / this.CYPHER_CHUNK;
    for(var i=0; i < numChunks; i++) {
      var n = cypherText.substr(i * this.CYPHER_CHUNK, this.CYPHER_CHUNK);
      n = parseInt(n) % this.hashDec.size; //Decode Mod Equivalend Indices
      b64 = b64.concat(this.hashDec.get(n));
    }
    return b64DecodeUnicode(b64);
  },
  /***** Decrypt the text in #message *****/
  decryptMessage: function(){
    this.action = this.ACTION_DECRYPT;
    this.fetchInput();
    this.keyFetch();
    if (this.async)
      return; //AJAX fetching this.keyUrl (let it encrypt on its own)
    this.decryptMessageFinalize();
  },
  /***** Finishes the Decrypt Process and Displays *****/
  decryptMessageFinalize: function(){
    if (this.fail)
      return; //Error was already alerted in fetchKey()
    this.message = this.message.trim(); //Ensure no accidentally copied whitespace
    this.message = this.decrypt(this.message);
    this.dom.message.value = this.message;
  },

  /***** Encrypt the clearText (hashEnc must be computed beforehand) *****/
  encrypt: function(clearText){
    var rtn = "";
    var b64Text = b64EncodeUnicode(clearText);
    if (this.hashEnc.size == 0) {
      alert("ERROR: Cannot Encrypt. Cypher Key was not set.");
      return;
    }
    for(var i=0; i < b64Text.length; ++i) {
      var c = b64Text.charAt(i);
      var cypherOpts = this.hashEnc.get(c);
      var cypherChar = cypherOpts[Math.floor(Math.random() * cypherOpts.length)];
      var tallyKey = c + "_" + cypherChar; //Make key WITHOUT formatted Mod Equivalents
      cypherChar = this.formatCypherChar(cypherChar);
      //Count used keys here to make Score Calculation MUCH easier
      if (!(tallyKey in this.tallyEnc))
        this.tallyEnc[tallyKey] = 0;
      this.tallyEnc[tallyKey]++;
      this.tallyTotal++;
      rtn = rtn.concat(cypherChar);
    }
    return rtn;
  },
  /***** Encrypt the text in #message *****/
  encryptMessage: function(){
//TODO: show progress bar (also hides buttons, preventing double click)
    this.action = this.ACTION_ENCRYPT;
    this.fetchInput();
    this.keyFetch();
    if (this.async)
      return; //AJAX fetching this.keyUrl (let it encrypt on its own)
    this.encryptMessageFinalize();
  },
  /***** Finishes the Encrypt Process and Displays *****/
  encryptMessageFinalize: function(){
    if (this.fail)
      return; //Error was already alerted in fetchKey()
    this.message = this.encrypt(this.message);
    this.dom.message.value = this.TAG_MESSAGE + "\n" + this.message;
  },

  /***** Get Input, in case user changed any values *****/
  fetchInput: function(){ //Ensure we have the latest Input/KeyConfig
    this.clearWarning();
    this.async = false;
    this.fail = false;
    this.keyText = this.dom.keyText.value;
    this.keyUrl = this.dom.keyUrl.value;
    this.message = this.dom.message.value;
    this.undoText = this.message;
    this.b64CharCount = {};
    for (var i=0; i < this.B64_ALPHABET.length; ++i)
      this.b64CharCount[this.B64_ALPHABET.charAt(i)] = 0;
  },

  /***** Turns the Index into a Modulus Equivalent with Zero Padding *****/
  formatCypherChar: function(n){ //n must be a positive integer
    var keyLen = this.hashDec.size;
    var maxMultiple = Math.floor(this.CYPHER_MAX / keyLen);
    var randMultiple = Math.floor(Math.random() * maxMultiple);
    n = keyLen * randMultiple + n; //Modulus equivalent index
    //Zero Padding
    n = "0000000000" + n.toString();
    return n.substr(n.length - this.CYPHER_CHUNK);
  },

  /***** Formats a score from a 0-based percent to a 100-based percent *****/
  formatScore: function(n, precision = 2, cap100 = true){
    n *= 100;
    n = n.toFixed(precision);
    if (n > 100 && cap100)
      n = 100;
    else if (n < 0)
      n = 0; //Should only happen with bad function param
    return n + "%";
  },

  /***** Gives numbers comma separators for thousands, millions, etc...*****/
  formatThousands: function (n) {
    if (Math.abs(n) <= 999)
      return n;
    n = n.toString();
    return n.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  },

  /***** Get & Validate the Cypher Key *****/
  keyFetch: function(){ //Gets the key and makes the hashes for it
    if (this.precomputed) //Static Pre-Defined Keys Specified.
      return; //No need to compute a dynamic key
     if (this.keyText.length > 0) { //Full Text takes precedent
      //Do nothing, this is the key we want
    } else if (this.keyUrl.length > 0) {
      this.async = true;
      this.keyFetchAsync();
      return;
    } else {
      alert("ERROR: You must specify either a Key URL or Full Key Text.");
      this.fail = true;
      return;
    }
    this.keyHash();
  },

  /***** Fetch Key accounting for fetch() asynchronicity *****/
  keyFetchAsync: async function() {
    let response = await fetch(this.keyUrl);
    if (response.status !== 200) {
      this.fail = true;
      alert("ERROR: Failed to fetch key from URL:\n" + this.keyUrl + "\n\n" +
        + "Please verify the URL & that the site allows Cross-Site Requests."
        + "\n\n(Status Received: " + response.status + " " + response.statusText + ")");
      return;
    }
    let txt = await response.text();

    //Proceed with this key like a normal key
    this.keyText = txt;
    this.keyHash();
    if (this.ACTION_DECRYPT == this.action) {
      this.decryptMessageFinalize();
    } else if (this.ACTION_ENCRYPT == this.action) {
      this.encryptMessageFinalize();
    } else {
      this.fail = true;
      alert("ERROR: Unknown Action Requested.");
    }
  },

  /***** Fetch or Compute hashDec & hashEnc *****/
  keyHash: function(){ //Generates hashEnc and hashDec
    if (this.precomputed)
      return; //Skip if Hashes are Pre-Computed
    this.hashDec.clear();
    this.hashEnc.clear();
    this.tallyEnc = {};
    this.tallyTotal = 0;

    //Ensure Key isn't too big
    if (this.keyText.length > this.KEY_LEN_MAX)
      this.keyText = this.keyText.substring(0, this.KEY_LEN_MAX);
    this.key64 = b64EncodeUnicode(this.keyText);

    //Ensure Key has ALL required characters for Base64 (minus padding)
    var numAdded = 0;
    var missingChars = "";
    for (var i=0; i < this.B64_ALPHABET.length; ++i) {
      var c = this.B64_ALPHABET.charAt(i);
      if (-1 == this.key64.indexOf(c)) { //If it doesn't have that B64 char
        missingChars = missingChars.concat(c);
        numAdded++;
      }
    }
    if (numAdded > 0) {
      //Add to front and back so each Char in the Alphabet has at least 2 cypher indices
      this.key64 = missingChars + this.key64 + missingChars;
      var s = (numAdded > 1 ? "s" : "");
      this.showWarning("Your key wasn't complicated enough, so we had to add " + numAdded + " character" + s + " to your key.<br/>"
        + "It will work fine, but each added character reduces the security of your encryption.<br/>"
        + "Consider using a longer and more complicated Cypher Key.");
    }

    //Compute Hashes
    var js = "var predefinedDecHash = new Map();\nvar predefinedEncHash = new Map();\n";
    for (var i=0; i < this.key64.length; ++i) {
      var c = this.key64.charAt(i);
      this.b64CharCount[c]++;
      this.hashDec.set(i,c);
      js += "\npredefinedDecHash.set(" + i + ", \"" + c + "\");";
      var tempArray = [];
      if (this.hashEnc.has(c))
        tempArray = this.hashEnc.get(c);
      tempArray.push(i);
      this.hashEnc.set(c, tempArray);
    }

    //Generate Static JS Keys for Display in UI
    js += "\n";
    for (var i=0; i < this.B64_ALPHABET.length; ++i) {
      var c = this.B64_ALPHABET.charAt(i);
      var tempArray = this.hashEnc.get(c);
      tempArray = JSON.stringify(tempArray);
      js += "\npredefinedEncHash.set(\"" + c + "\", " + tempArray + ");";
    }
    this.dom.predefinedJS.value = js;
  },

  /***** DEPRECATED: use b64EncodeUnicode() instead...  Wrapper for btoa(), because "=" padding gives away key length *****/
  btoa_no_padding: function(txt) {
    txt = btoa(txt);
    //Now remove padding (otherwise length of key can be known)
    while("=" == txt.charAt(txt.length-1))
      txt = txt.substring(0, txt.length - 1);
    return txt;
  },
  //No need for atob() wrapper, as it can handle unpadded strings

  /***** Displays a warning in the DOM *****/
  showWarning: function(txt) {
    this.dom.warning.innerHTML = txt + "<br/><br/>";
  },
  clearWarning: function() {
    this.dom.warning.innerHTML = "";
  },

  /***** Turns Dark UI on/off *****/
  toggleDarkUI: function() {
    var html = document.body.parentNode;
    if (html.className == "dark")
      html.className = "";
    else
      html.className = "dark";
  },

  /***** Hide All Cards *****/
  cardCloseAll: function() {
    var cards = document.querySelectorAll(".card");
    for(var i=0; i < cards.length; ++i) {
      if (!cards[i].className.match(/invisible/g))
        cards[i].className += " invisible";
    }
  },

  /***** Shows the specified Card *****/
  cardShow: function(id) {
    var card = document.getElementById(id);
    if (card.className.match(/invisible/g))
      card.className = card.className.replace(/invisible/g, "");
  },

  /***** Undoes the very last Encrypt/Decrypt *****/
  undo: function() {
    var newUndoText = this.dom.message.value;
    this.dom.message.value = this.undoText;
    this.undoText = newUndoText;
  },

  /***** Logs Messages to Console ONLY IF Debug is enabled *****/
  debug: function(msg, debugLevel = 1, title = "") {
    if (this.DEBUG && debugLevel <= this.DEBUG_LEVEL) {
      if (title.length > 0)
        console.log("========== " + title + " ==========");
      console.log(msg);
    }
  },

  zEndVariableWithNoComma: null //TODO: deleteme (and the final preceding comma)
}
