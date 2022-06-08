/**
 * CypherBunk allows for simple ad-hoc encryption using either a static
 * cypher, or a URL to fetch whose content should be used as the cypher.
 * We recommend linking to a versioned utility, like jQuery, so that the
 * cypher won't change, but alternately if you hosted a rotating cypher on
 * your own website, it would serve as a built in TTL for the message, as
 * the cypher will expire.
 * Either way, you will need to communicate what the cypher is to your
 * friends, so that they can decrypt the message.
 * They can either decrypt at localmess.com/cypherbunk, or you can host
 * the CypherBunk2076.js on your own site (or PC) and encrypt/decrypt
 * there. Since it just uses JS, you don't need a Web Server, just a Browser.
 * Since it is ad-hoc, you don't need to setup public/private keys with
 * your intended recipients before sending messages.  You can send it now,
 * and then communicate the cypher key to them via some other method.
 *
 * WARNING:
 *   CypherBunk is *NOT* Military grade encryption.
 *   Don't use it to encrypt sensitive info.
 *   It is merely hobbyist encryption for ad-hoc use among friends.
 *
 * DEPENDENCY:
 *   jQuery (any version with $.ajax() will work, but I tested with 3.6.0)
 *
 * Author: Rob Bates, June 2022
 * License: Do whatever you want, but please link to my site to give credit.
 * Site: www.localmess.com/cypherbunk
 */
class CypherBunk2076 {
  /***************************** CONSTANTS *****************************/
  static VERSION = 2076; //Check to ensure both parties are encrypting/decrypting with same version
  static ACTION_DECRYPT = "decrypt";
  static ACTION_ENCRYPT = "encrypt";
  static B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static CYPHER_CHUNK = 7; //7 digits in cypherMax, so 0000000 - 9999999
  static CYPHER_MAX = 9999999;
  static KEY_LEN_MAX = 100000; //We trim the key to this length for performance
//TODO: allow 1 Million above??? (if so, increase CYPHER_MAX & CYPHER_CHUNK)
  static TAG_MESSAGE = "CypherBunk Encrypted Message. Go to www.cypherbunk.com to decrypt this message.";

  /***************************** VARIABLES *****************************/
  b64CharCount = {};
  debugEnabled = false;
  debugLevel = 0; //1 for basic, 2 for detail
  hashDec = new Map(); //Maps Cypher Text Character to B64 Decrypted Char
  hashEnc = new Map(); //Maps B64 Character to array of possible Cypher Characters
  key64 = null; //Base 64 representation of this.keyText (or payload of keyUrl)
  keyText = null;
  keyUrl = null;
  precomputed = false //If true, we don't need keys (use precomputed ones)
  precomputedJS = ''; //Holds the JS of the Hashed Cypher Key
  precomputedWarning = null; //Holds a warning if the Cypher Key was too simple
  message = null;
  tallyEnc = {}; //Counts how often a root cypher char (without modulus added) was used
  tallyTotal = 0; //Total number of cypher chars used (to calculate avg use deviation)

  /***************************** FUNCTIONS *****************************/
  
  /**
   * Create an instance of CypherBunk2076 to use for encryption.
   * It will check for predefinedDecHash & predefinedEncHash. If these exist,
   * it will use them to encrypt in a more performant way with those vars.
   * Those vars can be generated using CypherBunkUI.js & index.html.
   * @param debugLevel: 0 to turn off debug messages, 1 for basic, 2 for detailed
   */
  constructor(debugLevel=0){
    this.debugEnabled = (debugLevel > 0);
    this.debugLevel = debugLevel;
    // Look for Pre-Computed Hashes
    if (typeof predefinedDecHash !== 'undefined' && predefinedEncHash !== 'undefined') {
      this.hashDec = predefinedDecHash;
      this.hashEnc = predefinedEncHash;
      this.precomputed = true;
      // Make it obvious to user that we are pre-computing
      this.debug1("Found Predefined Cypher Keys. Cypher Key Input Fields Hidden.");
      document.getElementById("keyWrap").style.display = "none";
    }
  }


  /**
   * 2 MDN Functions:
   *  - b64EncodeUnicode: %encoded-UTF8->raw-bytes->base64->no-padding
   *  - b64DecodeUnicode: bytestream->%encoded-UTF8->orig
   * Reference: https://stackoverflow.com/questions/30106476/using-javascripts-atob-to-decode-base64-doesnt-properly-decode-utf-8-strings
   * NOTE: toString(16) converts to HEXADECIMAL
   */
  static b64EncodeUnicode(txt) { var txt = btoa(encodeURIComponent(txt).replace(/%([0-9A-F]{2})/g, function toSolidBytes(match, p1) { return String.fromCharCode('0x' + p1); })); while("=" == txt.charAt(txt.length-1)) txt = txt.substring(0, txt.length - 1); return txt; }
  static b64DecodeUnicode(txt) { return decodeURIComponent(atob(txt).split('').map(function(c) { return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2); }).join('')); }


  /**
   * Calculates a Score for the latest Encryption
   */
  calculateScore(){
    var rtn = { "error":false };
    if (null == this.key64) {
      this.debug("WARNING: calculateScore cannot run before an encryption.", 0);
      rtn.error = true;
      rtn.message = "No encryption has run, so we can't score it.";
      return rtn;
    }
    var scoreRunningTotal = 0;
    var scoreNumCategories = 4; //4 types of tests

    //CALC Key Length
    var effectiveLen = this.key64.length > this.KEY_LEN_MAX ? this.KEY_LEN_MAX : this.key64.length;
    rtn.scoreLen = effectiveLen / this.KEY_LEN_MAX;
    rtn.userLen = effectiveLen;
    var maxLen = this.KEY_LEN_MAX;
    scoreRunningTotal += rtn.scoreLen;
    this.debug("Score Running Total: " + scoreRunningTotal, 2);

    //CALC Key Diversity
    var desiredNum = 1000;
    var totalKeyVariants = 0;
    for (var i=0; i < CypherBunk2076.B64_ALPHABET.length; ++i) {
      var c = CypherBunk2076.B64_ALPHABET.charAt(i);
      var tempVariants = this.hashEnc.get(c).length;
      if (tempVariants > desiredNum)
        tempVariants = desiredNum; //No Extra Credit (will throw off average)
      totalKeyVariants += tempVariants;
    }
    rtn.avgKeyVariants = (totalKeyVariants / CypherBunk2076.B64_ALPHABET.length);
    rtn.variantScore = rtn.avgKeyVariants / desiredNum;
    scoreRunningTotal += rtn.variantScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 2);

    //CALC Message Homogeneity Simple
    var highDigit = 0; //Set low to be overwritten
    var highPercent = 0;
    var lowDigit = 100; //Set high to be overwritten
    var lowPercent = 100;
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
    rtn.deviationScore = 1 - avgDeviation;
    this.debug("Avg Deviation Simple: 1 - (" + deviationTotal + " / 10) = " + rtn.deviationScore, 2);
    rtn.percentRange = Math.abs(highPercent - 1) + Math.abs(lowPercent - 1);
    scoreRunningTotal += rtn.deviationScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 2);


    //CALC Message Homogeneity Complex
    var highKey = "";
    var lowKey = "";
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
    rtn.complexDeviationScore = 1 - avgDeviation;
    this.debug("Avg Deviation Complex: 1 - (" + deviationTotal + " / 10) = " + rtn.complexDeviationScore, 2);
    rtn.complexPercentRange = Math.abs(highPercent - 1) + Math.abs(lowPercent - 1);
    scoreRunningTotal += rtn.complexDeviationScore;
    this.debug("Score Running Total: " + scoreRunningTotal, 2);

    //Overall Score
    rtn.overallScore = scoreRunningTotal / scoreNumCategories;
    return rtn;
  }


  /**
  * Uses a static Cypher Key to decrypt the message
  * @param cypherText: the encrypted String to decrypt
  * @param key: the String to use as the Cypher Key (longer & diverse is better)
  */
  decrypt(cypherText, key) {
    // Hash the New Key for use
    if (key != this.keyText)
      this.keyHash(key);
    // Remove Non-Numerics (letters can be added for obfuscation)
    if (cypherText.match(/[^0-9]/g))
      cypherText = cypherText.replace(/[^0-9]/g, "");
    var mod = cypherText.length % CypherBunk2076.CYPHER_CHUNK;
    if (mod != 0) {
      // Incorrect length: Remove final corrupt character & attempt decrypt
      cypherText = cypherText.substring(0, cypherText.length - mod);
    }
    // Chunk and Decrypt (we always encrypt into exact chunk lengths)
    var b64 = '';
    var numChunks = cypherText.length / CypherBunk2076.CYPHER_CHUNK;
    for(var i=0; i < numChunks; i++) {
      var n = cypherText.substr(i * CypherBunk2076.CYPHER_CHUNK, CypherBunk2076.CYPHER_CHUNK);
      n = parseInt(n) % this.hashDec.size; //Decode Mod Equivalent Indices
      b64 = b64.concat(this.hashDec.get(n));
    }
    return CypherBunk2076.b64DecodeUnicode(b64);
  }
  /**
   * Decrypts a message with a URL Cypher Key & delivers the data to a callback
   * Delivered message looks like this:
   *   {error:false, message:"", clearText="1234567890"}
   *   {error:true, message:"Failed to fetch...", clearText=null}
   * @param cypherText: the encrypted String to decrypt
   * @param urlKey: a resource to fetch as the key
   * @param callback: where to deliver the encrypted text to
   */
  async decryptWithURL(cypherText, urlKey, callback){
    // Only fetch the URL if it is a new one
    if (this.keyUrl == urlKey) {
      var clearText = this.decrypt(cypherText, this.keyText);
      var rtn = { error:false, message:'Used Cached URL Key', clearText:clearText };
      callback(rtn);
    } else {
      var cbRef = this;
      $.get(urlKey, function(data) { //Data will be the Cypher Key
        cbRef.keyUrl = urlKey;
        var clearText = cbRef.decrypt(cypherText, data);
        var rtn = { error:false, message:'', clearText:clearText };
        callback(rtn);
      }).fail(function(data){
        var msg = "Failed to fetch Decryption Key @ " + urlKey;
        console.log(msg);
        var rtn = { error:true, message:msg, clearText:null };
        callback(rtn);
      });
    }
  }


  /**
  * Uses a static Cypher Key to encrypt the message
  * @param clearText: the String to encrypt
  * @param key: the String to use as the Cypher Key (longer & diverse is better)
  */
  encrypt(clearText, key) {
    //TODO: allows CSV style output with fake words added (maybe like an inventory)
    var rtn = "";
    // Hash the New Key for use
    if (key != this.keyText)
      this.keyHash(key);
    // Base 64 Encode to handle Unicode well (also helps with CypherText Homogeneity)
    var b64Text = CypherBunk2076.b64EncodeUnicode(clearText);
    for(var i=0; i < b64Text.length; ++i) {
      var c = b64Text.charAt(i);
      var cypherOpts = this.hashEnc.get(c);
      var cypherChar = cypherOpts[Math.floor(Math.random() * cypherOpts.length)];
      // Make key WITHOUT formatted Mod Equivalents
      var tallyKey = c + "_" + cypherChar;
      cypherChar = this.formatCypherChar(cypherChar);
      //TODO: make a checkbox to add letter interlacing (50% chance to append an a-zA-Z after each number that is appended)
      // Count used keys here to make Score Calculation MUCH easier
      if (!(tallyKey in this.tallyEnc))
        this.tallyEnc[tallyKey] = 0;
      this.tallyEnc[tallyKey]++;
      this.tallyTotal++;
      // Force String Concat, even though cypherChar is always numeric
      rtn = rtn.concat(cypherChar);
    }
    this.message = rtn; //Save for calculateScore()
    return rtn;
  }
  /**
   * Encrypts a message with a URL Cypher Key & delivers the data to a callback
   * Delivered message looks like this:
   *   {error:false, message:"", cypherText="1234567890"}
   *   {error:true, message:"Failed to fetch...", cypherText=null}
   * @param clearText: the text to encrypt
   * @param urlKey: a resource to fetch as the key
   * @param callback: where to deliver the encrypted text to
   */
  async encryptWithURL(clearText, urlKey, callback){
    // Only fetch the URL if it is a new one
    if (this.keyUrl == urlKey) {
      var cypherText = this.encrypt(clearText, this.keyText);
      var rtn = { error:false, message:'Used Cached URL Key', cypherText:cypherText };
      callback(rtn);
    } else {
      var cbRef = this;
      $.get(urlKey, function(data) { //Data will be the Cypher Key
        cbRef.keyUrl = urlKey;
        var cypherText = cbRef.encrypt(clearText, data);
        var rtn = { error:false, message:'', cypherText:cypherText };
        callback(rtn);
      }).fail(function(data){
        var msg = "Failed to fetch Encryption Key @ " + urlKey;
        console.log(msg);
        var rtn = { error:true, message:msg, cypherText:null };
        callback(rtn);
      });
    }
  }


  /***** Turns the Index into a Modulus Equivalent with Zero Padding *****/
  formatCypherChar(n){ //n must be a positive integer
    var keyLen = this.hashDec.size;
    var maxMultiple = Math.floor(CypherBunk2076.CYPHER_MAX / keyLen);
    var randMultiple = Math.floor(Math.random() * maxMultiple);
    n = keyLen * randMultiple + n; //Modulus equivalent index
    //Zero Padding
    n = "0000000000" + n.toString();
    return n.substr(n.length - CypherBunk2076.CYPHER_CHUNK);
  }


  /**
   * Take a CypherKey and hash it into a Map
   * (Ignore if Precompute already exists from keys.js)
   */
  keyHash(key){ //Generates hashEnc and hashDec
    if (this.precomputed)
      return; //Skip if Hashes are Pre-Computed

    this.keyText = key;
    // Reset Variables
    this.hashDec.clear();
    this.hashEnc.clear();
    this.precomputedJS = '';
    this.precomputedWarning = null;
    this.tallyEnc = {};
    this.tallyTotal = 0;
    // Ensure Key isn't too big
    if (this.keyText.length > CypherBunk2076.KEY_LEN_MAX)
      this.keyText = this.keyText.substring(0, CypherBunk2076.KEY_LEN_MAX);
    this.debug1('B64 Encoding keyText');
    this.key64 = CypherBunk2076.b64EncodeUnicode(this.keyText);
    // Ensure Key has ALL required characters for Base64 (minus padding)
    var numAdded = 0;
    var missingChars = "";
    for (var i=0; i < CypherBunk2076.B64_ALPHABET.length; ++i) {
      var c = CypherBunk2076.B64_ALPHABET.charAt(i);
      if (-1 == this.key64.indexOf(c)) { //If it doesn't have that B64 char
        missingChars = missingChars.concat(c);
        numAdded++;
      }
    }
    if (numAdded > 0) {
      // Add to front and back so each Char has at least 2 cypher indices
      this.key64 = missingChars + this.key64 + missingChars;
      var s = (numAdded > 1 ? "s" : "");
      this.precomputedWarning = "Your key wasn't complicated enough, "
        + "so we had to add " + numAdded + " character" + s
        + " to your key.<br/>"
        + "It will work fine, but each added character reduces "
        + "the security of your encryption.<br/>"
        + "Consider using a longer and more complicated Cypher Key.";
      this.debug0(this.precomputedWarning);
    }
    // Compute Hashes
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
    // Generate Static JS Keys (for Display in UI)
    js += "\n";
    for (var i=0; i < CypherBunk2076.B64_ALPHABET.length; ++i) {
      var c = CypherBunk2076.B64_ALPHABET.charAt(i);
      var tempArray = this.hashEnc.get(c);
      tempArray = JSON.stringify(tempArray);
      js += "\npredefinedEncHash.set(\"" + c + "\", " + tempArray + ");";
    }
    this.precomputedJS = js;
  }










  /***** Logs Messages to Console ONLY IF Debug is enabled *****/
  debug(msg, debugLevel = 1, title = "") {
    if (this.debugEnabled && debugLevel <= this.debugLevel) {
      if (title.length > 0)
        console.log("========== " + title + " ==========");
      console.log(msg);
    }
  }
  debug0(msg, title = "") { this.debug(msg, 0, title); }
  debug1(msg, title = "") { this.debug(msg, 1, title); }
  debug2(msg, title = "") { this.debug(msg, 2, title); }
  debug3(msg, title = "") { this.debug(msg, 3, title); }
}
