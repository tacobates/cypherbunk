/**
 * Cypher Bunk UI is an example for how to make a page use the CypherBunk2076
 * utility.  It can be used to run Cypher Bunk as a stand-alone app, rather
 * than using it as a utility in another JS project.
 * This JS assumes that it has been included on the standard CypherBunk
 * index.html. As such, it assumes several DOM elements exist for it to
 * populate.
 *
 * DEPENDENCY:
 *   CypherBunk2076.js must be included on the page first
 *
 * Author: Rob Bates, June 2022
 * License: Do whatever you want, but please link to my site to give credit.
 * Site: www.localmess.com/_g.cypherbunk
 */

/********** GLOBAL VARIABLES **********/
var _g = {
  DEBUG_LEVEL: 1, //1 for basic messages, 2 for details, 3 for noise
  cypherbunk: null, //Holds the CypherBunk2076 object
  dom: {}, //Holds several dom elements for easy access
  message: null,
  undoText: "", //What was in _g.dom.message before we replaced it
}


/********** CLASS DEFINITION **********/
class CypherBunkUI {
  static TEST_URL = "https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js";
  static TEST_URL_BROKEN = "https://ajax.googleapis.com/BROKEN";


  /********** FUNCTIONS **********/
  /** Caches the DOM, and sets up the cypherbunk object */
  static init(){
    var testOnly = false; //true to run a simple test, log to console, and quit
    _g.cypherbunk = new CypherBunk2076(_g.DEBUG_LEVEL);

    _g.dom.keyUrl = document.getElementById("keyUrl");
    _g.dom.keyText = document.getElementById("keyText");
    _g.dom.message = document.getElementById("message");
    _g.dom.predefinedJS = document.getElementById("predefinedJS");
    _g.dom.warning = document.getElementById("warning");

    _g.dom.d1 = document.getElementById('detail1');
    _g.dom.d2 = document.getElementById('detail2');
    _g.dom.d3 = document.getElementById('detail3');
    _g.dom.d4 = document.getElementById('detail4');
    _g.dom.s = document.getElementById('score_total');
    _g.dom.s1 = document.getElementById('score1');
    _g.dom.s2 = document.getElementById('score2');
    _g.dom.s3 = document.getElementById('score3');
    _g.dom.s4 = document.getElementById('score4');

    document.getElementById("version").innerHTML = "version " + _g.cypherbunk.VERSION;
    //Make Close Icons for Popup Cards
    var cards = document.querySelectorAll(".card");
    for(var i=0; i < cards.length; ++i) {
      var closer = document.createElement("div");
      closer.className = "cardClose";
      closer.innerHTML = "&times;";
      closer.onclick = function(){ CypherBunkUI.cardCloseAll(); };
      cards[i].prepend(closer);
    }

    //Look for Pre-Computed Hashes
    if (typeof predefinedDecHash !== 'undefined' && predefinedEncHash !== 'undefined') {
      //Make it obvious to user that we are pre-computing
      CypherBunkUI.showWarning("Found Predefined Cypher Keys. Cypher Key Input Fields Hidden.");
      document.getElementById("keyWrap").style.display = "none";
    }

    //Default Message to one of our ASCII Logo
    if (typeof ASCII_LOGOS !== 'undefined')
      _g.dom.message.value = CypherBunk2076.b64DecodeUnicode(ASCII_LOGOS[Math.floor(Math.random() * ASCII_LOGOS.length)]);

    if (_g.cypherbunk.debugEnabled) {
      _g.cypherbunk.debug("Setting Key Values, since Debug Enabled", 2);
      _g.dom.keyText.value = "The Quick Red Fox Jumped Over the Lazy Brown Dog. <>,.?:;|{}[]~!@#$%^&*()_+=-0987654321`Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.".repeat(3);
      _g.dom.keyUrl.value = CypherBunkUI.TEST_URL;
    }

    if (testOnly) {
      CypherBunkUI.testStaticKey();
      CypherBunkUI.testUrlKey();
    }
  }


  /** Hide All Cards */
  static cardCloseAll() {
    var cards = document.querySelectorAll(".card");
    for(var i=0; i < cards.length; ++i) {
      cards[i].classList.add("invisible");
    }
  }
  /** Shows the specified Card */
  static cardShow(id) {
    CypherBunkUI.cardCloseAll();
    var card = document.getElementById(id);
    card.classList.remove("invisible");
  }


  /** Decrypt the text in #message */
  static decryptMessage(){
    if (_g.dom.keyText.value.length > 0) { // Use this Static Key
      var clearText = _g.cypherbunk.decrypt(_g.dom.message.value, _g.dom.keyText.value);
      var decObj = {error:false, message:"", clearText:clearText};
      CypherBunkUI.decryptMessageFinalize(decObj);
    } else {
      _g.cypherbunk.decryptWithURL(_g.dom.message.value, _g.dom.keyUrl.value, CypherBunkUI.decryptMessageFinalize);
    }
  }
  /** Finishes the Decrypt Process and Displays (can be used as Callback) */
  static decryptMessageFinalize(data){
    if (data.error) {
      CypherBunkUI.showWarning(data.message);
    } else {
      _g.dom.message.value = data.clearText;
    }
  }


  /** Encrypt the text in #message */
  static encryptMessage(){
    if (_g.dom.keyText.value.length > 0) { // Use this Static Key
      var cypherText = _g.cypherbunk.encrypt(_g.dom.message.value, _g.dom.keyText.value);
      var encObj = {error:false, message:"", cypherText:cypherText};
      CypherBunkUI.encryptMessageFinalize(encObj);
    } else {
      _g.cypherbunk.encryptWithURL(_g.dom.message.value, _g.dom.keyUrl.value, CypherBunkUI.encryptMessageFinalize);
    }
  }
  /** Finishes the Encrypt Process and Displays (can be used as Callback) */
  static encryptMessageFinalize(data){
    if (data.error) {
      CypherBunkUI.showWarning(data.message);
    } else {
      _g.dom.message.value = CypherBunk2076.TAG_MESSAGE + "\n" + data.cypherText;
    }
  }


  /***** Formats a score from a 0-based percent to a 100-based percent *****/
  static formatScore(n, precision = 2, cap100 = true){
    n *= 100;
    n = n.toFixed(precision);
    if (n > 100 && cap100)
      n = 100;
    else if (n < 0)
      n = 0; //Should only happen with bad function param
    return n + "%";
  }

  /***** Gives numbers comma separators for thousands, millions, etc...*****/
  static formatThousands(n) {
    if (Math.abs(n) <= 999)
      return n;
    n = n.toString();
    return n.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }


  /***** Display the Score for the latest Encryption *****/
  static scoreShow(){
    CypherBunkUI.cardShow('scoreCard');
    var loadMsg = "Calculating...";
    _g.dom.s.innerHTML = "Calculating Overall Score...";
    _g.dom.s1.innerHTML = _g.dom.s2.innerHTML = _g.dom.s3.innerHTML = loadMsg;
    _g.dom.d1.innerHTML = _g.dom.d2.innerHTML = _g.dom.d3.innerHTML = "";

    var score = _g.cypherbunk.calculateScore();
    if (score.error) {
      CypherBunkUI.cardCloseAll();
      CypherBunkUI.showWarning(score.message)
      return;
    }

    _g.dom.s1.innerHTML = CypherBunkUI.formatScore(score.scoreLen);
    _g.dom.d1.innerHTML = "Effective length: " + score.userLen;
    _g.dom.s2.innerHTML = CypherBunkUI.formatScore(score.variantScore);
    _g.dom.d2.innerHTML = "Average variants: " + Math.round(score.avgKeyVariants);
    _g.dom.s3.innerHTML = CypherBunkUI.formatScore(score.deviationScore);
    _g.dom.d3.innerHTML = "Heterogeny range: " + CypherBunkUI.formatScore(score.percentRange, 2, false);
    _g.dom.s4.innerHTML = CypherBunkUI.formatScore(score.complexDeviationScore);
    _g.dom.d4.innerHTML = "Heterogeny range: " + CypherBunkUI.formatScore(score.complexPercentRange, 2, false);

    _g.dom.s.innerHTML = "Overall Score: " + CypherBunkUI.formatScore(score.overallScore);
  }


  /***** Displays/Hides a warning in the DOM *****/
  static showWarning(txt){ _g.dom.warning.innerHTML = txt + "<br/><br/>"; }
  static clearWarning(){ _g.dom.warning.innerHTML = ""; }


  /***** Turns Dark UI on/off *****/
  static toggleDarkUI() {
    var html = document.body.parentNode;
    if (html.className == "dark")
      html.className = "";
    else
      html.className = "dark";
  }


  /***** Undoes the very last Encrypt/Decrypt *****/
  static undo() {
    var newUndoText = _g.dom.message.value;
    _g.dom.message.value = _g.undoText;
    _g.undoText = newUndoText;
  }



  /******************** TEST FUNCTIONS ********************/
  // Tests Encryption/Decryption with a Static Cypher Key
  static testStaticKey() {
    var tempKey = "Some Key";
    var temp = _g.cypherbunk.encrypt("Hello World!", tempKey);
    console.log("=========================");
    console.log("Synchronous Encrypt:");
    console.log(temp);
    temp = _g.cypherbunk.decrypt(temp, tempKey);
    console.log("Synchronous Decrypt:");
    console.log(temp);
    console.log("=========================");
  }

  // Tests Encryption/Decryption with a URL Cypher Key & callbacks
  static testUrlKey() {
    console.log("TEST: testUrlKey()");
    var urlKey = CypherBunkUI.TEST_URL;
    _g.cypherbunk.encryptWithURL("Hello World!", urlKey, CypherBunkUI.testUrlEncryptCallback);
    //_g.cypherbunk.encryptWithURL("Hello World!", urlKey, CypherBunkUI.encryptMessageFinalize);
    console.log("Asynchronous Encrypt:");
  }
  static testUrlEncryptCallback(x){
    console.log("TEST: testUrlEncryptedCallback()");
    var urlKey = CypherBunkUI.TEST_URL;
    if (x.error) {
      console.log('ERROR: ' + x.message);
    } else {
      console.log(x.cypherText);
      _g.cypherbunk.decryptWithURL(x.cypherText, urlKey, CypherBunkUI.testUrlDecryptCallback);
      //_g.cypherbunk.decryptWithURL(x.cypherText, urlKey, CypherBunkUI.decryptMessageFinalize);
    }
  }
  static testUrlDecryptCallback(x){
    console.log("TEST: testUrlDecryptedCallback()");
    console.log("Asynchronous Decrypt:");
    if (x.error)
      console.log('ERROR: ' + x.message);
    else
      console.log(x.clearText);
  }
}
