"use strict";
/**
 * This file should be in charge of overall extension 
 * logic
 */

/** 
 * display a popup window so that the user 
 * can authorize access to delicious 
 * Only needed for Yahoo OAuth protocol
 */
function showAuthorizationWindow(url) {
    chrome.windows.create({ url: url, focused: true, type: "normal" });
}

/** 
 * process the OAuth callback 
 * Only needed for Yahoo OAuth protocol
 */
function processCallback() {
    var url = window.location.href;
    var parts = url.split('?');
    if (parts.length == 2) {
        chrome.tabs.getSelected(null, function(tab) {
                chrome.tabs.remove(tab.id);
            });
        var bg = chrome.extension.getBackgroundPage();
        bg.oauth().verifyCallback(parts[1]);
    }
}
