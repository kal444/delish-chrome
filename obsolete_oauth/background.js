"use strict";
/**
 * this script contains all long running logic needed by 
 * the extension
 */

/**
 * ensures only 1 OAuth helper is created.
 * Stores the instance of the OAuth helper
 * This is only needed for Yahoo OAuth API
 */
// stores the instance of oauth helper 
var _oauth_instance;
function oauth() {
    if (!_oauth_instance) {
        console.log("creating new DelOauth");
        _oauth_instance = new DelOauth(
            {
                consumer_key: "" + "",
                consumer_shared_secret: "",
                oauth_callback_url: "http://www.yellowaxe.com/delish_callback.html"
            }
        );
    }

    return _oauth_instance;
}
