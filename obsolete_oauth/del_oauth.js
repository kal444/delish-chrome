"use strict";
/**
 * DelOauth will encapsulate the Oauth related 
 * portion of communication to yahoo.com/delicious.com
 *
 * Well apparently delicious.com is going to discontinue 
 * using Yahoo OAuth all together...
 *
 * So consider this class deprecated. I would guess this 
 * class is about 80% complete though.
 * @constructor
 */
var DelOauth = function(oauthConfig) {

    this._NONCE_SEED = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    this._OAUTH_VERSION = "1.0";
    this._OAUTH_URLS = {
        get_request_token: "https://api.login.yahoo.com/oauth/v2/get_request_token",
        request_auth: "https://api.login.yahoo.com/oauth/v2/request_auth",
        get_token: "https://api.login.yahoo.com/oauth/v2/get_token",
    };

    this._default_signature_method = 'HMAC-SHA1';
    this._default_lang_pref = 'en-us';

    if (!oauthConfig) {
        throw "Cannot processed without some configuration";
    }
    this._consumer_key = oauthConfig.consumer_key;
    this._consumer_shared_secret = oauthConfig.consumer_shared_secret;
    this._oauth_callback_url = oauthConfig.oauth_callback_url;
    if (!this._consumer_key || !this._consumer_shared_secret) {
        throw "Must provide consumer key and consumer shared secret";
    }

    /* 
     * the following won't be provided the first time this object is used.
     * they are populate only after a success authorization had happened 
     */
    this._oauth_token = oauthConfig.last_oauth_token;
    this._oauth_token_secret = oauthConfig.last_oauth_token_secret;
    this._oauth_session_handle = oauthConfig.last_oauth_session_handle;
    if (!this._oauth_callback_url && 
        (!this.oauth_token || !this.oauth_token_secret || !this._oauth_session_handle)) {
        throw "Must provide callback URL or previously authenticated tokens";
    }

    /**
     * returns a new nonce for use by the delicious oauth api, 
     * it will be a fixed length of 16 characters
     * @private
     */
    this._getNonce = function() {
        var result = "";
        var seedLen = this._NONCE_SEED.length + 1;
        for (var i = 0; i < 16; i++) {
            var pos = Math.floor(Math.random() * seedLen);
            result += this._NONCE_SEED[pos];
        };
        return result;
    }

    /**
     * returns the current timestamp for use by the delicious 
     * oauth API. It's only looking for seconds precision
     * @private
     */
    this._getTimestamp = function() {
        var date = new Date();
        return Math.round(date.getTime() / 1000);
    }

    /**
     * returns a normalized string of the incoming params
     * params is expected to be an object with name/value 
     * pairs
     * separator and quote strings are optional
     * @private
     */
    this._normalize = function(params, separator, quote) {
        if (!separator) {
            // defaults to &
            separator = '&';
        }
        if (!quote) {
            // defaults to no quotes - empty string
            quote = '';
        }
        var keys = new Array();
        for (p in params) {
            keys.push(p);
        }
        keys.sort();

        var result = "";
        var keysLen = keys.length;
        for (var i = 0; i < keysLen; i++) {
            result += encodeURIComponent(keys[i]) + "=" + quote +
                encodeURIComponent(params[keys[i]]) + quote;
            if (i + 1 < keysLen) {
                result += separator;
            }
        }

        return result;
    }

    /**
     * combine 2 objects into one. This is used to combine 
     * url params and authentication params if necessary
     * @private
     */
    this._combine = function(params1, params2) {
        var params = {};
        for (p1 in params1) {
            params[p1] = params1[p1];
        }
        for (p2 in params2) {
            params[p2] = params2[p2];
        }
        return params;
    }

    /**
     * returns a parsed object populated with key/value pairs from 
     * the response object
     * response is expected to be in a key=value&key=value format
     * @private
     */
    this._parseResponse = function(res) {
        var result = {};
        var strs = res.split('&');
        for (var i = 0, len = strs.length; i < len; i++) {
            var kv = strs[i].split('=');
            result[decodeURIComponent(kv[0])] = decodeURIComponent(kv[1]);
        }
        return result;
    }

    /**
     * creates the common part of the parameters needed for 
     * communicating to delicious over oauth
     * @private
     */
    this._buildCommonParams = function() {
        var params =  {
            oauth_version: this._OAUTH_VERSION,
            oauth_signature_method: this._default_signature_method,
            oauth_consumer_key: this._consumer_key,
            oauth_nonce: this._getNonce(),
            oauth_timestamp: this._getTimestamp(),
            xoauth_lang_pref: this._default_lang_pref
        };

        if (this._oauth_token) {
            params.oauth_token = this._oauth_token;
        }

        return params;
    }

    /**
     * create the key needed for communication based on shared secret and 
     * token secret. Even if there is no token secret yet, a '&' sign is 
     * still needed
     * @private
     */
    this._generateKey = function() {
        return (this._consumer_shared_secret ? this._consumer_shared_secret : '') + "&" + 
            (this._oauth_token_secret ? this._oauth_token_secret : '');
    }

    /**
     * build a request using OAuth api with plaintext signature
     * requestConfig is expected to provide the URL, URL params 
     * and authentication params and optional headers.
     * callback is only invoke when the call is successful. The 
     * response data will be passed on
     * @private
     */
    this._sendPlaintextRequest = function(requestConfig, callback) {
        var headers = requestConfig.headers;
        var url = requestConfig.url;
        var urlParams = requestConfig.urlParams;
        var authParams = requestConfig.authParams;

        // plaintext needs to include the key directly
        authParams.oauth_signature = this._generateKey();

        var queryParams = this._normalize(this._combine(urlParams, authParams));
        var requestUrl = url + "?" + queryParams;
        console.log("request URL=" + requestUrl);
        jQuery.ajax({
                type: 'GET',
                url: requestUrl,
                beforeSend: function(xhr) {
                    for (h in headers) {
                        xhr.setRequestHeader(h, headers[h]);
                    }
                },
                success: function(result, status, xhr) {
                    callback(result);
                },
                error: function(xhr, status, error) {
                    alert("Error in sendPlaintextRequest");
                }
            });
    }

    /**
     * build a request using OAuth api with sha1 signature
     * requestConfig is expected to provide the URL, URL params 
     * and authentication params and optiona headers.
     * callback is only invoke when the call is successful. The 
     * response data will be passed on
     * @private
     */
    this._sendSha1Request = function(requestConfig, callback) {
        var headers = requestConfig.headers;
        var url = requestConfig.url;
        var urlParams = requestConfig.urlParams;
        var authParams = requestConfig.authParams;

        var requestUrl;
        if (urlParams && Object.keys(urlParams).length > 0) {
            requestUrl = url + "?" + this._normalize(urlParams);
        } else {
            requestUrl = url;
        }
        console.log("request URL=" + requestUrl);

        var key = this._generateKey();
        console.log("key=" + key);
        // more uri encodings here
        var baseString = "GET&"+encodeURIComponent(url) + "&" + 
            encodeURIComponent(this._normalize(this._combine(urlParams, authParams)));
        console.log("base string=" + baseString);
        // = needs to be add to the end
        var signature = b64_hmac_sha1(key, baseString) + "=";
        console.log("signature=" + signature);
        // params needs to include commas and quotes. signature needs to be uri encoded
        // also needs a separation of protocol params and query params
        // query params go in the actual request and protocol params go in the header only
        var authheader = 'OAuth realm="yahooapis.com",' + 
            this._normalize(authParams,',','"') + ',oauth_signature="' + 
            encodeURIComponent(signature) + '"';
        console.log("authorization header=" + authheader);
        jQuery.ajax({
                type: 'GET',
                url: requestUrl,
                beforeSend: function(xhr) {
                    xhr.setRequestHeader("Authorization", authheader);
                    for (h in headers) {
                        xhr.setRequestHeader(h, headers[h]);
                    }
                },
                success: function(result, status, xhr) {
                    callback(result);
                },
                error: function(xhr, status, error) {
                    alert("Error in sendSha1Request");
                }
            });
    }
}

/**
 * send out an OAuth request. It wil pick the correct signature method 
 * based on the config object
 */
DelOauth.prototype.sendOauthRequest = function(requestConfig, callback) {
    if (requestConfig.authParams.oauth_signature_method == "plaintext") {
        this._sendPlaintextRequest(requestConfig, callback);
    } else {
        this._sendSha1Request(requestConfig, callback);
    }
}

/**
 * initialize the process to get a request token
 */
DelOauth.prototype.getRequestToken = function(callback) {
    // clear the existing tokens since this starts a new approval process
    this._oauth_token = null;
    this._oauth_token_secret = null;

    var authParams = this._buildCommonParams();
    authParams.oauth_callback = this._oauth_callback_url;
    var that = this; // workaround "this" scope issue in callbacks
    this.sendOauthRequest({
            url: this._OAUTH_URLS.get_request_token,
            authParams: authParams
        }, function(result) {
            that.onRequestToken(result, callback);
        });
}

/**
 * performs the processing of response to the request token request.
 * Will invoke callback when the reponse is parsed and ready to 
 * proceed to verificaiton
 *
 * the callback function is expected to take the verification URL 
 * and display it to the user. Once the user verifies, the control 
 * should be directed back to verifyCallback method.
 */
DelOauth.prototype.onRequestToken = function(result, callback) {
    var res = this._parseResponse(result);
    var authParams = this._buildCommonParams();

    authParams.oauth_token = res.oauth_token;
    authParams.oauth_callback = this._oauth_callback_url;
    authParams.oauth_signature_method = "plaintext";
    authParams.oauth_signature = this._generateKey();
    var url = this._OAUTH_URLS.request_auth + "?" + this._normalize(authParams);

    // saving the token and token secret must be done after the url is 
    // generated because this particular request does NOT need token secret 
    // as part of the key
    this._oauth_token = res.oauth_token;
    this._oauth_token_secret = res.oauth_token_secret;
    console.log("request token=" + res.oauth_token);
    console.log("request token secret=" + res.oauth_token_secret);

    callback(url);
}

/**
 * this needs to be called by the callback page. 
 * the token verifier needs to be provided.
 */
DelOauth.prototype.verifyCallback = function(result) {
    var res = this._parseResponse(result);
    if (this._oauth_token == res.oauth_token) {
        // verified for the same request token
        // now we can request a new access token
        var authParams = this._buildCommonParams();
        // TODO temporary walkaround to use plaintext
        // don't know why SHA1 method isn't working. 
        // seems like all the params are right. Is it not 
        // implemented or not implemented correctly on 
        // Yahoo side?
        authParams.oauth_signature_method = "plaintext";
        authParams.oauth_signature = this._generateKey();
        // TODO temporary walkaround to use plaintext
        var urlParams = {};
        urlParams.oauth_verifier = res.oauth_verifier;
        console.log("verifier=" + res.oauth_verifier);
        var that = this; // workaround "this" scope issue in callbacks
        this.sendOauthRequest({
                url: this._OAUTH_URLS.get_token,
                urlParams: urlParams,
                authParams: authParams
            }, function(result) {
                that.onAccessToken(result);
            });
    }
}

/**
 * this will be invoked to refresh an expired token
 */
DelOauth.prototype.refreshToken = function() {
    var authParams = this._buildCommonParams();
    authParams.oauth_session_handle = this._oauth_session_handle;
    // TODO temporary walkaround to use plaintext
    // don't know why SHA1 method isn't working. 
    // seems like all the params are right. Is it not 
    // implemented or not implemented correctly on 
    // Yahoo side?
    authParams.oauth_signature_method = "plaintext";
    authParams.oauth_signature = this._generateKey();
    // TODO temporary walkaround to use plaintext
    var that = this; // workaround "this" scope issue in callbacks
    this.sendOauthRequest({
            url: this._OAUTH_URLS.get_token,
            authParams: authParams
        }, function(result) {
            that.onAccessToken(result);
        });
}

/**
 * performs the processing of the response to the access token request.
 * Will invoke callback when the reponse is parsed. The access token, 
 * secret and session handle will be provided to the callback so that 
 * it can be saved
 */
DelOauth.prototype.onAccessToken = function(result) {
    var res = this._parseResponse(result);
    // saving the token and token secret 
    this._oauth_token = res.oauth_token;
    console.log("access token=" + res.oauth_token);
    this._oauth_token_secret = res.oauth_token_secret;
    console.log("access token secret=" + res.oauth_token_secret);
    this._oauth_session_handle = res.oauth_session_handle;
    console.log("session handle=" + res.oauth_session_handle);
}

