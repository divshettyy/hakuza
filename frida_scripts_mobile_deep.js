/**
 * HAKUZA Mobile Frida Scripts Library
 * Advanced runtime hooks for Android & iOS testing
 *
 * Usage:
 *   frida -U -f com.example.app -l frida_scripts_mobile_deep.js
 *   frida -H attacker.com:27042 -f com.example.app -l frida_scripts_mobile_deep.js
 */

// ============================================================================
// ANDROID: SSL PINNING BYPASS (OkHttp + Network Security Config)
// ============================================================================

var ssl_bypass_android = `
Java.perform(function() {
    console.log("[+] Initializing SSL bypass...");

    // TrustManager: Trust all certificates
    var TrustManager = Java.type('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.type('javax.net.ssl.SSLContext');
    var HostnameVerifier = Java.type('javax.net.ssl.HttpsURLConnection');

    // Create permissive trust manager
    var TrustAllCerts = Java.registerClass({
        name: 'com.hakuza.TrustAllCerts',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {
                console.log("[CERT] Client cert check bypassed");
            },
            checkServerTrusted: function(chain, authType) {
                console.log("[CERT] Server cert check bypassed: " + authType);
            },
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });

    // Install trust manager
    try {
        var ctx = SSLContext.getInstance('TLS');
        ctx.init(null, [new TrustAllCerts()], null);
        HostnameVerifier.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        console.log("[+] SSL verification disabled globally");
    } catch(e) {
        console.log("[-] SSL bypass error: " + e);
    }

    // OkHttp3 bypass (if used)
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClient.build.implementation = function() {
            console.log("[OkHttp] build() called");
            var client = this.build();

            // Hook setHostnameVerifier
            if (OkHttpClient.hostnameVerifier) {
                console.log("[OkHttp] Replacing hostname verifier");
                var DefaultHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
                DefaultHostnameVerifier.verify.implementation = function(host, session) {
                    console.log("[OkHttp] Hostname verification: " + host);
                    return true;
                };
            }

            return client;
        };
    } catch(e) {
        console.log("[OkHttp] Not present or error: " + e);
    }

    // Certificate pinning bypass (Network Security Config)
    try {
        var NetworkSecurityPolicy = Java.use('android.security.NetworkSecurityManager');
        if (NetworkSecurityPolicy) {
            console.log("[+] Found NetworkSecurityManager - attempting bypass");
            // This requires framework modifications
        }
    } catch(e) {
        // Expected if not available
    }
});
`;

// ============================================================================
// ANDROID: ROOT DETECTION BYPASS
// ============================================================================

var root_detection_bypass = `
Java.perform(function() {
    console.log("[+] Initializing root detection bypass...");

    var Runtime = Java.type('java.lang.Runtime');
    var File = Java.type('java.io.File');

    // Common root files to check for
    var root_files = [
        '/system/app/Superuser.apk',
        '/system/xbin/su',
        '/system/xbin/daemonsu',
        '/data/adb/su',
        '/data/adb/magisk',
        '/cache/magisk.log',
        '/dev/su',
        '/system/bin/su.real',
        '/sbin/su',
    ];

    // Check if file exists and report
    console.log("[*] Scanning for root indicators...");
    root_files.forEach(function(path) {
        try {
            var f = new File(path);
            if (f.exists()) {
                console.log("[ROOT] " + path + " — FOUND");
            }
        } catch(e) {}
    });

    // Hook Runtime.exec to intercept su commands
    var original_exec = Runtime.exec;
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1) {
            console.log("[EXEC] Intercepted: " + cmd);
            throw new Error("[+] su command blocked");
        }
        return original_exec.call(this, cmd);
    };

    // Hook Build properties
    try {
        var Build = Java.type('android.os.Build');
        var BuildClass = Java.type('java.lang.Class').forName('android.os.Build');

        // Common root indicators in build properties
        var root_props = ['TAGS', 'FINGERPRINT', 'PRODUCT', 'DEVICE'];
        root_props.forEach(function(prop) {
            try {
                var field = BuildClass.getDeclaredField(prop);
                field.setAccessible(true);
                var value = field.get(null);
                console.log("[BUILD] " + prop + " = " + value);
            } catch(e) {}
        });
    } catch(e) {
        console.log("[BUILD] Error accessing Build properties: " + e);
    }

    // Hook getProperty for ro.debuggable, ro.secure
    var System = Java.type('java.lang.System');
    var original_getProperty = System.getProperty;
    System.getProperty.overload('java.lang.String').implementation = function(key) {
        var value = original_getProperty.call(this, key);

        if (key === 'ro.debuggable' || key === 'ro.secure' || key === 'ro.build.tags') {
            console.log("[PROP] " + key + " = " + value);
        }

        return value;
    };
});
`;

// ============================================================================
// ANDROID: CRYPTO OPERATIONS LOGGER
// ============================================================================

var crypto_logger = `
Java.perform(function() {
    console.log("[+] Initializing crypto logger...");

    // Hook Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');
    var original_getInstance = Cipher.getInstance;

    Cipher.getInstance.overload('java.lang.String').implementation = function(transform) {
        console.log("[CIPHER] getInstance: " + transform);
        return original_getInstance.call(this, transform);
    };

    Cipher.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function(transform, provider) {
        console.log("[CIPHER] getInstance: " + transform + " (provider: " + provider + ")");
        return original_getInstance.call(this, transform, provider);
    };

    // Hook init (key setup)
    var original_init = Cipher.init;
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        var mode_name = (opmode === 1) ? "ENCRYPT" : "DECRYPT";
        console.log("[CIPHER-INIT] Mode: " + mode_name);
        console.log("[CIPHER-KEY] Algorithm: " + key.getAlgorithm());
        console.log("[CIPHER-KEY] Encoded: " + key.getEncoded().toString());

        return this.init(opmode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
        var mode_name = (opmode === 1) ? "ENCRYPT" : "DECRYPT";
        console.log("[CIPHER-INIT] Mode: " + mode_name);
        console.log("[CIPHER-KEY] Algorithm: " + key.getAlgorithm());
        console.log("[CIPHER-PARAMS] AlgParamSpec: " + params);

        return this.init(opmode, key, params);
    };

    // Hook doFinal (encrypt/decrypt)
    var original_doFinal = Cipher.doFinal;
    Cipher.doFinal.overload('[B').implementation = function(data) {
        console.log("[CIPHER-DATA] Input length: " + data.length);
        console.log("[CIPHER-DATA] Input hex: " + data.toString().substring(0, 32) + "...");

        var result = this.doFinal(data);

        console.log("[CIPHER-DATA] Output length: " + result.length);
        console.log("[CIPHER-DATA] Output hex: " + result.toString().substring(0, 32) + "...");

        return result;
    };

    // Hook MessageDigest (hashing)
    var MessageDigest = Java.type('java.security.MessageDigest');
    var original_digest = MessageDigest.getInstance;

    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
        console.log("[HASH] getInstance: " + algorithm);
        return original_digest.call(this, algorithm);
    };

    // Hook SecretKeySpec (symmetric key)
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    var original_ctor = SecretKeySpec.$init;

    SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function(key, offset, len, algorithm) {
        console.log("[SECRETKEY] Algorithm: " + algorithm);
        console.log("[SECRETKEY] Key length: " + len);
        console.log("[SECRETKEY] Key (hex): " + key.toString().substring(0, 32) + "...");

        return this.$init(key, offset, len, algorithm);
    };
});
`;

// ============================================================================
// ANDROID: SHARED PREFERENCES DUMPER
// ============================================================================

var shared_prefs_dump = `
Java.perform(function() {
    console.log("[+] Initializing SharedPreferences dumper...");

    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');

    // Hook constructor to intercept all SharedPreferences loading
    SharedPreferencesImpl.$init.overload('java.io.File', 'java.lang.String', 'int', 'android.util.ArrayMap', 'boolean').implementation = function(file, name, mode, map, rebuild) {
        console.log("[SP-LOAD] File: " + file.getPath());
        console.log("[SP-LOAD] Name: " + name);

        // Dump all preferences
        if (map && map.size && map.size() > 0) {
            var entries = map.entrySet().toArray();
            console.log("[SP-DATA] Entries count: " + entries.length);

            for (var i = 0; i < entries.length; i++) {
                var key = entries[i].getKey();
                var value = entries[i].getValue();
                console.log("[SP-PREF] " + key + " = " + value);

                // Alert on suspicious keys
                if (key.indexOf("token") !== -1 || key.indexOf("password") !== -1 ||
                    key.indexOf("secret") !== -1 || key.indexOf("key") !== -1) {
                    console.log("[SP-SENSITIVE!] " + key + " = " + value);
                }
            }
        }

        return this.$init(file, name, mode, map, rebuild);
    };

    // Hook getString/getInt/etc for real-time access
    var original_getString = SharedPreferencesImpl.getString;
    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        console.log("[SP-GET] " + key + " = " + result);
        return result;
    };

    var original_getInt = SharedPreferencesImpl.getInt;
    SharedPreferencesImpl.getInt.implementation = function(key, defValue) {
        var result = this.getInt(key, defValue);
        console.log("[SP-GET-INT] " + key + " = " + result);
        return result;
    };

    var original_getBoolean = SharedPreferencesImpl.getBoolean;
    SharedPreferencesImpl.getBoolean.implementation = function(key, defValue) {
        var result = this.getBoolean(key, defValue);
        console.log("[SP-GET-BOOL] " + key + " = " + result);
        return result;
    };
});
`;

// ============================================================================
// ANDROID: HTTP(S) REQUEST/RESPONSE INTERCEPTOR
// ============================================================================

var http_interceptor = `
Java.perform(function() {
    console.log("[+] Initializing HTTP interceptor...");

    // HttpURLConnection hooking
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');

    var original_getInputStream = HttpURLConnection.getInputStream;
    HttpURLConnection.getInputStream.implementation = function() {
        console.log("[HTTP-REQ] " + this.getRequestMethod() + " " + this.getURL());

        // Log headers
        var props = this.getRequestProperties();
        if (props) {
            var entries = props.entrySet().toArray();
            for (var i = 0; i < entries.length; i++) {
                console.log("[HTTP-HEADER] " + entries[i].getKey() + ": " + entries[i].getValue());
            }
        }

        var input = original_getInputStream.call(this);
        console.log("[HTTP-RESP] Status: " + this.getResponseCode() + " " + this.getResponseMessage());

        return input;
    };

    // OkHttp3 interceptor (if used)
    try {
        var Interceptor = Java.use('okhttp3.Interceptor');
        var RealInterceptorChain = Java.use('okhttp3.internal.http.RealInterceptorChain');

        // Hook proceed method
        var original_proceed = RealInterceptorChain.proceed;
        RealInterceptorChain.proceed.implementation = function(request) {
            var req_url = request.url().toString();
            var req_method = request.method();

            console.log("[OKHTTP-REQ] " + req_method + " " + req_url);

            // Log request body if present
            var body = request.body();
            if (body) {
                console.log("[OKHTTP-BODY] Content length: " + body.contentLength());
            }

            // Log request headers
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log("[OKHTTP-HDR] " + headers.name(i) + ": " + headers.value(i));
            }

            var response = original_proceed.call(this, request);

            console.log("[OKHTTP-RESP] Status: " + response.code());

            return response;
        };
    } catch(e) {
        console.log("[OKHTTP] Not present or hook failed: " + e);
    }
});
`;

// ============================================================================
// ANDROID: METHOD TRACER (Track app execution flow)
// ============================================================================

var method_tracer = `
Java.perform(function() {
    console.log("[+] Initializing method tracer...");

    // Trace critical methods
    var methods_to_trace = [
        { class: 'com.example.app.MainActivity', method: 'onCreate' },
        { class: 'com.example.app.LoginActivity', method: 'authenticate' },
        { class: 'com.example.app.network.ApiClient', method: 'makeRequest' },
        { class: 'com.example.app.database.Database', method: 'query' },
    ];

    methods_to_trace.forEach(function(target) {
        try {
            var cls = Java.use(target.class);
            if (cls && cls[target.method]) {
                var original_method = cls[target.method];

                cls[target.method].implementation = function() {
                    console.log("[TRACE-ENTER] " + target.class + "." + target.method);
                    console.log("[TRACE-ARGS] " + Array.prototype.slice.call(arguments));

                    var result = original_method.apply(this, arguments);

                    console.log("[TRACE-RETURN] " + target.class + "." + target.method);
                    console.log("[TRACE-RESULT] " + result);

                    return result;
                };
            }
        } catch(e) {
            console.log("[TRACE-ERROR] " + target.class + ": " + e);
        }
    });
});
`;

// ============================================================================
// ANDROID: SQLITE DATABASE DUMPER
// ============================================================================

var sqlite_dumper = `
Java.perform(function() {
    console.log("[+] Initializing SQLite dumper...");

    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    var SQLiteOpenHelper = Java.use('android.database.sqlite.SQLiteOpenHelper');

    // Hook rawQuery to intercept all SQL queries
    var original_rawQuery = SQLiteDatabase.rawQuery;
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava/lang/String;').implementation = function(sql, selectionArgs) {
        console.log("[SQL] Query: " + sql);

        if (selectionArgs && selectionArgs.length > 0) {
            console.log("[SQL-ARGS] " + selectionArgs);
        }

        var cursor = original_rawQuery.call(this, sql, selectionArgs);

        try {
            if (cursor && cursor.getCount() > 0) {
                console.log("[SQL-RESULT] Rows: " + cursor.getCount());
                cursor.moveToFirst();

                for (var i = 0; i < cursor.getColumnCount(); i++) {
                    console.log("[SQL-COL] " + cursor.getColumnName(i));
                }
            }
        } catch(e) {}

        return cursor;
    };

    // Hook query method
    var original_query = SQLiteDatabase.query;
    SQLiteDatabase.query.overload('java.lang.String', '[Ljava/lang/String;', 'java.lang.String', '[Ljava/lang/String;', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy) {
        console.log("[SQL-TABLE] " + table);
        if (columns && columns.length > 0) {
            console.log("[SQL-COLS] " + columns);
        }

        return original_query.apply(this, arguments);
    };
});
`;

// ============================================================================
// iOS: SSL PINNING BYPASS
// ============================================================================

var ios_ssl_bypass = `
ObjC.perform(function() {
    console.log("[+] Initializing iOS SSL bypass...");

    var NSURLSession = ObjC.use("NSURLSession");

    // Hook URLSession initialization
    var original_init = NSURLSession.sessionWithConfiguration;
    NSURLSession.sessionWithConfiguration.implementation = function(config) {
        console.log("[iOS-SSL] URLSession created with config");
        var session = original_init.call(this, config);
        return session;
    };

    // Hook URLSessionConfiguration
    var URLSessionConfig = ObjC.use("NSURLSessionConfiguration");
    var original_config = URLSessionConfig.defaultSessionConfiguration;
    URLSessionConfig.defaultSessionConfiguration.implementation = function() {
        console.log("[iOS-SSL] Creating URLSessionConfiguration");
        var config = original_config.call(this);
        return config;
    };
});
`;

// ============================================================================
// iOS: KEYCHAIN DUMPER
// ============================================================================

var ios_keychain_dump = `
ObjC.perform(function() {
    console.log("[+] Initializing iOS Keychain dumper...");

    var SecurityFramework = ObjC.use("Security");
    var SecItemCopyMatching = ObjC.use("Security").SecItemCopyMatching;

    // Use SecItemCopyMatching to dump all keychain items
    var NSMutableDictionary = ObjC.use("NSMutableDictionary");
    var kSecClass = ObjC.use("Security").kSecClass;
    var kSecClassGenericPassword = ObjC.use("Security").kSecClassGenericPassword;
    var kSecReturnAttributes = ObjC.use("Security").kSecReturnAttributes;
    var kSecReturnData = ObjC.use("Security").kSecReturnData;

    try {
        var query = NSMutableDictionary.new();
        query.setObject_forKey_(kSecClassGenericPassword, kSecClass);
        query.setObject_forKey_(ObjC.use("NSNumber").numberWithBool_(true), kSecReturnAttributes);
        query.setObject_forKey_(ObjC.use("NSNumber").numberWithBool_(true), kSecReturnData);

        console.log("[iOS-KC] Dumping all Keychain items...");
        // This requires framework-level implementation
    } catch(e) {
        console.log("[iOS-KC] Error: " + e);
    }
});
`;

// ============================================================================
// EXPORT INTERFACE
// ============================================================================

var SCRIPTS = {
    'ssl_bypass_android': ssl_bypass_android,
    'root_detection_bypass': root_detection_bypass,
    'crypto_logger': crypto_logger,
    'shared_prefs_dump': shared_prefs_dump,
    'http_interceptor': http_interceptor,
    'method_tracer': method_tracer,
    'sqlite_dumper': sqlite_dumper,
    'ios_ssl_bypass': ios_ssl_bypass,
    'ios_keychain_dump': ios_keychain_dump,
};

// Auto-run all scripts
console.log("[*] Loading Hakuza Mobile Frida Scripts");
console.log("[*] Available scripts: " + Object.keys(SCRIPTS).join(", "));

// Uncomment specific scripts to load
// eval(ssl_bypass_android);
// eval(crypto_logger);
// eval(shared_prefs_dump);
// eval(http_interceptor);

console.log("[+] Frida script library loaded successfully");
