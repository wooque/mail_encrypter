var password = "kurta";
var header = "MailSec encrypted ";

function ua2hex(ua) {
    var hex = "";
    for (var i = 0; i < ua.length; i++) {
        hex += (ua[i] < 16 ? "0": "") + ua[i].toString(16);
    }
    return hex;
}

function hex2ua(hex) {
    var ua = new Uint8Array(hex.length/2);
    for (var i = 0; i < hex.length; i += 2) {
        ua[i/2] = parseInt(hex.slice(i, i+2), 16);
    }
    return ua;
}

function get_key(password) {
    var pass_bytes = new TextEncoder().encode(password);
    return crypto.subtle.digest({name: "SHA-256"}, pass_bytes)
    .then(function(hash) {
        return crypto.subtle.importKey("raw", hash, {name: "AES-CTR"}, false, ["encrypt", "decrypt"]);
    });
}

function encrypt_txt(txt, password) {
    var data = new TextEncoder().encode(txt);
    var encrypted_data = new Uint8Array(16 + data.length);
    var counter = crypto.getRandomValues(new Uint8Array(16));
    encrypted_data.set(counter);
    
    return get_key(password).then(function (key) {
        return crypto.subtle.encrypt({name: "AES-CTR", counter: counter, length: 128}, key, data)
        .then(function(encrypted){
            encrypted_data.set(new Uint8Array(encrypted), 16);
            return new Promise(function(resolve, reject) {
                resolve(ua2hex(encrypted_data));
            });
        });
    });
}

function decrypt_txt(txt, password) {
    var data = hex2ua(txt);
    var counter = data.slice(0, 16);
    data = data.slice(16);

    return get_key(password).then(function (key) {
        return crypto.subtle.decrypt({name: "AES-CTR", counter: counter, length: 128}, key, data)
        .then(function(decrypted){
            var orig_txt = new TextDecoder().decode(new Uint8Array(decrypted));
            return new Promise(function(resolve, reject) {
                resolve(orig_txt);
            });
        });
    });
}

function encrypt_email() {
    var send = document.getElementsByClassName('Am Al editable LW-avf');
    if (send.length == 0) return;
    
    send = send[0];
    var text = send.innerHTML;
    if (text.startsWith(header)) return;
    
    return encrypt_txt(text, password)
    .then(function(enc_txt) {
        send.innerHTML = header + enc_txt;
        return new Promise(function (resolve, reject) { resolve(); });
    });
};

function attach_on_send() {
    var send = document.getElementsByClassName('T-I J-J5-Ji aoO T-I-atl L3');
    if (send.length == 0) return;
    
    send = send[0];
    if (send.getAttribute("attached")) return;
    send.setAttribute("attached", true);
    
    var triggered = false;
    send.addEventListener("click", function(e) {
        if (triggered) {
            triggered = false;
            return;
        }
        e.stopImmediatePropagation();
        
        encrypt_email().then(function() {
            triggered = true;
            send.click();
        });
    });
}

function decrypt_email() {
    var msg = document.getElementsByClassName('a3s aXjCH');
    if (msg.length == 0) return;
    
    msg = msg[0];
    msg = msg.childNodes[0];
    if (!msg.innerHTML.startsWith(header)) return;
    
    var text = msg.innerHTML.replace(/\<wbr\>/g, '');
    
    return decrypt_txt(text.slice(header.length), password)
    .then(function (dec_txt) {
        msg.innerHTML = dec_txt;
        return new Promise(function (resolve, reject) { resolve(); });
    });
}

chrome.runtime.onMessage.addListener(function() {
    encrypt_email();
    decrypt_email();
});

document.addEventListener("DOMSubtreeModified", function() {    
    attach_on_send();
    decrypt_email();
});
