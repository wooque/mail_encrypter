var password = "kurta";
var header = "MailSec encrypted ";

function ua2hex(ua) {
    var hex = "";
    for (var i = 0; i < ua.length; i++) {
        hex += (ua[i] < 16 ? "0" : "") + ua[i].toString(16);
    }
    return hex;
}

function hex2ua(hex) {
    var ua = new Uint8Array(hex.length / 2);
    for (var i = 0; i < hex.length; i += 2) {
        ua[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return ua;
}

function get_key(password) {
    var pass_bytes = new TextEncoder().encode(password);
    return crypto.subtle.digest({name: "SHA-256"}, pass_bytes).then(function (hash) {
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
            .then(function (encrypted) {
                encrypted_data.set(new Uint8Array(encrypted), 16);
                return new Promise(function (resolve, reject) {
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
            .then(function (decrypted) {
                var orig_txt = new TextDecoder().decode(new Uint8Array(decrypted));
                return new Promise(function (resolve, reject) {
                    resolve(orig_txt);
                });
            });
    });
}

function get_send_mail_elem_gmail() {
    var send = document.getElementsByClassName('Am Al editable LW-avf');
    if (send.length == 0) return;

    return send[0];
}

function get_send_mail_elem_outlook() {
    var send = document.getElementById('divtagdefaultwrapper');
    if (send) return send;

    send = document.getElementsByClassName('_mcp_W1');
    if (send.length == 0) return;

    return send[0];
}

function get_send_mail_elem() {
    return get_send_mail_elem_gmail() || get_send_mail_elem_outlook();
}

function encrypt_email() {
    var send = get_send_mail_elem();
    if (!send) return;

    var text = send.innerHTML;
    if (text.startsWith(header)) return;

    return encrypt_txt(text, password).then(function (enc_txt) {
        send.innerHTML = header + enc_txt;
        return new Promise(function (resolve, reject) {
            resolve();
        });
    });
}

function get_send_button_gmail() {
    var send = document.getElementsByClassName('T-I J-J5-Ji aoO T-I-atl L3');
    if (send.length == 0) return;

    return send[0];
}

function get_send_button_outlook() {
    var send = document.getElementsByClassName('_mcp_Z1');
    if (send.length == 0) return;

    for (var i = 0; i < send.length; i++) {
        if (send[i].innerText == "Send") {
            return send[i];
        }
    }
}

function get_send_button() {
    return get_send_button_gmail() || get_send_button_outlook();
}

function attach_on_send() {
    var send = get_send_button();
    if (!send) return;

    if (send.getAttribute("attached")) return;
    send.setAttribute("attached", true);

    var triggered = false;
    send.addEventListener("click", function (e) {
        if (triggered) {
            triggered = false;
            return;
        }
        e.stopImmediatePropagation();

        encrypt_email().then(function () {
            triggered = true;
            send.click();
        });
    }, true);
}

function get_mail_elem_gmail() {
    var msg = document.getElementsByClassName('a3s aXjCH');
    if (msg.length == 0) return;

    return msg[0].childNodes[0];
}

function get_mail_elem_outlook() {
    return document.getElementById('x_divtagdefaultwrapper');
}

function get_mail_elem() {
    return get_mail_elem_gmail() || get_mail_elem_outlook();
}

function decrypt_email() {
    var msg = get_mail_elem();
    if (!msg) return;

    var text = msg.innerHTML.replace(/(<wbr>|\n)/g, '');
    if (!text.startsWith(header)) return;

    return decrypt_txt(text.slice(header.length), password).then(function (dec_txt) {
        msg.innerHTML = dec_txt;
        return new Promise(function (resolve, reject) {
            resolve();
        });
    });
}

chrome.runtime.onMessage.addListener(function () {
    encrypt_email();
    decrypt_email();
});

document.addEventListener("DOMSubtreeModified", function () {
    attach_on_send();
    decrypt_email();
});
