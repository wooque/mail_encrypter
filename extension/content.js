function hex2ua(h) {
    let ua = new Uint8Array(h.length / 2);
    for (let i = 0; i < h.length - 1; i += 2) {
        ua[i / 2] = parseInt(h.slice(i, i + 2), 16);
    }
    return ua;
}

function ua2hex(ua) {
    if (!(ua instanceof Uint8Array)) {
        ua = new Uint8Array(ua);
    }
    let hex = "";
    for (let i = 0; i < ua.length; i++) {
        hex += (ua[i] < 16 ? "0" : "") + ua[i].toString(16);
    }
    return hex;
}

function generate_key(source) {
    if (source) {
        let src_bytes = new TextEncoder().encode(source);
        return crypto.subtle.digest({name: "SHA-256"}, src_bytes).then(function (data) {
            return crypto.subtle.importKey("raw", data, {name: "AES-CBC"}, false, ["encrypt", "decrypt"])
        });
    } else {
        return crypto.subtle.generateKey({name: "AES-CBC", length: 256}, true, ["encrypt", "decrypt"]);
    }
}

function encrypt(data, password) {
    let iv = crypto.getRandomValues(new Uint8Array(16));
    return generate_key(password).then(function (key) {
        return crypto.subtle.encrypt({name: "AES-CBC", iv: iv}, key, data)
            .then(function (encrypted_data) {
                encrypted_data = new Uint8Array(encrypted_data);
                let enc_result = new Uint8Array(16 + encrypted_data.length);
                enc_result.set(iv);
                enc_result.set(encrypted_data, 16);
                return new Promise(function (resolve, reject) {
                    resolve(ua2hex(enc_result));
                });
            });
    });
}

function decrypt(data, password) {
    data = hex2ua(data);
    let iv = data.slice(0, 16);
    data = data.slice(16);

    return generate_key(password).then(function (key) {
        return crypto.subtle.decrypt({name: "AES-CBC", iv: iv}, key, data)
            .then(function (decrypted) {
                return new Promise(function (resolve, reject) {
                    resolve(new Uint8Array(decrypted));
                });
            })
    });
}

function private_decrypt(data, private_key) {
    data = hex2ua(data);
    return crypto.subtle.decrypt({name: "RSA-OAEP"}, private_key, data).then(function (dec_data) {
        return new Promise(function (resolve, reject) {
            dec_data = new TextDecoder().decode(new Uint8Array(dec_data));
            resolve(dec_data);
        });
    });
}

function public_encrypt(txt, public_key) {
    txt = new TextEncoder().encode(txt);
    return crypto.subtle.encrypt({name: "RSA-OAEP"}, public_key, txt).then(function (enc_data) {
        return new Promise(function (resolve, reject) {
            resolve(ua2hex(enc_data));
        });
    });
}

function json_ajax(options) {
    return new Promise(function (resolve, reject) {
        let method = options.method || "GET";
        let data = options.data || null;
        if (data) {
            data = JSON.stringify(data);
        }

        let xhr = new XMLHttpRequest();
        xhr.open(method, options.url);

        for (let h in options.headers || {}) {
            xhr.setRequestHeader(h, options.headers[h]);
        }

        xhr.onreadystatechange = function() {
            if (xhr.readyState === XMLHttpRequest.DONE) {
                if (xhr.status === 200) {
                    var resp = {};
                    if (xhr.responseText) {
                        resp = JSON.parse(xhr.responseText);
                    }
                    resolve(resp);
                } else {
                    reject('There was a problem with the request.');
                }
            }
        };
        xhr.send(data);
    });
}

const api_url = "http://localhost:8080";

function login(email, password) {
    return json_ajax({
        method: "POST",
        url: api_url + "/auth",
        data: {email: email, password: password}
    });
}

function init_keys(user) {
    if (user.public_key) {
        let p1 = crypto.subtle.importKey("spki", hex2ua(user.public_key), {name: "RSA-OAEP", hash: {name: "SHA-256"}},
            false, ["encrypt"]);
        let p2 = decrypt(user.private_key, user.password).then(function (dec_key) {
            return crypto.subtle.importKey("pkcs8", dec_key, {name: "RSA-OAEP", hash: {name: "SHA-256"}},
                false, ["decrypt"]);
        });

        Promise.all([p1, p2]).then(function (result) {
            user.public_key = result[0];
            user.private_key = result[1];
            return new Promise(function (resolve, reject) {
                resolve(user);
            });
        });
    } else {
        const pub_exp = new Uint8Array([0x01, 0x00, 0x01]);
        crypto.subtle.generateKey({
            name: "RSA-OAEP", modulusLength: 2048, publicExponent: pub_exp,
            hash: {name: "SHA-256"}
        }, true, ["encrypt", "decrypt"])
            .then(function (key) {
                user.private_key = key.privateKey;
                user.public_key = key.publicKey;

                let p1 = crypto.subtle.exportKey("spki", user.public_key);
                let p2 = crypto.subtle.exportKey("pkcs8", user.private_key).then(function (key_data) {
                    return encrypt(key_data, user.password);
                });

                Promise.all([p1, p2]).then(function (result) {
                    json_ajax({
                        method: "POST",
                        url: api_url + "/create",
                        data: {email: user.email, password: user.password, 
                               public_key: ua2hex(result[0]), private_key: result[1]},
                        headers: {Authorization: "Bearer " + user.token}
                    }).then(function (resp) {
                        user.key_id = resp.id;
                        return new Promise(function (resolve, reject) {
                            resolve(user);
                        });
                    })
                });
            });
    }
}

function get_users_keys(users) {
    let params = "";
    for (let i = 0; i < users.length; i++) {
        if (params) {
            params += "&";
        }
        params += "users=" + encodeURIComponent(users[i]);
    }
    return json_ajax({
        url: api_url + "/keys?" + params,
        params: {users: users},
        headers: {Authorization: "Bearer " + user.token}
    }).then(function (raw_keys) {
        let ps = [];
        for (let k in raw_keys) {
            let p = crypto.subtle.importKey("spki", hex2ua(raw_keys[k]), {name: "RSA-OAEP", hash: {name: "SHA-256"}},
                                            false, ["encrypt"]);
            ps.push(p);
        }
        return Promise.all(ps).then(function (keys) {
            let ret_keys = {};
            let i = 0;
            for (let k in raw_keys) {
                ret_keys[k] = keys[i];
                i++;
            }
            return new Promise(function (resolve, reject) {
                resolve(ret_keys);
            });
        });
    })
}

const header = "MailEncrypter encrypted ";

function get_send_mail_elem_gmail() {
    let send = document.getElementsByClassName('Am Al editable LW-avf');
    if (send.length == 0) return;

    let send_users = document.getElementsByClassName('vN bfK a3q');
    if (send_users.length == 0) return;
    let send_emails = [];
    for (let i = 0; i < send_users.length; i++) {
        send_emails.push(send_users[i].getAttribute("email"));
    }
    return [send[0], send_emails];
}

function get_send_mail_elem_outlook() {
    let send = document.getElementById('divtagdefaultwrapper');
    if (send) return send;

    send = document.getElementsByClassName('_mcp_W1');
    if (send.length == 0) return;

    return [send[0], []];
}

function get_send_mail_elem() {
    return get_send_mail_elem_gmail() || get_send_mail_elem_outlook();
}

function encrypt_email() {
    let send_mail= get_send_mail_elem();
    let send_text = send_mail[0];
    if (!send_text) return;

    let send_users = send_mail[1];
    if (send_users.length == 0) return;


    let text = send_text.innerHTML;
    if (text.startsWith(header)) return;

    // TODO: for now only sending to one user is supported
    return get_users_keys([send_users[0]]).then(function (public_keys) {
        return public_encrypt(text, public_keys[send_users[0]]).then(function (enc_txt) {
            send_text.innerHTML = header + enc_txt;
            return new Promise(function (resolve, reject) {
                resolve();
            });
        });
    })
}

function get_send_button_gmail() {
    let send = document.getElementsByClassName('T-I J-J5-Ji aoO T-I-atl L3');
    if (send.length == 0) return;

    return send[0];
}

function get_send_button_outlook() {
    let send = document.getElementsByClassName('_mcp_Z1');
    if (send.length == 0) return;

    for (let i = 0; i < send.length; i++) {
        if (send[i].innerText == "Send") {
            return send[i];
        }
    }
}

function get_send_button() {
    return get_send_button_gmail() || get_send_button_outlook();
}

function attach_on_send() {
    let send = get_send_button();
    if (!send) return;

    if (send.getAttribute("attached")) return;
    send.setAttribute("attached", true);

    let triggered = false;
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
    let msg = document.getElementsByClassName('a3s aXjCH');
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
    let msg = get_mail_elem();
    if (!msg) return;

    let text = msg.innerHTML.replace(/(<wbr>|\n)/g, '');
    if (!text.startsWith(header)) return;

    return private_decrypt(text.slice(header.length), user.private_key).then(function (dec_txt) {
        msg.innerHTML = dec_txt;
        return new Promise(function (resolve, reject) {
            resolve();
        });
    });
}

let user = {email: "wooque@gmail.com", password: "pass"};
login(user.email, user.password).then(function (user_data) {
    if (!user_data.error) {
        user_data.email = user.email;
        user_data.password = user.password;
        user = user_data;
    }
    init_keys(user);
});

chrome.runtime.onMessage.addListener(function () {
    encrypt_email();
    decrypt_email();
});

document.addEventListener("DOMSubtreeModified", function () {
    attach_on_send();
    decrypt_email();
});
