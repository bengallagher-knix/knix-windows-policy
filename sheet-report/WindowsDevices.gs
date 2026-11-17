/**
 * Knix Windows device inventory -> Google Sheet, with patch-status colours and ONE Slack alert.
 *
 * Add this as a NEW FILE in the Apps Script project attached to the "IT Alert Logs" sheet
 * (Extensions > Apps Script > + > Script). It does not define doGet/doPost and every name starts with
 * wd_ / kwd_ / KWD so it cannot collide with the existing alert code.
 *
 * SECRETS: none are in this file. Set them in Project Settings > Script properties:
 *   WD_ATERA_API_KEY   Atera API key (Admin > Data management > API). Read-only permissions are enough.
 *   WD_SLACK_TOKEN     xoxb- bot token with chat:write
 *   WD_SLACK_CHANNEL   Slack channel ID (C...) for the alert
 *   WD_SHEET_ID        the sheet's ID (the long string in its URL). Needed when the script is NOT bound to the sheet.
 *   WD_INGEST_KEY      a long random string you make up. Devices must send it to log WDAC events (see below).
 *
 * WDAC AUDIT EVENTS -> SHEET: each device runs Apply-KnixWdacAudit.ps1 -Mode Collect from Atera, which POSTs its
 * "would have been blocked" findings to this script's web app. They land in the tab "WDAC Audit Events", one row per
 * device + file, with serial number, Windows version, logged-in users and the user the event ran as.
 * Web app setup (Deploy > New deployment > Web app > Execute as: Me, Who has access: Anyone):
 *   - NEW standalone project (recommended, keeps the keys separate from your alert project): add this file plus
 *       function doPost(e) { return wd_ingest(e); }
 *   - or in your existing project, at the top of doPost add:
 *       if (e.parameter && e.parameter.platform === 'WDAC_AUDIT') return wd_ingest(e);
 *   The URL + WD_INGEST_KEY go in the Atera bootstrap as KNIX_SHEET_WEBHOOK / KNIX_SHEET_KEY. Requests without the
 *   key are rejected. Cell text starting with = + - @ is neutralised so a file name cannot run as a formula.
 *
 * RUN ORDER (Run menu):
 *   1. wd_probe        read-only test. Shows what the Atera API really returns. Run first.
 *   2. wd_syncDryRun   computes everything and logs it. Writes nothing, sends nothing.
 *   3. wd_sync         real run (creates/updates the tabs).
 *   4. wd_install      schedules wd_sync every 6h and wd_syncSoftware every 4h.
 *   wd_testSlack       sends one test message. wd_uninstall removes the schedules.
 *
 * STATUS COLOURS (column D, whole row coloured):
 *   CURRENT  nothing
 *   YELLOW   a newer patch level has existed for 3+ days (normal rollout lag, or age not yet known)
 *   ORANGE   30+ days behind, or on a Windows version that is out of servicing but offline
 *   RED      should have updated for sure: 9+ days behind (policy deadline 7 + grace 2) while online and
 *            checking in, or still on a Windows version that is out of servicing while online
 *   UNKNOWN  Atera gave no patch level (build.revision), so patch age cannot be judged
 *   STALE    not seen for 45+ days (probably retired). Not coloured, not alerted.
 *
 * HOW PATCH AGE IS WORKED OUT: Atera does not say when a patch level was released. So each sync records the
 * first time any device reported a given build.revision (tab "Windows Build History"). A device is "behind" when
 * a newer revision of its build exists; the clock starts when the first device reported that newer revision.
 * The very first run only creates a baseline, so ages become accurate after one patch cycle.
 *
 * SLACK: at most ONE message per run, only if (a) any device is ORANGE or RED, or (b) 25%+ of devices are
 * behind by 7+ days. The same alert is not repeated for 7 days unless the list of devices changes.
 */

var KWD = {
  TAB_DEVICES: 'Windows Devices',
  TAB_SOFTWARE: 'Windows Software',
  TAB_BUILDS: 'Windows Build History',
  TAB_EVENTS: 'WDAC Audit Events',
  EVENT_KEEP_DAYS: 90,        // WDAC event rows not seen for this long are removed
  ATERA_BASE: 'https://app.atera.com',
  PAGE_SIZE: 50,
  ONLINE_WITHIN_DAYS: 3,      // "checking in" = seen within this many days
  STALE_AFTER_DAYS: 45,
  YELLOW_AFTER_DAYS: 3,
  RED_AFTER_DAYS: 9,          // policy: deadline 7 days + grace 2 days
  ORANGE_AFTER_DAYS: 30,
  BULK_BEHIND_DAYS: 7,
  BULK_PERCENT: 25,
  BULK_MIN_DEVICES: 3,
  ALERT_REPEAT_DAYS: 7,
  SOFTWARE_BUDGET_MS: 270000, // stay under Apps Script's 6 minute limit
  SOFTWARE_BATCH: 10,
  // Tried in order against the first device. The first one that answers with a list is remembered.
  SOFTWARE_ENDPOINTS: [
    '/api/v3/agents/{id}/software',
    '/api/v3/agents/{guid}/software',
    '/api/v3/agents/{id}/installed-software',
    '/api/v3/agents/{guid}/installed-software',
    '/api/v3/agents/{id}/applications',
    '/api/v3/agents/{guid}/applications'
  ]
};

// build number -> [name, servicing ends Home/Pro, servicing ends Enterprise/Education]
// [ASSUMPTION] dates from memory of Microsoft's lifecycle pages. Verify and edit.
var KWD_BUILDS = {
  19045: ['Windows 10 22H2', '2025-10-14', '2025-10-14'],
  22000: ['Windows 11 21H2', '2023-10-10', '2024-10-08'],
  22621: ['Windows 11 22H2', '2024-10-08', '2025-10-14'],
  22631: ['Windows 11 23H2', '2025-11-11', '2026-11-10'],
  26100: ['Windows 11 24H2', '2026-10-13', '2027-10-12'],
  26200: ['Windows 11 25H2', '2027-10-12', '2028-10-10']
};

var KWD_HEADERS = [
  'Device Key', 'Serial Number', 'Device Name', 'Status', 'Status Reason', 'Windows', 'OS (Atera)', 'Build',
  'Patch Level', 'Days Behind', 'Servicing Ends', 'Online', 'Last Seen (Atera)', 'Last Reboot', 'Customer',
  'Domain', 'Manufacturer / Model', 'IP Address', 'Security Info', 'Atera Agent ID', 'Device GUID',
  'First Seen', 'Last Sync', 'Present in Current Sync'
];
var KWD_TEXT_COLS = ['Device Key', 'Serial Number', 'Build', 'Patch Level', 'Servicing Ends', 'Last Seen (Atera)',
  'Last Reboot', 'IP Address', 'Atera Agent ID', 'Device GUID', 'First Seen', 'Last Sync'];
var KWD_SW_HEADERS = ['Device Key', 'Device Name', 'Application', 'Version', 'Publisher', 'Install Date', 'Synced'];
var KWD_HIST_HEADERS = ['Build', 'Revision (UBR)', 'First Seen (UTC)', 'Baseline', 'Devices Now'];
var KWD_EV_HEADERS = [
  'Event Key', 'First Seen (UTC)', 'Last Seen (UTC)', 'Device Name', 'Serial Number', 'Device Key', 'Windows', 'Windows Build',
  'Edition', 'User (event)', 'Logged-in User(s)', 'Manufacturer / Model', 'Domain', 'Category', 'Location', 'File Path', 'Process',
  'Publisher', 'Signed', 'Signing Level', 'User-writeable', 'SHA256', 'Count', 'Policy', 'Reported At (UTC)', 'Notes'
];
var KWD_EV_TEXT_COLS = ['Event Key', 'First Seen (UTC)', 'Last Seen (UTC)', 'Serial Number', 'Device Key', 'Windows Build', 'SHA256', 'Reported At (UTC)'];

var KWD_DAY = 86400000;
var KWD_BAD_SERIAL = /^(0+|none|n\/a|na|default string|to be filled by o\.?e\.?m\.?|system serial number|serial ?number|unknown|123456789.*)$/i;

// ============================================================================ entry points
function wd_probe() {
  var j = kwd_atera_('/api/v3/agents?page=1&itemsInPage=5');
  var items = Array.isArray(j) ? j : (j.items || j.Items || []);
  Logger.log('ENVELOPE KEYS: ' + (Array.isArray(j) ? '(plain array)' : Object.keys(j).join(', ')));
  Logger.log('AGENTS ON PAGE 1: ' + items.length);
  if (!items.length) { Logger.log('No agents returned. Check the API key permissions.'); return; }
  var a = items.filter(function (x) { return /windows/i.test(JSON.stringify([x.OS, x.OSType, x.os, x.osType])); })[0] || items[0];
  var keys = Object.keys(a).sort();
  Logger.log('KEYS: ' + keys.join(', '));
  Logger.log('SECURITY-LOOKING KEYS: ' + (keys.filter(function (k) { return KWD_SEC_RE.test(k); }).join(', ') || '(none)'));
  Logger.log('FIRST WINDOWS AGENT (full JSON): ' + JSON.stringify(a));
  var lc = kwd_lc_(a);
  var id = kwd_pick_(lc, ['AgentID', 'AgentId', 'Id']);
  var guid = kwd_pick_(lc, ['DeviceGuid', 'DeviceGUID']);
  KWD.SOFTWARE_ENDPOINTS.forEach(function (t) { kwd_logTry_(t, id, guid); });
  kwd_logTry_('/api/v3/agents/{guid}/installed-patches?page=1&itemsInPage=3', id, guid);
  kwd_logTry_('/api/v3/agents/{guid}/available-patches?page=1&itemsInPage=3', id, guid);
  Logger.log('Done. For sharing, the KEYS and ENDPOINT lines are enough (no device data needed).');
}

// Use this when wd_probe gets HTTP 401. It tries the key a few ways and logs only status codes and the SHAPE of the key
// (length, spaces, quotes), never the key itself.
function wd_probeAuth() {
  var key = kwd_prop_('WD_ATERA_API_KEY');
  Logger.log('KEY SHAPE: length ' + key.length + ', has space ' + /\s/.test(key) + ', has quote ' + /["']/.test(key) +
    ', starts with "Bearer" ' + /^bearer/i.test(key) + ', only hex/letters/digits/-/_ ' + /^[A-Za-z0-9_\-]+$/.test(key));
  var tests = [
    ['agents, X-API-KEY', '/api/v3/agents?page=1&itemsInPage=1', { 'X-API-KEY': key }],
    ['agents no params, X-API-KEY', '/api/v3/agents', { 'X-API-KEY': key }],
    ['alerts, X-API-KEY', '/api/v3/alerts?page=1&itemsInPage=1', { 'X-API-KEY': key }],
    ['customers, X-API-KEY', '/api/v3/customers?page=1&itemsInPage=1', { 'X-API-KEY': key }],
    ['agents, no key at all (control)', '/api/v3/agents?page=1&itemsInPage=1', {}],
    ['agents, Authorization Bearer', '/api/v3/agents?page=1&itemsInPage=1', { 'Authorization': 'Bearer ' + key }]
  ];
  tests.forEach(function (t) {
    try {
      var h = t[2];
      h['Accept'] = 'application/json';
      var r = UrlFetchApp.fetch(KWD.ATERA_BASE + t[1], { headers: h, muteHttpExceptions: true });
      var hd = r.getHeaders();
      Logger.log(t[0] + ' -> HTTP ' + r.getResponseCode() + ' | WWW-Authenticate: ' + (hd['WWW-Authenticate'] || hd['www-authenticate'] || '(none)') +
        ' | body: ' + r.getContentText().substring(0, 150));
    } catch (e) { Logger.log(t[0] + ' -> error ' + e.message); }
  });
}

function wd_syncDryRun() { kwd_run_(true); }
function wd_sync() { kwd_run_(false); }

function wd_install() {
  wd_uninstall();
  ScriptApp.newTrigger('wd_sync').timeBased().everyHours(6).create();
  ScriptApp.newTrigger('wd_syncSoftware').timeBased().everyHours(4).create();
  Logger.log('Scheduled: wd_sync every 6 hours, wd_syncSoftware every 4 hours.');
}

function wd_uninstall() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    var f = t.getHandlerFunction();
    if (f === 'wd_sync' || f === 'wd_syncSoftware') ScriptApp.deleteTrigger(t);
  });
}

function wd_testSlack() {
  kwd_slack_(':white_check_mark: Windows device report: test message. If you can read this, Slack alerts work.');
  Logger.log('Test message sent.');
}

// ============================================================================ main sync
function kwd_run_(dryRun) {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) { Logger.log('Another run is in progress, skipping.'); return; }
  try {
    var ss = kwd_ss_();
    var now = new Date();
    var agents = kwd_fetchAgents_();
    var byKey = {};
    agents.map(kwd_normalize_).filter(function (d) { return d.isWindows; }).forEach(function (d) {
      var prev = byKey[d.key];
      if (!prev || (d.lastSeen && (!prev.lastSeen || d.lastSeen > prev.lastSeen))) byKey[d.key] = d;
    });
    var devices = Object.keys(byKey).map(function (k) { return byKey[k]; });
    if (!devices.length) throw new Error('Atera returned no Windows devices (' + agents.length + ' agents in total). Sheet left untouched.');

    if (!dryRun) kwd_ensureSheets_(ss);
    var hist = kwd_loadHistory_(dryRun ? null : ss);
    devices.forEach(function (d) { if (d.build && d.ubr !== null) hist.observe(d.build, d.ubr, now); });
    devices.forEach(function (d) { kwd_evaluate_(d, now, hist); });

    var counts = {};
    devices.forEach(function (d) { counts[d.status] = (counts[d.status] || 0) + 1; });
    Logger.log('Windows devices: ' + devices.length + ' of ' + agents.length + ' agents. Status: ' + JSON.stringify(counts));
    if (dryRun) {
      devices.filter(function (d) { return d.level >= 1; }).slice(0, 40).forEach(function (d) {
        Logger.log('  ' + d.status + '  ' + d.name + '  ' + d.reason);
      });
      Logger.log('Dry run: nothing written, nothing sent.');
      return;
    }
    kwd_saveHistory_(ss, hist, devices);
    kwd_upsertDevices_(ss, devices, now);
    kwd_pruneEvents_(ss, now);
    kwd_maybeAlert_(ss, devices, now);
  } finally {
    lock.releaseLock();
  }
}

function kwd_ss_() {
  var id = PropertiesService.getScriptProperties().getProperty('WD_SHEET_ID');
  return id ? SpreadsheetApp.openById(id) : SpreadsheetApp.getActiveSpreadsheet();
}

// ============================================================================ Atera
function kwd_prop_(name) {
  var v = PropertiesService.getScriptProperties().getProperty(name);
  v = v ? String(v).trim() : '';      // a stray space or newline from copy/paste would make Atera answer 401
  if (!v) throw new Error('Missing script property ' + name + ' (Project Settings > Script properties).');
  return v;
}

function kwd_fetch_(url, options) {
  var opts = options || {};
  opts.muteHttpExceptions = true;
  var resp;
  for (var i = 0; i < 4; i++) {
    resp = UrlFetchApp.fetch(url, opts);
    var code = resp.getResponseCode();
    if (code !== 429 && code < 500) return resp;
    Utilities.sleep(2000 * Math.pow(2, i));
  }
  return resp;
}

function kwd_ateraOpts_() { return { headers: { 'X-API-KEY': kwd_prop_('WD_ATERA_API_KEY'), 'Accept': 'application/json' } }; }

function kwd_atera_(path) {
  var resp = kwd_fetch_(KWD.ATERA_BASE + path, kwd_ateraOpts_());
  var code = resp.getResponseCode();
  if (code !== 200) throw new Error('Atera ' + path + ' returned HTTP ' + code + ': ' + resp.getContentText().substring(0, 200));
  return JSON.parse(resp.getContentText());
}

function kwd_fetchAgents_() {
  var all = [];
  var page = 1;
  var totalPages = 1;
  do {
    var j = kwd_atera_('/api/v3/agents?page=' + page + '&itemsInPage=' + KWD.PAGE_SIZE);
    var items = Array.isArray(j) ? j : (j.items || j.Items || []);
    all = all.concat(items);
    totalPages = Array.isArray(j) ? 1 : (j.totalPages || j.TotalPages || 1);
    if (!items.length) break;
    page++;
  } while (page <= totalPages && page < 500);
  return all;
}

function kwd_logTry_(template, id, guid) {
  var path = template.replace('{id}', id).replace('{guid}', guid);
  try {
    var resp = kwd_fetch_(KWD.ATERA_BASE + path, kwd_ateraOpts_());
    var body = resp.getContentText();
    Logger.log('ENDPOINT ' + template + ' -> HTTP ' + resp.getResponseCode() + (resp.getResponseCode() === 200 ? ' | ' + body.substring(0, 300) : ''));
  } catch (e) { Logger.log('ENDPOINT ' + template + ' -> error ' + e.message); }
}

// ============================================================================ normalise
var KWD_SEC_RE = /(antivir|antimalw|malware|firewall|bitlock|encrypt|defender|security|tpm|secureboot|patch)/i;

function kwd_lc_(obj) {
  var m = {};
  Object.keys(obj).forEach(function (k) { m[k.toLowerCase()] = obj[k]; });
  return m;
}

function kwd_pick_(lc, names) {
  for (var i = 0; i < names.length; i++) {
    var v = lc[names[i].toLowerCase()];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return '';
}

function kwd_date_(v) {
  if (!v) return null;
  var d = new Date(v);
  return isNaN(d.getTime()) ? null : d;
}

function kwd_normalize_(a) {
  var lc = kwd_lc_(a);
  var serial = String(kwd_pick_(lc, ['VendorSerialNumber', 'SerialNumber', 'BiosSerialNumber'])).trim();
  var guid = String(kwd_pick_(lc, ['DeviceGuid'])).trim();
  var agentId = String(kwd_pick_(lc, ['AgentID', 'AgentId', 'Id'])).trim();
  var goodSerial = serial && !KWD_BAD_SERIAL.test(serial);
  var osStr = String(kwd_pick_(lc, ['OS', 'OSName', 'OperatingSystem'])).trim();
  var osType = String(kwd_pick_(lc, ['OSType'])).trim();

  var buildText = [kwd_pick_(lc, ['OSBuild', 'BuildNumber']), kwd_pick_(lc, ['OSVersion'])].join(' ');
  var withUbr = buildText.match(/\b(\d{5})\.(\d{1,6})\b/);
  var plain = buildText.match(/\b(\d{5})\b/);
  var build = withUbr ? Number(withUbr[1]) : (plain ? Number(plain[1]) : null);
  var ubr = withUbr ? Number(withUbr[2]) : null;

  var ips = kwd_pick_(lc, ['IpAddresses', 'IPAddresses', 'ReportedFromIP']);
  if (Array.isArray(ips)) ips = ips.join(', ');

  var sec = [];
  Object.keys(a).forEach(function (k) {
    var v = a[k];
    if (!KWD_SEC_RE.test(k) || v === null || v === '' || typeof v === 'object') return;
    sec.push(k + ': ' + v);
  });

  var model = [kwd_pick_(lc, ['Vendor']), kwd_pick_(lc, ['VendorBrandModel', 'Model'])].filter(String).join(' ');
  var onlineRaw = kwd_pick_(lc, ['Online']);

  return {
    key: goodSerial ? 'SERIAL:' + serial : (guid ? 'GUID:' + guid : 'AGENT:' + agentId),
    serial: goodSerial ? serial : (serial ? serial + ' (not unique)' : ''),
    name: String(kwd_pick_(lc, ['MachineName', 'AgentName', 'SystemName'])),
    isWindows: /windows/i.test(osStr + ' ' + osType),
    os: osStr,
    osType: osType,
    edition: /enterprise|education/i.test(osStr) ? 'ent' : 'pro',
    build: build,
    ubr: ubr,
    lastSeen: kwd_date_(kwd_pick_(lc, ['LastSeen'])),
    lastReboot: kwd_date_(kwd_pick_(lc, ['LastRebootTime', 'LastReboot'])),
    onlineFlag: onlineRaw === true || String(onlineRaw).toLowerCase() === 'true',
    customer: String(kwd_pick_(lc, ['CustomerName'])),
    domain: String(kwd_pick_(lc, ['Domain', 'DomainName'])),
    model: model,
    ip: String(ips),
    security: sec.join('; '),
    agentId: agentId,
    guid: guid,
    // filled by kwd_evaluate_
    status: 'UNKNOWN', level: 0, reason: '', daysBehind: null, servicingEnds: '', windowsName: ''
  };
}

// ============================================================================ build history
function kwd_loadHistory_(ss) {
  var hist = {
    map: {},
    wasEmpty: true,
    observe: function (build, ubr, now) {
      var list = this.map[build] || (this.map[build] = []);
      for (var i = 0; i < list.length; i++) if (list[i].ubr === ubr) return;
      list.push({ ubr: ubr, first: now, baseline: this.wasEmpty });
    },
    nextNewer: function (build, ubr) {
      var list = (this.map[build] || []).filter(function (e) { return e.ubr > ubr; });
      list.sort(function (x, y) { return x.ubr - y.ubr; });
      return list.length ? list[0] : null;
    }
  };
  if (!ss) return hist;
  var sh = ss.getSheetByName(KWD.TAB_BUILDS);
  var last = sh ? sh.getLastRow() : 0;
  if (last > 1) {
    var rows = sh.getRange(2, 1, last - 1, 4).getValues();
    rows.forEach(function (r) {
      if (r[0] === '' || r[1] === '') return;
      var list = hist.map[Number(r[0])] || (hist.map[Number(r[0])] = []);
      list.push({ ubr: Number(r[1]), first: kwd_date_(r[2]) || new Date(), baseline: r[3] === true || String(r[3]).toUpperCase() === 'TRUE' });
    });
    hist.wasEmpty = rows.length === 0;
  }
  return hist;
}

function kwd_saveHistory_(ss, hist, devices) {
  var sh = ss.getSheetByName(KWD.TAB_BUILDS);
  var counts = {};
  devices.forEach(function (d) { if (d.build && d.ubr !== null) counts[d.build + '.' + d.ubr] = (counts[d.build + '.' + d.ubr] || 0) + 1; });
  var rows = [];
  Object.keys(hist.map).forEach(function (b) {
    hist.map[b].forEach(function (e) { rows.push([Number(b), e.ubr, e.first.toISOString(), e.baseline, counts[b + '.' + e.ubr] || 0]); });
  });
  rows.sort(function (x, y) { return x[0] - y[0] || x[1] - y[1]; });
  var old = Math.max(sh.getLastRow() - 1, 0);
  if (old > 0) sh.getRange(2, 1, old, KWD_HIST_HEADERS.length).clearContent();
  if (rows.length) sh.getRange(2, 1, rows.length, KWD_HIST_HEADERS.length).setValues(rows);
}

// ============================================================================ status
function kwd_evaluate_(d, now, hist) {
  var reasons = [];
  var level = 0;
  var info = d.build ? KWD_BUILDS[d.build] : null;
  d.windowsName = info ? info[0] : (d.build ? 'Windows build ' + d.build : d.os);
  var seenAgo = d.lastSeen ? (now - d.lastSeen) / KWD_DAY : null;
  var online = d.onlineFlag || (seenAgo !== null && seenAgo <= KWD.ONLINE_WITHIN_DAYS);

  if (seenAgo !== null && seenAgo > KWD.STALE_AFTER_DAYS) {
    d.status = 'STALE'; d.level = 0; d.reason = 'not seen for ' + Math.floor(seenAgo) + ' days';
    d.servicingEnds = info ? info[d.edition === 'ent' ? 2 : 1] : '';
    return;
  }

  if (info) {
    d.servicingEnds = info[d.edition === 'ent' ? 2 : 1];
    if (new Date(d.servicingEnds + 'T23:59:59Z') < now) {
      level = online ? 3 : 2;
      reasons.push(info[0] + ' is out of servicing since ' + d.servicingEnds + ' (no more security patches)');
    }
  } else if (d.build) {
    reasons.push('build ' + d.build + ' is not in the servicing table');
  }

  var patchKnown = d.build && d.ubr !== null;
  if (patchKnown) {
    var newer = hist.nextNewer(d.build, d.ubr);
    if (newer) {
      if (newer.baseline) {
        level = Math.max(level, 1);
        reasons.push('behind the newest patch level seen in the fleet (age not known yet)');
      } else {
        var days = Math.floor((now - newer.first) / KWD_DAY);
        d.daysBehind = days;
        if (online && days > KWD.RED_AFTER_DAYS) {
          level = Math.max(level, 3);
          reasons.push(days + ' days behind while online and checking in (policy forces updates by day ' + KWD.RED_AFTER_DAYS + ')');
        } else if (days > KWD.ORANGE_AFTER_DAYS) {
          level = Math.max(level, 2);
          reasons.push(days + ' days behind' + (online ? '' : ', device offline'));
        } else if (days >= KWD.YELLOW_AFTER_DAYS) {
          level = Math.max(level, 1);
          reasons.push(days + ' days behind');
        }
      }
    }
  } else if (level === 0) {
    reasons.push('Atera did not report a patch level (build.revision)');
  }

  d.level = level;
  d.status = level === 3 ? 'RED' : level === 2 ? 'ORANGE' : level === 1 ? 'YELLOW' : (patchKnown ? 'CURRENT' : 'UNKNOWN');
  d.reason = reasons.join('; ');
}

// ============================================================================ sheets
function kwd_colLetter_(n) {
  var s = '';
  while (n > 0) { var m = (n - 1) % 26; s = String.fromCharCode(65 + m) + s; n = Math.floor((n - m) / 26); }
  return s;
}

function kwd_headerRow_(sh, headers) {
  var cur = sh.getRange(1, 1, 1, headers.length).getValues()[0];
  if (cur.join('|') !== headers.join('|')) sh.getRange(1, 1, 1, headers.length).setValues([headers]);
  sh.getRange(1, 1, 1, headers.length).setFontWeight('bold');
  sh.setFrozenRows(1);
}

function kwd_ensureSheets_(ss) {
  var dev = ss.getSheetByName(KWD.TAB_DEVICES) || ss.insertSheet(KWD.TAB_DEVICES);
  kwd_headerRow_(dev, KWD_HEADERS);
  var rows = Math.max(dev.getMaxRows() - 1, 1);
  KWD_TEXT_COLS.forEach(function (h) { dev.getRange(2, KWD_HEADERS.indexOf(h) + 1, rows, 1).setNumberFormat('@'); });

  var width = KWD_HEADERS.length;
  var range = dev.getRange(2, 1, rows, width);
  var statusCol = kwd_colLetter_(KWD_HEADERS.indexOf('Status') + 1);
  var presentCol = kwd_colLetter_(KWD_HEADERS.indexOf('Present in Current Sync') + 1);
  function colour(label, bg) {
    return SpreadsheetApp.newConditionalFormatRule().whenFormulaSatisfied('=$' + statusCol + '2="' + label + '"').setBackground(bg).setRanges([range]).build();
  }
  var grey = SpreadsheetApp.newConditionalFormatRule().whenFormulaSatisfied('=AND($A2<>"",$' + presentCol + '2=FALSE)').setFontColor('#999999').setRanges([range]).build();
  dev.setConditionalFormatRules([colour('RED', '#ea9999'), colour('ORANGE', '#f6b26b'), colour('YELLOW', '#ffe599'), grey]);

  var hist = ss.getSheetByName(KWD.TAB_BUILDS) || ss.insertSheet(KWD.TAB_BUILDS);
  kwd_headerRow_(hist, KWD_HIST_HEADERS);
  hist.getRange(2, 3, Math.max(hist.getMaxRows() - 1, 1), 1).setNumberFormat('@');
}

function kwd_fmt_(ss, d) {
  return d ? Utilities.formatDate(d, ss.getSpreadsheetTimeZone(), 'yyyy-MM-dd HH:mm:ss') : '';
}

function kwd_upsertDevices_(ss, devices, now) {
  var sh = ss.getSheetByName(KWD.TAB_DEVICES);
  var width = KWD_HEADERS.length;
  var nowStr = kwd_fmt_(ss, now);
  var last = sh.getLastRow();
  var existing = last > 1 ? sh.getRange(2, 1, last - 1, width).getValues() : [];
  var cur = {};
  devices.forEach(function (d) { cur[d.key] = d; });

  var iFirst = KWD_HEADERS.indexOf('First Seen');
  var iPresent = KWD_HEADERS.indexOf('Present in Current Sync');
  var seen = {};
  var out = [];

  existing.forEach(function (r) {
    var key = String(r[0]);
    if (!key) return;
    seen[key] = true;
    var d = cur[key];
    var first = r[iFirst] instanceof Date ? kwd_fmt_(ss, r[iFirst]) : String(r[iFirst] || nowStr);
    if (d) { out.push(kwd_toRow_(ss, d, first, nowStr, true)); }
    else { var row = r.slice(); row[iPresent] = false; out.push(row); }
  });
  devices.forEach(function (d) { if (!seen[d.key]) out.push(kwd_toRow_(ss, d, nowStr, nowStr, true)); });

  if (sh.getMaxRows() < out.length + 1) sh.insertRowsAfter(sh.getMaxRows(), out.length + 1 - sh.getMaxRows());
  var old = Math.max(last - 1, 0);
  if (old > 0) sh.getRange(2, 1, old, width).clearContent();
  if (out.length) sh.getRange(2, 1, out.length, width).setValues(out);
  Logger.log('Devices tab updated: ' + out.length + ' rows (' + devices.length + ' present in this sync).');
}

function kwd_toRow_(ss, d, first, nowStr, present) {
  var map = {
    'Device Key': d.key, 'Serial Number': d.serial, 'Device Name': d.name, 'Status': d.status, 'Status Reason': d.reason,
    'Windows': d.windowsName, 'OS (Atera)': d.os, 'Build': d.build === null ? '' : String(d.build),
    'Patch Level': d.ubr === null ? '' : String(d.build) + '.' + d.ubr,
    'Days Behind': d.daysBehind === null ? '' : d.daysBehind, 'Servicing Ends': d.servicingEnds,
    'Online': d.onlineFlag, 'Last Seen (Atera)': kwd_fmt_(ss, d.lastSeen), 'Last Reboot': kwd_fmt_(ss, d.lastReboot),
    'Customer': d.customer, 'Domain': d.domain, 'Manufacturer / Model': d.model, 'IP Address': d.ip,
    'Security Info': d.security, 'Atera Agent ID': d.agentId, 'Device GUID': d.guid,
    'First Seen': first, 'Last Sync': nowStr, 'Present in Current Sync': present
  };
  return KWD_HEADERS.map(function (h) { return map[h]; });
}

// ============================================================================ Slack (one message)
function kwd_slack_(text) {
  var resp = kwd_fetch_('https://slack.com/api/chat.postMessage', {
    method: 'post',
    contentType: 'application/json; charset=utf-8',
    headers: { Authorization: 'Bearer ' + kwd_prop_('WD_SLACK_TOKEN') },
    payload: JSON.stringify({ channel: kwd_prop_('WD_SLACK_CHANNEL'), text: text, unfurl_links: false })
  });
  var j = JSON.parse(resp.getContentText());
  if (!j.ok) throw new Error('Slack refused the message: ' + j.error);
}

function kwd_maybeAlert_(ss, devices, now) {
  var props = PropertiesService.getScriptProperties();
  var considered = devices.filter(function (d) { return d.status !== 'STALE'; });
  var superOld = considered.filter(function (d) { return d.status === 'ORANGE' || d.status === 'RED'; });
  var behind = considered.filter(function (d) {
    return d.level >= 2 || (d.level === 1 && d.daysBehind !== null && d.daysBehind >= KWD.BULK_BEHIND_DAYS);
  });
  var bulk = behind.length >= KWD.BULK_MIN_DEVICES && considered.length > 0 && (behind.length / considered.length * 100) >= KWD.BULK_PERCENT;

  if (!bulk && !superOld.length) {
    props.deleteProperty('WD_ALERT_SIG'); props.deleteProperty('WD_ALERT_AT');
    return;
  }
  var names = superOld.map(function (d) { return d.name; }).sort();
  var sig = (bulk ? 'BULK|' : '') + names.join(',');
  var lastSig = props.getProperty('WD_ALERT_SIG');
  var lastAt = Number(props.getProperty('WD_ALERT_AT') || 0);
  if (sig === lastSig && (now.getTime() - lastAt) < KWD.ALERT_REPEAT_DAYS * KWD_DAY) return;

  var lines = [':warning: *Windows patching needs attention*'];
  if (bulk) lines.push(behind.length + ' of ' + considered.length + ' Windows devices (' + Math.round(behind.length / considered.length * 100) + '%) are ' + KWD.BULK_BEHIND_DAYS + '+ days behind on updates.');
  if (superOld.length) {
    superOld.sort(function (x, y) { return y.level - x.level; });
    lines.push(superOld.length + ' device' + (superOld.length === 1 ? ' is' : 's are') + ' badly out of date:');
    superOld.slice(0, 10).forEach(function (d) { lines.push('• ' + (d.status === 'RED' ? ':red_circle:' : ':large_orange_circle:') + ' *' + d.name + '* ' + d.reason); });
    if (superOld.length > 10) lines.push('...and ' + (superOld.length - 10) + ' more');
  }
  lines.push('<' + ss.getUrl() + '|Open the Windows Devices sheet>');
  kwd_slack_(lines.join('\n'));
  props.setProperty('WD_ALERT_SIG', sig);
  props.setProperty('WD_ALERT_AT', String(now.getTime()));
  Logger.log('Slack alert sent.');
}

// ============================================================================ WDAC audit events from devices
// Web app entry. Call this from doPost (see the header). Returns JSON text.
function wd_ingest(e) {
  function out(o) { return ContentService.createTextOutput(JSON.stringify(o)).setMimeType(ContentService.MimeType.JSON); }
  try {
    var body = JSON.parse((e && e.postData && e.postData.contents) || '{}');
    var expected = PropertiesService.getScriptProperties().getProperty('WD_INGEST_KEY');
    if (!expected || body.key !== expected) return out({ ok: false, error: 'unauthorized' });
    if (!body.device || !Array.isArray(body.events)) return out({ ok: false, error: 'bad payload' });
    var lock = LockService.getScriptLock();
    lock.waitLock(60000);
    try { var n = kwd_ingestEvents_(kwd_ss_(), body); } finally { lock.releaseLock(); }
    return out({ ok: true, rows: n });
  } catch (err) {
    return out({ ok: false, error: String(err && err.message ? err.message : err) });
  }
}

// Spreadsheets treat text starting with = + - @ as a formula. File names and process names are attacker-controlled.
function kwd_safe_(v) {
  var s = (v === null || v === undefined) ? '' : String(v);
  if (s.length > 2000) s = s.substring(0, 2000);
  return /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
}

// Pure function: merges one device's findings into the table (array of rows, no header). One row per device + file.
function kwd_mergeEvents_(table, payload, nowStr) {
  var C = {};
  KWD_EV_HEADERS.forEach(function (h, i) { C[h] = i; });
  var idx = {};
  table.forEach(function (r, i) { idx[String(r[0])] = i; });
  var dev = payload.device || {};
  var devKey = kwd_safe_(dev.deviceKey);

  payload.events.forEach(function (ev) {
    var path = kwd_safe_(ev.path);
    if (!path) return;
    var key = devKey + '|' + path.toLowerCase();
    var row;
    if (idx[key] === undefined) {
      row = [];
      for (var k = 0; k < KWD_EV_HEADERS.length; k++) row.push('');
      row[C['Event Key']] = key;
      row[C['First Seen (UTC)']] = kwd_safe_(ev.firstSeen);
      row[C['Last Seen (UTC)']] = kwd_safe_(ev.lastSeen);
      row[C['Count']] = 0;
      table.push(row);
      idx[key] = table.length - 1;
    } else {
      row = table[idx[key]];
    }
    var first = kwd_safe_(ev.firstSeen), last = kwd_safe_(ev.lastSeen);
    if (first && (!row[C['First Seen (UTC)']] || first < row[C['First Seen (UTC)']])) row[C['First Seen (UTC)']] = first;
    if (last && (!row[C['Last Seen (UTC)']] || last > row[C['Last Seen (UTC)']])) row[C['Last Seen (UTC)']] = last;
    row[C['Count']] = (Number(row[C['Count']]) || 0) + (Number(ev.count) || 1);

    // Device facts always reflect the latest report.
    row[C['Device Name']] = kwd_safe_(dev.name);
    row[C['Serial Number']] = kwd_safe_(dev.serial);
    row[C['Device Key']] = devKey;
    row[C['Windows']] = kwd_safe_(dev.windows);
    row[C['Windows Build']] = kwd_safe_(dev.build);
    row[C['Edition']] = kwd_safe_(dev.edition);
    row[C['Logged-in User(s)']] = kwd_safe_(dev.loggedIn);
    row[C['Manufacturer / Model']] = kwd_safe_(dev.model);
    row[C['Domain']] = kwd_safe_(dev.domain);

    // Users the event ran as accumulate.
    var users = String(row[C['User (event)']] || '').split('; ').filter(String);
    String(ev.user || '').split('; ').forEach(function (u) { u = kwd_safe_(u); if (u && users.indexOf(u) < 0) users.push(u); });
    row[C['User (event)']] = users.join('; ');

    row[C['Category']] = kwd_safe_(ev.category);
    row[C['Location']] = kwd_safe_(ev.location);
    row[C['File Path']] = path;
    row[C['Process']] = kwd_safe_(ev.process);
    if (ev.publisher) row[C['Publisher']] = kwd_safe_(ev.publisher);
    row[C['Signed']] = ev.signed === true;
    row[C['Signing Level']] = kwd_safe_(ev.signingLevel);
    row[C['User-writeable']] = kwd_safe_(ev.userWriteable);
    if (ev.sha256) row[C['SHA256']] = kwd_safe_(ev.sha256);
    if (ev.policy) row[C['Policy']] = kwd_safe_(ev.policy);
    row[C['Reported At (UTC)']] = nowStr;
  });
  return table;
}

function kwd_ensureEventsSheet_(ss) {
  var sh = ss.getSheetByName(KWD.TAB_EVENTS);
  if (sh) return sh;
  sh = ss.insertSheet(KWD.TAB_EVENTS);
  kwd_headerRow_(sh, KWD_EV_HEADERS);
  var rows = Math.max(sh.getMaxRows() - 1, 1);
  KWD_EV_TEXT_COLS.forEach(function (h) { sh.getRange(2, KWD_EV_HEADERS.indexOf(h) + 1, rows, 1).setNumberFormat('@'); });
  var signedCol = kwd_colLetter_(KWD_EV_HEADERS.indexOf('Signed') + 1);
  var unsigned = SpreadsheetApp.newConditionalFormatRule()
    .whenFormulaSatisfied('=AND($A2<>"",$' + signedCol + '2=FALSE)').setBackground('#fff2cc')
    .setRanges([sh.getRange(2, 1, rows, KWD_EV_HEADERS.length)]).build();
  sh.setConditionalFormatRules([unsigned]);
  sh.getRange(1, 1, sh.getMaxRows(), KWD_EV_HEADERS.length).createFilter();
  return sh;
}

function kwd_ingestEvents_(ss, payload) {
  var sh = kwd_ensureEventsSheet_(ss);
  var width = KWD_EV_HEADERS.length;
  var last = sh.getLastRow();
  var table = last > 1 ? sh.getRange(2, 1, last - 1, width).getValues() : [];
  var now = Utilities.formatDate(new Date(), 'UTC', 'yyyy-MM-dd HH:mm:ss');
  kwd_mergeEvents_(table, payload, now);
  if (sh.getMaxRows() < table.length + 1) sh.insertRowsAfter(sh.getMaxRows(), table.length + 1 - sh.getMaxRows());
  if (table.length) sh.getRange(2, 1, table.length, width).setValues(table);
  return payload.events.length;
}

// Removes event rows that have not been seen for KWD.EVENT_KEEP_DAYS days (keeps the sheet well under Google's cell limit).
function kwd_pruneEvents_(ss, now) {
  var sh = ss.getSheetByName(KWD.TAB_EVENTS);
  if (!sh || sh.getLastRow() < 2) return;
  var width = KWD_EV_HEADERS.length;
  var rows = sh.getRange(2, 1, sh.getLastRow() - 1, width).getValues();
  var iLast = KWD_EV_HEADERS.indexOf('Last Seen (UTC)');
  var cutoff = Utilities.formatDate(new Date(now.getTime() - KWD.EVENT_KEEP_DAYS * KWD_DAY), 'UTC', 'yyyy-MM-dd HH:mm:ss');
  var keep = rows.filter(function (r) { var s = String(r[iLast]); return !s || s >= cutoff; });
  if (keep.length === rows.length) return;
  sh.getRange(2, 1, rows.length, width).clearContent();
  if (keep.length) sh.getRange(2, 1, keep.length, width).setValues(keep);
  Logger.log('Pruned ' + (rows.length - keep.length) + ' old WDAC event row(s).');
}

// ============================================================================ software (only if the API exposes it)
function wd_syncSoftware() {
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(30000)) { Logger.log('Another run is in progress, skipping.'); return; }
  var started = Date.now();
  try {
    var props = PropertiesService.getScriptProperties();
    var ss = kwd_ss_();
    var dev = ss.getSheetByName(KWD.TAB_DEVICES);
    if (!dev || dev.getLastRow() < 2) { Logger.log('Run wd_sync first.'); return; }

    var width = KWD_HEADERS.length;
    var rows = dev.getRange(2, 1, dev.getLastRow() - 1, width).getValues();
    var iKey = 0, iName = KWD_HEADERS.indexOf('Device Name'), iId = KWD_HEADERS.indexOf('Atera Agent ID');
    var iGuid = KWD_HEADERS.indexOf('Device GUID'), iPresent = KWD_HEADERS.indexOf('Present in Current Sync');
    var targets = rows.filter(function (r) { return r[iKey] && r[iPresent] === true; }).map(function (r) {
      return { key: String(r[iKey]), name: String(r[iName]), id: String(r[iId]), guid: String(r[iGuid]) };
    });
    if (!targets.length) return;

    var template = props.getProperty('WD_SW_ENDPOINT');
    if (!template) {
      template = kwd_discoverSoftwareEndpoint_(targets[0]);
      if (!template) { Logger.log('The Atera API did not return software for any known endpoint. Run wd_probe and check the ENDPOINT lines.'); return; }
      props.setProperty('WD_SW_ENDPOINT', template);
    }

    var sw = ss.getSheetByName(KWD.TAB_SOFTWARE) || ss.insertSheet(KWD.TAB_SOFTWARE);
    kwd_headerRow_(sw, KWD_SW_HEADERS);
    var cursor = Number(props.getProperty('WD_SW_CURSOR') || 0);
    if (cursor >= targets.length) cursor = 0;
    var batchStart = cursor;
    var replaced = {};
    var fresh = [];
    var stamp = kwd_fmt_(ss, new Date());
    var opts = kwd_ateraOpts_();

    while (cursor < targets.length && (Date.now() - started) < KWD.SOFTWARE_BUDGET_MS) {
      var batch = targets.slice(cursor, cursor + KWD.SOFTWARE_BATCH);
      var reqs = batch.map(function (t) {
        var o = { url: KWD.ATERA_BASE + template.replace('{id}', t.id).replace('{guid}', t.guid), method: 'get', muteHttpExceptions: true };
        o.headers = opts.headers;
        return o;
      });
      var resps = UrlFetchApp.fetchAll(reqs);
      resps.forEach(function (resp, i) {
        if (resp.getResponseCode() !== 200) return;   // keep the old rows for this device, retry next cycle
        var t = batch[i];
        var list = kwd_softwareList_(JSON.parse(resp.getContentText()));
        replaced[t.key] = true;
        list.forEach(function (it) { fresh.push([t.key, t.name, it.name, it.version, it.publisher, it.date, stamp]); });
      });
      cursor += batch.length;
    }
    props.setProperty('WD_SW_CURSOR', String(cursor >= targets.length ? 0 : cursor));

    var last = sw.getLastRow();
    var kept = last > 1 ? sw.getRange(2, 1, last - 1, KWD_SW_HEADERS.length).getValues().filter(function (r) { return !replaced[String(r[0])]; }) : [];
    var all = kept.concat(fresh);
    if (sw.getMaxRows() < all.length + 1) sw.insertRowsAfter(sw.getMaxRows(), all.length + 1 - sw.getMaxRows());
    if (last > 1) sw.getRange(2, 1, last - 1, KWD_SW_HEADERS.length).clearContent();
    if (all.length) sw.getRange(2, 1, all.length, KWD_SW_HEADERS.length).setValues(all);
    Logger.log('Software: refreshed ' + Object.keys(replaced).length + ' devices (' + fresh.length + ' rows). Devices ' + batchStart + ' to ' + cursor + ' of ' + targets.length + '.');
  } finally {
    lock.releaseLock();
  }
}

function kwd_softwareList_(j) {
  var items = Array.isArray(j) ? j : (j.items || j.Items || []);
  return items.map(function (x) {
    var lc = kwd_lc_(x);
    return {
      name: String(kwd_pick_(lc, ['Name', 'SoftwareName', 'DisplayName', 'ApplicationName'])),
      version: String(kwd_pick_(lc, ['Version', 'DisplayVersion', 'SoftwareVersion'])),
      publisher: String(kwd_pick_(lc, ['Publisher', 'Vendor', 'SoftwarePublisher'])),
      date: String(kwd_pick_(lc, ['InstallDate', 'InstalledOn', 'InstalledDate', 'SoftwareInstallDate']))
    };
  }).filter(function (r) { return r.name; });
}

function kwd_discoverSoftwareEndpoint_(t) {
  for (var i = 0; i < KWD.SOFTWARE_ENDPOINTS.length; i++) {
    var template = KWD.SOFTWARE_ENDPOINTS[i];
    if (template.indexOf('{id}') >= 0 && !t.id) continue;
    if (template.indexOf('{guid}') >= 0 && !t.guid) continue;
    var resp = kwd_fetch_(KWD.ATERA_BASE + template.replace('{id}', t.id).replace('{guid}', t.guid), kwd_ateraOpts_());
    if (resp.getResponseCode() !== 200) continue;
    try {
      var j = JSON.parse(resp.getContentText());
      if (Array.isArray(j) || Array.isArray(j.items) || Array.isArray(j.Items)) return template;
    } catch (e) { /* not JSON, try the next one */ }
  }
  return '';
}
