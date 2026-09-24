// Dependency-free interaction checks using a minimal DOM double, NOT a browser.
// Run: node tests/frontend_interaction.cjs
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const app = fs.readFileSync(path.join(root, 'frontend/app.js'), 'utf8');
const key = 'provo.inspection.comparison.v1';
const payload = {status: 'uploaded', filename: 'signed.jpg', file_size: 10, sha256: 'a'.repeat(64), c2pa: {
    manifest_found: true, validation_state: 'Valid', validation_results: {activeManifest: {
        success: [{code: 'claimSignature.validated'}], failure: [{code: 'signingCredential.untrusted'}]
    }}, hardened_verdict: {verdict: 'UNTRUSTED_SIGNER'}
}};
class Element {
    constructor(attrs = '') {
        this.attrs = Object.fromEntries([...attrs.matchAll(/([\w-]+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
        this.className = this.attrs.class || '';
        this.textContent = ''; this.style = {}; this.events = {}; this.files = [];
        this.classList = {
            contains: value => this.className.split(/\s+/).includes(value),
            add: (...values) => { this.className += ' ' + values.join(' '); },
            remove: (...values) => { this.className = this.className.split(/\s+/).filter(v => !values.includes(v)).join(' '); }
        };
    }
    addEventListener(name, fn) { this.events[name] = fn; }
    querySelector() { return this; }
    getAttribute(name) { return this.attrs[name]; }
    appendChild() {} replaceChildren() {} scrollIntoView() {} contains() { return false; }
    async trigger(name) { if (this.events[name]) await this.events[name]({preventDefault() {}, stopPropagation() {}}); }
}
function boot(file, storage = new Map(), blocked = false) {
    const html = fs.readFileSync(path.join(root, 'frontend', file), 'utf8');
    const elements = [...html.matchAll(/<[a-z][^>]*>/gi)].map(m => new Element(m[0]));
    const ids = Object.fromEntries(elements.filter(e => e.attrs.id).map(e => [e.attrs.id, e]));
    let ready;
    let ok = true;
    const alerts = [];
    const document = {
        body: {dataset: {page: file === 'comparison.html' ? 'comparison' : ''}},
        getElementById: name => ids[name] || null,
        createElement: () => new Element(),
        querySelectorAll: selector => selector === '[data-eval]' ? elements.filter(e => e.attrs['data-eval']) : [],
        addEventListener: (_, fn) => { ready = fn; }
    };
    const context = vm.createContext({document, window: {addEventListener() {}},
        sessionStorage: {
            getItem: k => { if (blocked) throw Error('blocked'); return storage.get(k) || null; },
            setItem: (k,v) => { if (blocked) throw Error('blocked'); storage.set(k,v); },
            removeItem: k => { if (blocked) throw Error('blocked'); storage.delete(k); }
        },
        fetch: async url => ({ok: url === '/api/health' || ok, json: async () => ok ? payload : {detail: 'rejected'}}),
        FormData: class { append() {} },
        FileReader: class { readAsDataURL() { this.onload({target: {result: 'data:image/jpeg;base64,'}}); } },
        alert: m => alerts.push(m), navigator: {clipboard: {writeText: async () => {}}}, setTimeout() {}, console
    });
    vm.runInContext(app, context);
    ready();
    return {ids, elements, storage, alerts, setOk: value => {ok = value;}};
}
async function stage(app) {
    app.ids.mediaFile.files = [{name: 'test.jpg', size: 10, type: 'image/jpeg'}];
    await app.ids.mediaFile.trigger('change');
}
(async () => {
    const home = boot('index.html');
    assert(home.ids.openComparisonPage.classList.contains('hidden'));
    await stage(home);
    assert(home.ids.openComparisonPage.classList.contains('hidden'), 'selection alone must not unlock');
    await home.ids.uploadForm.trigger('submit');
    assert(!home.ids.openComparisonPage.classList.contains('hidden'));
    assert.equal(home.ids.resExploitTitle.textContent, 'SIGNER TRUST NOT ESTABLISHED');
    const report = boot('comparison.html', home.storage);
    assert(!report.ids.workbench.classList.contains('hidden'));
    assert.match(report.ids.comparisonSource.textContent, /UPLOADED FILE RESULT/);
    assert.equal(report.ids.provoVerdictBadge.textContent, 'UNTRUSTED SIGNER');
    for (const preset of ['revoked', 'modified', 'signed', 'ordinary', 'exclusion']) {
        await report.elements.find(e => e.attrs['data-eval'] === preset).trigger('click');
        assert.match(report.ids.comparisonSource.textContent, /SIMULATED PRESET/);
    }
    await report.ids.restoreUploadedResult.trigger('click');
    assert.equal(report.ids.provoVerdictBadge.textContent, 'UNTRUSTED SIGNER');
    assert.equal(report.ids.resFilename.textContent, 'signed.jpg');
    await stage(home);
    assert(home.ids.openComparisonPage.classList.contains('hidden'), 'new file must invalidate previous comparison');
    home.setOk(false);
    await home.ids.uploadForm.trigger('submit');
    assert(home.ids.openComparisonPage.classList.contains('hidden'), 'failed upload must not unlock');
    for (const storage of [new Map(), new Map([[key, '{bad json']])]) {
        const gated = boot('comparison.html', storage);
        assert(gated.ids.workbench.classList.contains('hidden'));
        assert(!gated.ids.comparisonGate.classList.contains('hidden'));
    }
    const blocked = boot('index.html', new Map(), true);
    await stage(blocked); await blocked.ids.uploadForm.trigger('submit');
    assert(blocked.ids.openComparisonPage.classList.contains('hidden'));
    assert.match(blocked.ids.comparisonAvailability.textContent, /session storage/);
    assert.equal(blocked.alerts.length, 0, 'blocked storage must not break the inspection');
    console.log('PASS: upload gate, successful and failed uploads, file change reset, all five presets, original-result restore, missing/corrupt/blocked storage.');
})().catch(error => {console.error(error); process.exitCode = 1;});
