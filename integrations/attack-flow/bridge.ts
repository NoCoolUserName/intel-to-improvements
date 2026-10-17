/** ITI integration only: same-origin artifact, bounded ready/error bridge and real viewport fit. */
import { nextTick } from 'vue';
import type { ApplicationStore } from '@/stores/ApplicationStore';
const params = new URLSearchParams(location.search);
const frame = params.get('iti_frame');
const packageId = params.get('iti_package');
let active: ApplicationStore | undefined;
const paint = () => new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
function report(status: string, detail: Record<string, unknown> = {}) {
    document.documentElement.dataset.itiStatus = status;
    if (frame && packageId && window.parent !== window) {
        window.parent.postMessage({type: 'iti-attack-flow', frame, packageId, status, ...detail}, location.origin);
    }
}
export function fail(error: unknown) {
    report('error', {message: error instanceof Error ? error.message : String(error)});
}
export function artifactUrl(src: string): URL {
    const url = new URL(src);
    if (url.origin !== location.origin || !/^\/api\/artifacts\/[^/]+\/attack-flow\.json$/.test(url.pathname)
        || !url.searchParams.get('customer_id') || !url.searchParams.get('environment_id')
        || url.username || url.password) throw new Error('Only a scoped local Attack Flow artifact can be loaded.');
    return url;
}
async function fit() {
    if (!active) throw new Error('Diagram has not loaded.');
    const {file, interface: ui} = active.activeEditor;
    const boxes = file.canvas.blocks.map(b => b.face.boundingBox);
    if (!boxes.length || ui.width < 1 || ui.height < 1) throw new Error('No rendered actions or viewport unavailable.');
    const xmin = Math.min(...boxes.map(b => b.xMin)), xmax = Math.max(...boxes.map(b => b.xMax));
    const ymin = Math.min(...boxes.map(b => b.yMin)), ymax = Math.max(...boxes.map(b => b.yMax));
    const camera = {x: (xmin + xmax) / 2, y: (ymin + ymax) / 2,
        k: Math.min(1, (ui.width - 64) / Math.max(xmax - xmin, 1), (ui.height - 64) / Math.max(ymax - ymin, 1))};
    if (!Object.values(camera).every(Number.isFinite) || camera.k <= 0) throw new Error('Cannot fit diagram bounds.');
    ui.setCameraLocation(camera, 0);
    await paint(); await paint();
    ui.render();
    report('ready', {nodes: boxes.length, edges: file.canvas.lines.length});
}
export async function ready(context: ApplicationStore) {
    active = context;
    await nextTick(); await document.fonts.ready; await paint(); await paint();
    // Upstream stacks disconnected roots vertically. A grid is presentation only:
    // no new edges, temporal order or logical operator is asserted.
    const {file, interface: ui} = context.activeEditor;
    if (!file.canvas.lines.length && file.canvas.blocks.length > 1) {
        const blocks = file.canvas.blocks;
        const width = Math.max(...blocks.map(b => b.face.boundingBox.width)) + 80;
        const height = Math.max(...blocks.map(b => b.face.boundingBox.height)) + 80;
        const columns = Math.max(1, Math.ceil(Math.sqrt(blocks.length * ui.width * height / (ui.height * width))));
        blocks.forEach((block, i) => {
            const box = block.face.boundingBox;
            block.moveBy((i % columns) * width - box.xMid, Math.floor(i / columns) * height - box.yMid);
        });
        file.canvas.calculateLayout();
    }
    await fit();
}
window.addEventListener('message', event => {
    if (event.origin !== location.origin || event.source !== window.parent || !frame || !packageId) return;
    const data = event.data;
    if (data?.type === 'iti-attack-flow-fit' && data.frame === frame && data.packageId === packageId) fit().catch(fail);
});
window.addEventListener('error', event => fail(event.error || event.message));
window.addEventListener('unhandledrejection', event => fail(event.reason));
