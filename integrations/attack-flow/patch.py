"""Small, fail-closed patch against the exact pin; no renderer fork."""
from pathlib import Path
import re
import shutil

def patch(builder: Path):
    def replace(path, before, after):
        p=builder/path; text=p.read_text()
        if text.count(before)!=1: raise RuntimeError('Upstream patch anchor changed: '+path)
        p.write_text(text.replace(before,after))
    # Production build only; devtools-kit fails on Node 25's experimental localStorage.
    replace('vite.config.ts', "import vueDevTools from 'vite-plugin-vue-devtools'\n", '')
    replace('vite.config.ts', '    vueDevTools(),\n', '')
    replace('src/App.vue', '// Dependencies', '// Dependencies\nimport * as Iti from "./iti-bridge";')
    replace('src/App.vue', '    const ctx = this.application;', '    const ctx = this.application;\n    try {')
    replace('src/App.vue', 'this.execute(AppCommand.loadSettings(ctx, settings));', 'await this.execute(AppCommand.loadSettings(ctx, settings));')
    replace('src/App.vue', 'this.execute(AppCommand.setReadonlyMode(ctx, true));', 'await this.execute(AppCommand.setReadonlyMode(ctx, true));')
    replace('src/App.vue', 'this.execute(await AppCommand.prepareEditorFromUrl(ctx, src));', 'Iti.artifactUrl(src);\n        await this.execute(await AppCommand.prepareEditorFromUrl(ctx, src));\n        await Iti.ready(ctx);')
    replace('src/App.vue', '        console.error(ex);', '        console.error(ex);\n        Iti.fail(ex);')
    replace('src/App.vue', '  },\n  mounted() {', '    } catch (ex) { Iti.fail(ex); }\n  },\n  mounted() {')
    # Upstream store did not await asynchronous command groups (including file preparation).
    replace('src/stores/ApplicationStore.ts', '                command.execute();', '                await command.execute();')
    # No chatbot/provider setup in either local view; remove its entire mount/import.
    p=builder/'src/components/Elements/EditorSidebar.vue'; text=p.read_text()
    text=re.sub(r'    <AccordionPane\s+name="Chat"[\s\S]*?</AccordionPane>\n', '', text, count=1)
    text=text.replace('import ChatPane from "@/components/Elements/ChatPane.vue";\n','').replace('    ChatPane,\n','');p.write_text(text)
    # No duplicate extraction UI, including if the user opens a new blank file.
    p=builder/'src/components/Elements/SplashMenu.vue';text=p.read_text()
    # The Generate block contains nested markup; anchor its full range.
    text=p.read_text();start=text.index('            <div\n              class="button"\n              @click="onGenerateFlow"');end=text.index('            </div>',text.index('{{ generateFlow.description }}',start))+len('            </div>')
    text=text[:start]+text[end:]
    text=text.replace('<AIGenerationSplashScreen @on-click-back="onGenerationClickBack" />','<p>Generate intelligence packages in the workbench.</p>')
    text=text.replace('import AIGenerationSplashScreen from "./AIGenerationSplashScreen.vue";\n','').replace('    AIGenerationSplashScreen,\n','');p.write_text(text)
    p=builder/'src/stores/ContextMenuStore.ts';text=p.read_text();text=re.sub(r',\s*\{\s*text: "Generate Flow",[\s\S]*?\n                    \}', '', text, count=1);p.write_text(text)
    # No automatic/predictive Atomic, D3FEND or remote TIE catalog retrieval.
    replace('src/assets/configuration/app.configuration.ts', '    recommender: {\n        create: () => new AttackFlowRecommender()\n    },', '')
    replace('src/assets/configuration/app.configuration.ts', 'import { AttackFlowRecommender } from "./AttackFlowRecommender/AttackFlowRecommender.ts";\n', '')
    p='src/assets/scripts/Application/Commands/FileManagement/LoadFile.ts'
    replace(p, '        this.editor.interface.installPlugin(\n            new AtomicRedTeamLinkPlugin(this.editor, url => context.execute(openHyperlink(url)))\n        );','        // ITI: no outbound Atomic link plugin in this local viewer/editor.')
    replace(p, '            context.execute(new SaveDiagramFileToRecoveryBank(context, editor));','            // ITI: explicit device export only; no cross-package recovery bank.')
    replace('src/assets/configuration/AttackFlowTemplates/AtomicRedTeamInlineLinks.ts', '    return url ? [{ afterField: "technique", text: "red-team this ↗", url }] : [];', '    return []; // ITI uses its own pinned, assessed Atomic candidates.')
    p=builder/'src/components/Elements/PropertyEditor.vue';text=p.read_text()
    text=re.sub(r'            <template #after-ttp>[\s\S]*?</template>\n', '', text, count=1);p.write_text(text)
    # Author/extension identity is metadata, not an action or an attack edge.
    replace('src/assets/scripts/StixToAttackFlow/StixToAttackFlow.ts', '    private resolveTemplate(stix: StixObject): string | null {', '    private resolveTemplate(stix: StixObject): string | null {\n        if (stix.type === "identity") return null;')
    replace('src/assets/scripts/StixToAttackFlow/ResolveEmbeddedRelationships.ts', '    if ("created_by_ref" in stix) {\n        common.push(stix.created_by_ref);\n    }', '    // ITI: created_by_ref is attribution, not attack progression.')
    p='src/assets/scripts/Application/Commands/FileManagement/index.ts'
    replace(p, '    const file = await (await fetch(url)).text();', '    const response = await fetch(url);\n    if (!response.ok) throw new Error(`Artifact request failed (${response.status})`);\n    const file = await response.text();')
    shutil.copy2(Path(__file__).with_name('bridge.ts'), builder/'src/iti-bridge.ts')
