# Analyse d'impact — migration Pi 0.83.0 → 0.87.1

> **Statut** : analyse uniquement. Aucune modification de code ou de dépendance n'a été effectuée.
> **Date** : 2026-09-29. **Cible** : `@earendil-works/pi-coding-agent`, `pi-ai`, `pi-tui` `^0.83.0` → `^0.87.1` (transitif : `pi-agent-core`).
> **Verdict synthétique** : migration **faible risque**, **saut direct recommandé**, **aucun changement de code prérequis** identifié dans les sources primaires. Les risques résiduels se concentrent sur la réécriture des ranges peers (obligatoire), la dérive de types détectable uniquement par `tsc`, et le comportement runtime **invisible à nos tests** (mocks) — d'où un test de chargement manuel obligatoire.

---

## 1. Synthèse exécutive

1. **Le code n'importe qu'un seul package Pi** : `@earendil-works/pi-coding-agent`, exclusivement via `import type` (effacé au runtime), avec **deux symboles** : `ExtensionAPI` et `ExtensionUIContext`. `pi-ai` et `pi-tui` sont des peers déclarés mais jamais importés ; `pi-agent-core` est purement transitif.
2. **Aucun des breaking changes annoncés entre 0.84.0 et 0.87.1** (pi-coding-agent §0.84.0/0.84.3, pi-agent-core §0.84.0/0.84.4/0.87.0, pi-ai §0.84.0/0.84.3/0.85.0/0.86.0, pi-tui §0.85.0) **ne touche une API que nous utilisons**. La liste exhaustive des « aucun impact » est en §5.2.
3. **La migration ne peut pas se faire sans réécriture des ranges** : `^0.83.0` sur un package 0.x signifie `>=0.83.0 <0.84.0` (règle caret npm) — le lockfile ne résoudra jamais 0.87.x. Les trois peers passent à `^0.87.1` ensemble (lockstep vérifié : les quatre packages publient les mêmes 11 versions, publiées à quelques minutes d'écart, dernière le 2026-09-22).
4. **L'arbre transitif change fortement** (`@google/genai` 1.52.0 → **2.21.0**, `chalk` 5 → **6**, proxy-agents 7 → **9**, `@anthropic-ai/sdk` 0.91 → 0.124, ajout de `@earendil-works/chord` et `@earendil-works/pi-telemetry`, retraits de `glob`, `@mistralai/mistralai`, `@opentelemetry/api`). Nos overrides (`undici ^8.10.2`, `protobufjs ^7.6.5`, `ws ^8.21.0`) restent syntaxiquement valides mais leur pertinence doit être re-vérifiée après install (`npm ls`) — l'override `protobufjs` risque de devenir inerte.
5. **Écart préexistant à traiter dans le même train** : la CI tourne sous **Node 20** alors que les quatre packages exigent `node >=22.19.0` (inchangé entre 0.83.0 et 0.87.1, mais le rajeunissement de l'arbre transitif rend le Node 20 plus fragile). Un dist-tag `legacy-node20 = 0.74.2` existe en amont, cohérent avec notre historique (montée 0.74.0 → 0.82.1 documentée dans `docs/future-improvements.md`).
6. **Nos tests ne chargent pas Pi réel** : tous les tests mockent `ExtensionAPI` via `as unknown as ExtensionAPI` et rejouent des événements synthétiques ; `integration.test.ts` ne charge pas `extensions/security.ts`. Une rupture runtime de la surface Pi serait **invisible** à `npm test`. Le seul filet de sécurité type-level est `tsc --noEmit` ; le seul filet runtime est le test manuel de chargement — il est **obligatoire**.
7. **Des correctifs de sécurité amont plaident pour 0.87.1 plutôt qu'un palier intermédiaire** : contournement des handlers d'extension en RPC corrigé (0.86.0, #8718), `user_bash` fail-closed (0.86.0, #9068), handlers `context` ne droppant plus le system prompt (0.87.0, #9789/#9822), factories d'extension défaillantes ne laissant plus d'abonnements actifs (0.84.3, #8424). Pour une extension **de sécurité**, rester en 0.84.x/0.85.x exposerait à des bugs de contournement déjà corrigés.

---

## 2. Méthode et sources

Chaque risque cite **deux preuves** : (a) une source primaire amont, (b) un usage concret dans notre code (fichier + symbole).

Sources primaires (vérifiées 2026-09-29) :

- **npm registry** (packuments : versions, dates, engines, deps) : `https://registry.npmjs.org/@earendil-works/{pi-coding-agent,pi-ai,pi-tui,pi-agent-core}` — 0.87.1 est `dist-tags.latest` des quatre (publié le 2026-09-22). Les quatre packages se déclarent entre eux en **dépendances régulières** (`^0.87.1` croisés), pas en peerDependencies ; engines `node >=22.19.0` inchangé sur les 24 manifests relevés.
- **Repo officiel** (champ `repository` npm) : `https://github.com/earendil-works/pi` — monorepo (`packages/coding-agent`, `packages/ai`, `packages/tui`, `packages/agent`). **Pas de GitHub Releases** (API vide) ; les notes officielles sont les `CHANGELOG.md` par package au tag : `https://raw.githubusercontent.com/earendil-works/pi/v0.87.1/packages/coding-agent/CHANGELOG.md` (idem `ai`, `tui`, `agent`). Tags `v0.83.0`…`v0.87.1` vérifiés.
- **Doc extensions** : `https://raw.githubusercontent.com/earendil-works/pi/v0.87.1/packages/coding-agent/docs/extensions.md`.

Cartographie code : inventaire exhaustif `extensions/`, `lib/`, `test/` + `package-lock.json` (voir §3).

---

## 3. Inventaire des usages `@earendil-works/*` (preuve code)

**Seul `@earendil-works/pi-coding-agent` est importé, uniquement en `import type`.** Deux symboles : `ExtensionAPI`, `ExtensionUIContext`. Aucun import dynamique, aucun deep-path, aucun import de `pi-ai`/`pi-tui`/`pi-agent-core`.

### 3.1 Symboles et sites d'usage

| Site | Symbole | Usage exploitant la signature |
|---|---|---|
| `extensions/security.ts:7,20` | `ExtensionAPI` | Factory `export default function (pi: ExtensionAPI)` ; `pi.on("session_start", …)` (:48) lisant `ctx.cwd` |
| `lib/audit.ts:12` | `ExtensionAPI` | `pi.registerCommand(name, { description, handler })` ×6 (:1101–1258) ; handler `(args, ctx)` appelant `ctx.ui.notify(msg, severity)` |
| `lib/guard-pipeline.ts:18,139,251,494` | `ExtensionAPI`, `ExtensionUIContext` | `pi.on("tool_call")` (retour `{ block: true, reason }` ou `undefined`), `pi.on("turn_start")` ; `Pick<ExtensionUIContext, "notify" \| "confirm">` (:139) |
| `lib/injection-scanner.ts:23,272,305,324` | `ExtensionAPI` | `before_provider_request` (lit `event.payload`, **retourne le payload muté**), `after_provider_response` (`ctx.hasUI`, `ctx.ui.notify`), `turn_start` |
| `lib/metrics-scanner.ts:24,311–393` | `ExtensionAPI` | `before_provider_request`/`after_provider_response` (parcourt tout l'event pour `usage`/`model`), `turn_start`, `session_start` |
| `lib/secret-scanner.ts:11,314–355` | `ExtensionAPI` | `before_provider_request` (lit `event.payload`, **retourne le payload muté**), `after_provider_response`, `turn_start` |
| `lib/skill-scanner.ts:13,33,521` | `ExtensionAPI`, `ExtensionUIContext` | `session_start` (`ctx.cwd`) ; `Pick<ExtensionUIContext, "notify" \| "confirm" \| "select">` (:33) |
| `test/*.test.ts` (audit, guard-pipeline, injection-scanner, integration, metrics-scanner, rate-limiter) | `ExtensionAPI` | Mocks `pi` + cast `as unknown as ExtensionAPI` (ex. `guard-pipeline.test.ts:224,386`, `integration.test.ts:57`) |

### 3.2 Contrat d'extension consommé

- **Entrée** : `export default function (pi: ExtensionAPI)` — seul point d'entrée (`package.json:8-12`).
- **Hooks `pi.on`** : `session_start`, `tool_call`, `turn_start`, `before_provider_request`, `after_provider_response` — cinq événements, aucun autre.
- **Registrar** : `pi.registerCommand` uniquement (commandes `security`, `security:skills`, `security:trust`, `security:allow`, `security:clean`, `security:verify`). **Aucun** `registerTool`, `registerProvider`, `registerPathProvider`, `registerConfig`.
- **Champs de contexte lus** : `ctx.cwd`, `ctx.hasUI`, `ctx.ui.notify/confirm/select`, `ctx.mode` — les deux derniers via des interfaces locales narrowing (`PipelineCtx`, `guard-pipeline.ts:123-140` ; `SkillScannerContext`, `skill-scanner.ts:24-35`), avec une union `PiMode = "tui" | "rpc" | "json" | "print"` **miroir locale** (`guard-pipeline.ts:151`) d'un type amont non exporté.
- **Config** : chargée hors Pi (`loadConfig`, `defaults/` résolu via `import.meta.url` — `lib/utils.ts:116-119` — donc indépendant du cwd).

### 3.3 État du lockfile (0.83.0)

Les quatre packages résolus à **0.83.0** ; `pi-agent-core` tiré par `pi-coding-agent` (`^0.83.0`). Provenance des overrides : `undici` ← pin exact `8.5.0` de `pi-coding-agent` ; `protobufjs` ← `@google/genai@1.52.0` (via `pi-ai`) ; `ws` ← `@google/genai` + `@mistralai/mistralai` (via `pi-ai`) + `openai` (peer optionnel).

---

## 4. Changements amont 0.84.0 → 0.87.1 (preuve sources)

Résumé par version ; détail et citations dans les CHANGELOGs liés en §2.

| Version | pi-coding-agent (host d'extension) | pi-ai | pi-tui | pi-agent-core |
|---|---|---|---|---|
| 0.84.0 | **Breaking** : rename `ModelsStreamTransforms`→`ModelsRequestTransforms` ; RPC `message_update` delta-only (#7290) ; `ModelRegistry.getApiKeyAndHeaders/refresh` ; OAuth `refreshToken(signal)`. **Fix** : events d'extension survivant aux reloads (#7656), images surdimensionnées des tools d'extension (#7330) | **Breaking** : idem rename ; abort signals provider ; `context.stored`/`publish()` | additif (TUI fullscreen) | **Breaking** : modèle de session harness v4 (`Session`/`SessionRepo`), `FileSystem.renameFile()` requis |
| 0.84.1 | `terminate` sur `tool_call` bloqué (#7715) | — | additif | `BeforeToolCallResult.terminate` |
| 0.84.2 | `expandPromptTemplates` | Mistral SDK retiré (HTTP natif) | — | — |
| 0.84.3 | **Breaking** : rename `GoogleThinkingLevel`→`GoogleApiThinkingLevel`. **Changed** : expansion des ressources de package via glob natif Node ; chargement jiti/deferred. **Fix** : factories défaillantes ne laissent plus d'abonnements actifs (#8424) | idem rename ; `@opentelemetry/api` retiré | additif | — |
| 0.84.4 | events `ui_prompt_start/end` | — | additif | **Breaking** : `prepareNextTurn` après tour final |
| 0.85.0 | rétablit le sous-path `/client` | **Breaking** : `createGatewayBindingFetch`→`createAiBindingFetch` | **Breaking** : env-var defaults retirés (`PI_DEBUG_REDRAW`→`PI_TUI_DEBUG_REDRAW`, cursor/clearOnShrink via constructeur) | — |
| 0.85.1 | subpaths expérimentaux source-only | — | — | (sections vides — absence vérifiée) |
| 0.86.0 | **Breaking** : `Context`→`TranscriptContext` (providers custom) ; `ToolCall.arguments`/`ToolResultMessage.details` restreints JSON ; `user_bash` fail-closed (#9068). **Added** : `pi.on()` retourne un désabonnement (#8967). **Fix** : RPC steer/follow_up contournant les handlers d'extension (#8718) ; tools sans schéma rejetés (#9300) | idem Transcript/JSON ; `@google/genai` **1.52.0→2.21.0** ; proxy-agents 7→9 | `getNativeClipboard()` ; `marked` 18.0.11 | (section vide) |
| 0.86.1 | modèles ; cache de compilation | catalogues | (vide) | (vide) |
| 0.87.0 | **Breaking** : `shouldStopAfterTurn` retiré ; `ContextEditEntry` dans `SessionEntry` ; `SessionManager` canonique pour le contexte ; `TurnEndEvent`/`emitBoundary` ; runs depuis `agent_settled` différés. **Fix** : handlers `context` ne droppant plus system prompt/tools (#9789, #9822) | métadonnées catalogues | (vide) | **Breaking** : `shouldStopAfterTurn` retiré → `finishTurn` |
| 0.87.1 | modèles ; `--mode` strict | catalogues | (vide) | (vide) |

**Métadonnées clés** : les quatre packages à `0.87.1` = `latest` (2026-09-22) ; engines `node >=22.19.0` inchangé ; `pi-coding-agent@0.87.1` dépend de `pi-ai ^0.87.1`, `pi-tui ^0.87.1`, `pi-agent-core ^0.87.1`, `chord ^0.87.1`, `undici 8.10.2` (pin exact) ; pas de prérequis TypeScript déclaré dans les manifests aux deux bornes.

---

## 5. Matrice de risques (sévérité × preuves)

### 5.1 Risques actifs

| ID | Point d'impact | Preuve (a) source amont | Preuve (b) code | Sévérité | Détection | Traitement |
|---|---|---|---|---|---|---|
| R1 | `^0.83.0` ne peut **pas** résoudre 0.87.x (caret 0.x = `>=0.83.0 <0.84.0`) ; les 4 packages bougent en lockstep | Manifests npm : `pi-coding-agent@0.87.1` dépend des trois autres en `^0.87.1` ; 11 versions synchrones | `package.json:20-22` (3 peers `^0.83.0`) | **Bloquant** (c'est la migration elle-même) | `npm install` | Réécrire les 3 peers → `^0.87.1` ; `pi-agent-core` transite, pas d'édit direct |
| R2 | CI Node 20 vs `engines: node >=22.19.0` — **préexistant**, aggravé par les majors transitives nouvelles (genai 2, chalk 6, proxy-agents 9) | Registry : engines inchangé aux deux bornes ; dist-tag `legacy-node20 = 0.74.2` ; deps 0.87.1 (table §4) | `.github/workflows/ci.yml` — `node-version: 20` dans les 6 jobs ; aucun `engines`/`.nvmrc` dans le repo | **Moyen** | warnings EBADENGINE, runtime CI | Aligner la CI sur Node 22 LTS (recommandé dans le même train) |
| R3 | Dérive du type `ExtensionUIContext` : `Pick<…, "notify"\|"confirm"\|"select">` code en dur les noms de membres et leurs unions (sévérités) | CHANGELOGs pi-coding-agent 0.84.0→0.87.1 : **aucun** renommage de `ExtensionUIContext` ou de ses membres annoncé | `lib/guard-pipeline.ts:139` ; `lib/skill-scanner.ts:33` | **Moyen** (compile-time) | `tsc --noEmit` | Élargir/ajuster le `Pick` si échec |
| R4 | Sémantique **runtime** des handlers `pi.on` : retour du payload muté (`before_provider_request`), `{ block, reason }` (`tool_call`), ordre de dispatch — la couche events évolue amont (#7290 en 0.84.0, #8718 corrigé en 0.86.0) | CHANGELOG pi-coding-agent §0.84.0 (#7290), §0.86.0 (#8718) | `lib/guard-pipeline.ts:251-254` ; `lib/secret-scanner.ts:314-337` ; `lib/injection-scanner.ts:272-302` ; **tests aveugles** : mocks `as unknown as` (`test/guard-pipeline.test.ts:224`) | **Moyen** (invisible à `npm test`) | test manuel de chargement (§9.5) | Ajuster les handlers si comportement modifié |
| R5 | `ctx.mode` : union miroir locale `"tui"\|"rpc"\|"json"\|"print"` non importée — un nouveau mode amont tomberait silencieusement dans la branche fail-closed (`mode !== "tui"`) sans erreur de type | `extensions.md` @v0.87.1 (liste des modes non re-vérifiée ligne à ligne — voir §10) | `lib/guard-pipeline.ts:151, 158-206` | **Faible** (fail-closed = sûr mais plus restrictif) | test manuel en modes `print`/`json` | Mettre à jour l'union si nouveau mode documenté |
| R6 | Contrat `registerCommand(name, { description, handler })` — 6 commandes `/security:*` | Aucun changement annoncé dans les CHANGELOGs 0.84→0.87.1 | `lib/audit.ts:1101-1258` ; mock étroit `test/audit.test.ts:1192,1207` | **Faible** | test manuel (commandes listées) | — |
| R7 | Overrides vs nouvel arbre : `undici` (amont passe du pin 8.5.0 à 8.10.2 ; notre `^8.10.2` force 8.11.2 — converge) ; `protobufjs` (source unique `@google/genai` passe en 2.x → override possiblement **inert**) ; `ws` (genai 2.x + openai restent) | Manifests deps 0.83.0 vs 0.87.1 (registry) | `package.json:29-33` ; lock : `undici` via pi-coding-agent (:605), `protobufjs` via `@google/genai` (:1407), `ws` via genai/mistral/openai (:1408/1468/2901) ; `@mistralai/mistralai` **retiré** en 0.84.2 | **Faible** | `npm ls undici protobufjs ws` post-install | Garder les planchers sécurité ; retirer un override devenu inerte (facultatif) |
| R8 | SBOM : `bom.json` à régénérer — diff substantiel (retraits `glob`, `@mistralai/mistralai`, `@opentelemetry/api` ; ajouts `@earendil-works/chord`, `@earendil-works/pi-telemetry` ; bumps majeurs) | Manifests + CHANGELOGs §0.84.2/0.84.3/0.86.0 | `package.json:17` (script `sbom`) | **Faible** (procédural) | `npm run sbom` + diff | Revoir et committer le nouveau `bom.json` |
| R9 | Résolution `defaults/` : via `import.meta.url` (package-relative), donc **hors** du changement 0.84.3 d'expansion des ressources pi-package ; reste à confirmer au chargement jiti | CHANGELOG pi-coding-agent §0.84.3 (glob natif Node) | `lib/utils.ts:116-119` ; `lib/config.ts:135` | **Faible** | test manuel (config chargée) | — |
| R10 | Compat TypeScript 7.0.2 avec les `.d.ts` des nouveaux packages | Manifests : aucun prérequis TS déclaré aux deux bornes ; `skipLibCheck` couvre les erreurs internes (pas les erreurs de syntaxe) | `tsconfig.json` (`skipLibCheck: true`) ; `package.json:27` | **Faible** | `tsc --noEmit` | — |
| R11 | Gate coverage c8 (lignes 86 %, `lib/**`) | — (imports type-only effacés au runtime ; aucun changement de code prévu) | `package.json:16` ; §3.1 | **Aucun attendu** | `npm run test:coverage` | — |

### 5.2 Breaking changes annoncés **sans impact** sur nous (vérification explicite)

| Breaking change annoncé (source) | Pourquoi aucun impact — preuve code |
|---|---|
| pi-agent-core 0.84.0 : harness/session v4, `Session`/`SessionRepo`, `FileSystem.renameFile()` | `pi-agent-core` **jamais importé** (inventaire §3) |
| pi-ai 0.84.0 : `ModelsStreamTransforms`→`ModelsRequestTransforms`, abort signals, `context.stored/publish()` | `pi-ai` **jamais importé** ; aucun provider enregistré |
| pi-coding-agent 0.84.0 : RPC `message_update` delta-only (#7290) | Nous sommes une extension in-process, **pas un client RPC** ; aucun import `/client` |
| pi-coding-agent 0.84.0 : `ModelRegistry.getApiKeyAndHeaders/refresh`, OAuth `refreshToken(signal)` | `ModelRegistry`/OAuth non utilisés (aucun `ctx.modelRegistry`, aucun `registerProvider`) |
| pi-agent-core 0.84.4 : `prepareNextTurn` après tour final | Non utilisé |
| pi-ai/pi-coding-agent 0.84.3 : `GoogleThinkingLevel`→`GoogleApiThinkingLevel` | Type pi-ai non importé |
| pi-tui 0.85.0 : env-var defaults retirés (`PI_TUI_DEBUG_REDRAW`, cursor/clearOnShrink) | `pi-tui` **jamais importé** ; concerne la config du host, pas de l'extension |
| pi-ai 0.85.0 : `createGatewayBindingFetch`→`createAiBindingFetch` | Non utilisé |
| 0.86.0 : `Context`→`TranscriptContext` (providers custom) | Aucun provider custom |
| 0.86.0 : `ToolCall.arguments`/`ToolResultMessage.details` restreints JSON, `ToolResultMessage` conditionnel | Nous lisons `event.input` via cast (`guard-pipeline.ts:254`) sans produire de `ToolResult` ; aucun type concerné importé |
| 0.86.0 : `user_bash` fail-closed (#9068) | Pas d'abonnement `user_bash` (§3.2 : cinq hooks, tous listés) |
| 0.87.0 : `shouldStopAfterTurn` retiré → `finishTurn` | Non utilisé |
| 0.87.0 : `ContextEditEntry` dans `SessionEntry` | Aucun switch exhaustif sur `SessionEntry` |
| 0.87.0 : `SessionManager` canonique (fin des écritures `session.agent.state.messages`) | Nous n'écrivons jamais l'état de session |
| 0.87.0 : `TurnEndEvent`/`AgentBeforeSettleEvent`/`emitBoundary` | Ni `ExtensionRunner` ni `turn_end` utilisés |
| 0.84.3/0.86.0 : tools d'extension sans schéma rejetés (#9300) ; constrained sampling par défaut | **Aucun `registerTool`** |

Changements **additifs** non consommés (sans effet) : `pi.on()` retourne un désabonnement (#8967 — nous ignorons la valeur de retour), nouveaux events (`session_compact_failed`, `ui_prompt_start/end`, `cache_warming_decision`, `context_with_system`), `ctx.modelRegistry.stream()`, `expandPromptTemplates`, `BeforeToolCallResult.terminate`.

### 5.3 Correctifs amont favorables à notre modèle de menace

Pour une extension dont la fonction est d'empêcher des actions dangereuses, ces correctifs justifient la cible 0.87.1 plutôt qu'un palier :

- **0.86.0 #8718** : RPC `steer`/`follow_up` contournait les handlers d'extension — corrigé (notre union `PiMode` inclut `"rpc"`, `guard-pipeline.ts:151`).
- **0.86.0 #9068** : `user_bash` échoue fermé (défense en profondeur derrière notre bash-gate).
- **0.87.0 #9789/#9822** : les handlers `context` ne droppent plus system prompt et déclarations d'outils.
- **0.84.3 #8424** : une factory d'extension défaillante ne laisse plus d'abonnements/provider actifs — notre factory enregistre 9 listeners + 6 commandes (`extensions/security.ts:20-64`).
- **0.84.0 #7656** : les listeners survivent aux reloads/disposal de l'extension.

---

## 6. Contraintes transverses

1. **Engines Node** : `node >=22.19.0` inchangé entre 0.83.0 et 0.87.1 — la migration n'introduit **aucune** nouvelle exigence. En revanche la CI (Node 20) était déjà hors spec et le devient davantage avec les majors transitives (R2).
2. **TypeScript 7.0.2** : aucun prérequis TS déclaré amont ; `skipLibCheck: true` neutralise les erreurs internes des `.d.ts`. Reste le risque de syntaxe non parsable — couvert par `tsc --noEmit` (R10).
3. **Overrides npm** : valides syntaxiquement après la montée. `undici ^8.10.2` reste **plus restrictif** que le pin amont (8.10.2) → résoudra 8.11.x, plancher de sécurité conservé. `protobufjs` et `ws` dépendront de l'arbre de `@google/genai` 2.x — à constater par `npm ls` (R7).
4. **SBOM** (`npm sbom --sbom-format cyclonedx --sbom-type application > bom.json`) : le contenu suivra l'arbre (R8) — régénération + revue de diff à prévoir, le script lui-même ne change pas.
5. **Coverage** : imports Pi type-only, exclusions `extensions/**` et périmètre `lib/**` inchangés ; aucun changement de code prévu → gate 86 % lignes attendue stable (R11).

---

## 7. Saut direct 0.83.0 → 0.87.1 ou montée incrémentale ?

**Recommandation : saut direct, en un seul train.**

1. **Aucun palier intermédiaire ne réduit le risque** : aucun breaking change annoncé sur l'intervalle ne touche notre surface (§5.2). Notre exposition est identique à 0.84.0, 0.85.0, 0.86.0 et 0.87.1 — les mêmes deux types, cinq hooks, `registerCommand`.
2. **Nos tests ne discrimineraient pas les paliers** : ils mockent `ExtensionAPI` et ne chargent pas Pi réel (§3.1). Chaque palier ajouterait un cycle install + CI complet pour **zéro signal supplémentaire**.
3. **Les paliers intermédiaires cumulent des défauts corrigés ensuite** : rester en 0.84.x/0.85.x reviendrait à s'exposer à #8718 (contournement RPC, corrigé en 0.86.0) et à #9789/#9822 (corrigés en 0.87.0) — incohérent pour une extension de sécurité (§5.3).
4. **Le seul vrai test est le chargement runtime dans un host 0.87.1** — à exécuter une fois, sur la cible finale.

**Plan B (diagnostic, pas stratégie)** : si le test de chargement manuel échoue, bissecter en intercalant 0.86.1 puis 0.85.1 pour isoler la version fautive — le lockstep des quatre packages rend chaque palier reproductible.

---

## 8. Plan de migration ordonné (ordre de modification des fichiers)

> Aucune modification de code n'est prérequise d'après les sources ; les étapes 4–5 ne s'exécutent que sur échec des vérifications.

1. **Préparation** — branche dédiée, arbre git propre (point de restauration). Recommandé dans le même train : CI Node 20 → 22 (`ci.yml`, 6 occurrences de `node-version`).
2. **`package.json`** — seul fichier à modifier a priori : peers `@earendil-works/pi-ai`, `pi-coding-agent`, `pi-tui` de `^0.83.0` → `^0.87.1` (3 lignes, lignes 20-22). Rien d'autre : pas de devDeps à toucher, overrides conservés en l'état.
3. **`package-lock.json`** — `npm install` ; vérifier l'absence d'`EBADENGINE` et la résolution unique des quatre packages (§9.1).
4. **Code (conditionnel)** — si `tsc --noEmit` échoue : ajuster les `Pick<ExtensionUIContext, …>` (`lib/guard-pipeline.ts:139`, `lib/skill-scanner.ts:33`) ou les types des handlers concernés ; si le test manuel révèle un nouveau mode, mettre à jour l'union `PiMode` (`lib/guard-pipeline.ts:151`). Chaque retouche reste locale aux interfaces de narrowing — pas de propagation attendue.
5. **`bom.json`** — `npm run sbom`, revue du diff (nouveaux composants attendus : `chord`, `pi-telemetry`, genai 2.x, chalk 6), commit.
6. **Clôture** — changelog maison / note de version ; suivre la convention du précédent upgrade documenté dans `docs/future-improvements.md`.

## 9. Plan de vérification

### 9.1 Déduplication / lockstep (`npm ls`)

```bash
npm ls @earendil-works/pi-coding-agent @earendil-works/pi-ai \
      @earendil-works/pi-tui @earendil-works/pi-agent-core
# Attendu : les quatre à 0.87.1, un seul exemplaire chacun (aucun "deduped" multiple)

npm ls undici protobufjs ws && npm explain undici
# Attendu : undici 8.11.x (override) ; ws 8.21.x ; protobufjs 7.6.x
# ou ABSENT (override inert si genai 2.x ne le tire plus) → décider du retrait
```

### 9.2 Types

```bash
npm run typecheck   # tsc --noEmit — détecte R3 (Pick ExtensionUIContext) et R10 (d.ts)
```

### 9.3 Tests et coverage

```bash
npm test                     # 16 fichiers — rappel : couverture runtime Pi nulle (mocks)
npm run test:coverage        # gate lignes 86 % (R11 : attendu inchangé)
```

### 9.4 SBOM

```bash
npm run sbom && git diff --stat bom.json   # revue des composants (R8)
```

### 9.5 Test manuel de chargement de l'extension (obligatoire — R4/R5/R6/R9)

Dans un sandbox avec un host Pi 0.87.1 :

1. `npm i -g @earendil-works/pi-coding-agent@0.87.1` (ou équivalent local), installer/lier `pi-secured-setup`.
2. Lancer `pi` dans un projet de test : l'extension se charge sans erreur jiti ; la config par défaut est bien résolue depuis le package (`defaults/` — R9).
3. Vérifier la présence des 6 commandes `/security`, `/security:skills`, `/security:trust`, `/security:allow`, `/security:clean`, `/security:verify` (R6).
4. Déclencher une commande interdite (ex. `rm -rf` hors périmètre) : blocage par le guard avec raison, entrée d'audit écrite (`session_start` a bien créé la session d'audit — `ctx.cwd`).
5. Soumettre un prompt contenant un faux secret : vérifier la réaction du secret-scanner sur `before_provider_request` (rédaction du payload — sémantique de retour muté, R4).
6. Répéter en `--mode print` et `--mode json` : comportement du guard cohérent avec la branche non-TUI (R5).

## 10. Limites de l'analyse

- Les « release notes » officielles sont les `CHANGELOG.md` par package au tag — **pas de GitHub Releases**. Sections pi-tui 0.86.1/0.87.x et pi-agent-core 0.85.1+ **vides (absence vérifiée)**, non reconstituées par diff de commits.
- `docs/packages.md` (manifeste pi-package) **non vérifié** — le comportement d'installation/distribution des ressources est couvert indirectement par le test manuel (R9).
- La liste exacte des valeurs de `ctx.mode` à 0.87.1 n'a pas été re-relevée mot à mot dans `extensions.md` (R5 traité en vérification manuelle).
- `typebox` 1.3.7 → 1.3.27 et `chalk` 5 → 6 (internes à Pi, non importés par nous) n'ont pas été audités indépendamment.
- L'absence de régressions **non annoncées** ne peut être garantie par lecture — c'est précisément le rôle du test de chargement manuel, nos tests automatisés étant aveugles à la surface runtime de Pi (§3.1).
