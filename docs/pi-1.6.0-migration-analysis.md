# Analyse d'impact — migration Pi 0.87.1 → 1.6.0

> **Statut** : analyse **exécutée**. Rédigée et vérifiée le 2026-11-21 ; la migration a été réalisée le même jour — voir §11 « Retour d'exécution ». Les modifications ont porté sur `package.json` (peers `^0.87.1` → `^1.6.0`, suppression de l'override `undici`), `package-lock.json`, la CI (commentaire du job audit) et la documentation présente.
> **Date** : 2026-11-21. **Cible** : `@earendil-works/pi-ai`, `pi-coding-agent`, `pi-tui` `^0.87.1` → `^1.6.0` (transitifs : `pi-agent-core`, plus les nouveaux `pi-mcp`, `pi-codemode`, `pi-schema`, `pi-telemetry` épinglés à `1.6.0` exact).
> **Verdict synthétique** : saut majeur 0.x → 1.x **faible risque** pour notre contrat, **aucun changement de code prérequis** (confirmé : `tsc --noEmit` 0 erreur et test de chargement sans retouche). La seule décision non triviale est l'override `undici` : **supprimé** — upstream pinne désormais `8.12.4` exact (patché des six GHSAs de la 1.6.0), garder notre plancher `^8.10.2` ferait flotter vers 8.13.x, jamais testé en amont.

---

## 1. Synthèse exécutive

1. **Le contrat consommé n'a pas bougé** : le code n'importe qu'un seul package Pi (`@earendil-works/pi-coding-agent`, exclusivement en `import type`, effacé au runtime), deux symboles (`ExtensionAPI`, `ExtensionUIContext`), cinq hooks `pi.on`, `pi.registerCommand` ×6 et cinq champs de contexte. Aucun breaking change annoncé entre 0.87.1 et 1.6.0 ne touche cette surface (§4).
2. **Le saut 0.x → 1.x est un lockstep, pas un changement de modèle** : `pi-coding-agent@1.6.0` pinne `pi-ai`/`pi-tui`/`pi-agent-core`/`pi-mcp`/`pi-codemode` en exact `1.6.0` ; le passage à 1.0.0 (2026-10-01) marquait la maturité de l'API, pas une réécriture du contrat d'extension.
3. **L'override `undici` doit être supprimé, pas reconvergé** : le manifeste 1.6.0 pinne `undici 8.12.4` **exact** (résout GHSA-mqg3-3v4r-cm32, GHSA-7xg3-fphp-28hg, GHSA-5rm8-gv32-r954, GHSA-9v6h-8rgp-m69f, GHSA-3g9m-rv3r-w5w2, GHSA-r4pc-4jcp-7pqc — #12200). Notre `^8.10.2` résolvait 8.12.3 et continuerait à flotter ; l'amont a choisi la stabilité du pin, nous l'adoptons (divergence détectable par `npm ls undici`).
4. **`protobufjs` et `ws` restent** : `@google/genai@2.32.0` (via `pi-ai`) dépend toujours de `protobufjs ^7.5.4` et `ws ^8.18.0` ; `openai@7.59.0` n'a plus de `ws`. Les deux overrides restent des planchers actifs.
5. **Nos tests restent aveugles à la surface runtime Pi** (mocks `as unknown as ExtensionAPI`) : `tsc --noEmit` couvre les types, le test de chargement manuel couvre le runtime — il reste **obligatoire** malgré le verdict « aucun impact » (exécuté : §11.1, les six étapes passent).
6. **Aucune nouvelle exigence transverse** : `engines: node >=22.19.0` inchangé ; la CI reste sur Node 22 ; TypeScript 7.0.2 compile les `.d.ts` 1.6.0 (l'amont a lui-même basculé son build sur TS 7.0 en 0.99.0) ; `skipLibCheck: true` couvre le reste.

---

## 2. Méthode et sources

Chaque risque cite **deux preuves** : (a) une source primaire amont, (b) un usage concret dans notre code (fichier + symbole). Les sources primaires (vérifiées 2026-11-21) :

- **Registry npm** : packuments `@earendil-works/{pi-coding-agent,pi-ai,pi-tui}` — `1.6.0` = `dist-tags.latest` (publié le 2026-11-20) ; pins exacts croisés (`pi-* 1.6.0`, `undici 8.12.4`) ; `engines: node >=22.19.0` inchangé.
- **CHANGELOG `pi-coding-agent` au tag v1.6.0** : sections 0.87.1 → 1.6.0 passées en revue (16 versions), breaking changes inclus ; livré dans le package npm installé (`CHANGELOG.md` à la racine).
- **Releases GitHub `earendil-works/pi`** : v1.6.0 publiée le 2026-11-20.
- **Doc extensions @1.6.0** (`docs/extensions.md` du package) : modes `ctx.mode` `"tui" | "rpc" | "json" | "print"` (ligne 1173) — union inchangée ; contrat `registerCommand(name, { description, handler })` inchangé.
- **Précédent interne** : `docs/pi-0.87.1-migration-analysis.md` (méthode, §9.5 test de chargement, §11 retour d'exécution).

Cartographie code : inventaire exhaustif `extensions/`, `lib/`, `test/` (§3).

---

## 3. Inventaire du contrat consommé (preuve code — à ne pas élargir)

**Seul `@earendil-works/pi-coding-agent` est importé, uniquement en `import type`.** Deux symboles : `ExtensionAPI`, `ExtensionUIContext`. Aucun import dynamique, aucun deep-path, aucun import direct de `pi-ai`/`pi-tui`/`pi-agent-core`/`pi-mcp`/`pi-codemode`/`pi-schema`.

### 3.1 Symboles et sites d'usage

| Site | Symbole | Usage exploitant la signature |
|---|---|---|
| `extensions/security.ts:7` | `ExtensionAPI` | Factory `export default function (pi: ExtensionAPI)` ; `pi.on("session_start", …)` (:48) lisant `ctx.cwd` |
| `lib/audit.ts:12` | `ExtensionAPI` | `pi.registerCommand(name, { description, handler })` ×6 (:1101–1258) ; handler `(args, ctx)` appelant `ctx.ui.notify(msg, severity)` |
| `lib/guard-pipeline.ts:18` | `ExtensionAPI`, `ExtensionUIContext` | `pi.on("tool_call")` (:251, retour `{ block: true, reason }` ou `undefined`), `pi.on("turn_start")` (:494) ; `Pick<ExtensionUIContext, "notify" \| "confirm">` (:139) |
| `lib/skill-scanner.ts:13` | `ExtensionAPI`, `ExtensionUIContext` | `session_start` (:521, `ctx.cwd`) ; `Pick<ExtensionUIContext, "notify" \| "confirm" \| "select">` (:33) |
| `lib/secret-scanner.ts:19` | `ExtensionAPI` | `before_provider_request` (:422, **retourne le payload muté**), `after_provider_response` (:475), `turn_start` (:501) |
| `lib/injection-scanner.ts:29` | `ExtensionAPI` | `before_provider_request` (:471, payload muté), `after_provider_response` (:515), `turn_start` (:534) |
| `lib/metrics-scanner.ts:24` | `ExtensionAPI` | `before_provider_request` (:311), `after_provider_response` (:317), `turn_start` (:389), `session_start` (:393) |
| `test/*.test.ts` | `ExtensionAPI` | Mocks `pi` + cast `as unknown as ExtensionAPI` — **aveugles à la surface runtime réelle** |

### 3.2 Contrat d'extension

- **Entrée** : `export default function (pi: ExtensionAPI)` (`package.json` champ `pi.extensions`).
- **Hooks `pi.on`** : `session_start`, `tool_call`, `turn_start`, `before_provider_request`, `after_provider_response` — cinq événements, aucun autre.
- **Registrar** : `pi.registerCommand` uniquement (6 commandes). **Aucun** `registerTool`, `registerProvider`, `registerPathProvider`, `registerConfig` — c'est ce qui neutralise les breaking changes 1.5.0/1.5.1 (tools) et tous ceux liés aux providers.
- **Champs de contexte lus** : `ctx.cwd`, `ctx.hasUI`, `ctx.ui.notify/confirm/select`, `ctx.mode` ; via des interfaces locales narrowing (`PipelineCtx`, `guard-pipeline.ts:123-140` ; `SkillScannerContext`, `skill-scanner.ts:24-35`) et l'union miroir `PiMode = "tui" | "rpc" | "json" | "print"` (`guard-pipeline.ts:151`).
- **Config** : chargée hors Pi (`loadConfig`, `defaults/` résolu via `import.meta.url` — indépendant du cwd).

---

## 4. Changements amont 0.87.1 → 1.6.0 (preuve sources)

16 versions publiées dans l'intervalle (0.99.0 → 1.6.0). Breaking changes annoncés, avec le verdict pour notre contrat :

| Version | Breaking change annoncé (CHANGELOG v1.6.0) | Impact pour nous |
|---|---|---|
| 1.6.0 | Composants d'extension : `render()` → `readonly string[]`, `Container` renvoie le tableau caché (#9549) | **Aucun** — nous ne sous-classons aucun composant pi-tui, aucun `render()` |
| 1.5.1 | `GrepOperations.readFile` n'est plus appelé pour les lignes de contexte (déprécié) ; `"tools": []` omis quand tous les tools sont désactivés (#11843) | **Aucun** — aucun tool enregistré, aucune opérations grep |
| 1.5.0 | Validation des arguments de tools sur `@earendil-works/pi-schema` (TypeBox hors JSON Schema ignoré) | **Aucun** — aucun `registerTool` |
| 1.2.0 | Schemas de thèmes publiés + validation au démarrage ; `BeforeAgentStartEvent` devient une union sur `messageType` ; session comptée busy pendant le démarrage d'un run (`ctx.isIdle()`) ; `pi mcp list --json` rapporte `resources: true` | **Aucun** — ni thème ni `before_agent_start` ni `ctx.isIdle()` ni MCP dans notre contrat |
| 1.0.3 | Renommage du provider Azure `azure-openai-responses` → `azure` | **Aucun** — aucun provider consommé |
| 0.99.0 | Avertissement pour les packages listant les modules de l'hôte en `dependencies` (#9863) | **Conforme** — notre package utilise déjà `peerDependencies` ; l'avertissement ne s'applique pas |
| 1.0.0 | (Pas de breaking API d'extension ; bascule du build amont sur TypeScript 7.0 / ES2024) | **Aucun** — nous compilons avec TS 7.0.2 / ES2022 localement ; `tsc --noEmit` passe sur les `.d.ts` 1.6.0 |

Versions sans section Breaking dans l'intervalle : 0.99.1, 0.99.2, 1.0.1, 1.0.2, 1.0.4, 1.1.0, 1.3.0, 1.4.0, 1.5.2 (absence vérifiée dans le CHANGELOG livré).

**Changements pertinents hors breaking** :

- **1.6.0** : `undici` → `8.12.4` pour les six GHSAs listés en §1 (#12200) — motive la suppression de notre override ; correctifs RPC utiles à notre test : `session_start` n'est plus émis deux fois sur `new_session`/`fork` RPC (#10470), `--mode json` ne droppe plus les events émis par les handlers `session_start`.
- Correctifs sécurité précédents (RPC `steer`/`follow_up` #8718, `user_bash` fail-closed #9068, handlers `context` #9789/#9822) étaient déjà dans notre 0.87.1.

**Métadonnées clés @1.6.0** (manifestes npm installés) : `pi-coding-agent@1.6.0` pinne `pi-ai`/`pi-tui`/`pi-agent-core`/`pi-mcp`/`pi-codemode` en `1.6.0` et `undici` en `8.12.4` exact ; `pi-ai@1.6.0` dépend de `@google/genai 2.32.0`, `openai 7.59.0`, `@anthropic-ai/sdk 0.129.0`, `pi-schema 1.6.0`, `pi-telemetry 1.6.0` ; `engines: node >=22.19.0` inchangé.

---

## 5. Matrice de risques

| ID | Risque | Preuve (a) amont / (b) code | Sévérité | Détection | Traitement |
|---|---|---|---|---|---|
| R1 | Les ranges peers `^0.87.1` ne peuvent pas résoudre 1.x ; les packages publient en lockstep | (a) manifests pins exacts ; (b) `package.json:20-22` | **Bloquant** (c'est la migration) | `npm install` + `npm ls` | Les 3 peers passent à `^1.6.0` ensemble — jamais un sous-ensemble |
| R2 | Dérive des types `ExtensionAPI`/`ExtensionUIContext` (`Pick<…>` code en dur les membres) | (a) aucun renommage annoncé dans l'intervalle ; (b) `lib/guard-pipeline.ts:139`, `lib/skill-scanner.ts:33` | **Moyen** (compile-time) | `tsc --noEmit` | Élargir/ajuster le `Pick` si échec — **non déclenché** (0 erreur) |
| R3 | Sémantique runtime des handlers (payload muté retourné, `{ block, reason }`, ordre de dispatch) invisible aux tests mockés | (a) `docs/extensions.md` @1.6.0 ; (b) mocks `as unknown as` | **Moyen** | test de chargement (§11.1) | Ajuster les handlers si comportement modifié — **non déclenché** |
| R4 | Union `PiMode` miroir locale obsolète → un nouveau mode tomberait fail-closed silencieusement (sûr mais restrictif) | (a) `docs/extensions.md` @1.6.0 : modes toujours `"tui"\|"rpc"\|"json"\|"print"` ; (b) `guard-pipeline.ts:151` | **Faible** | test de chargement modes print/json + doc @1.6.0 | Union inchangée — **vérifiée à jour** |
| R5 | `undici` résolu différemment du pin upstream après suppression de l'override | (a) manifeste pinne `8.12.4` exact ; (b) suppression décidée | **Faible** | `npm ls undici` | Résolu **8.12.4 exact, copie unique deduped** — conforme ; réintroduire un plancher `^8.12.4` si divergence future |
| R6 | Overrides `protobufjs`/`ws` devenus inertes dans le nouvel arbre | (a) `@google/genai@2.32.0` dépend toujours des deux ; (b) `package.json` | **Faible** | `npm ls protobufjs ws` | Tous deux **actifs** (7.6.6, 8.23.0) — conservés |
| R7 | Nouvelles vulnérabilités transitives dans le nouvel arbre (genai 2.32, openai 7) | (a) `npm audit` ; (b) lockfile | **Faible** | `npm audit` deux niveaux | **0 critical, 0 high** ; 4 moderates préexistants dev-only (§11) |
| R8 | SBOM : le script CycloneDX doit fonctionner sur le nouvel arbre | (a) arbre étendu (215 paquets) ; (b) `package.json` script `sbom` | **Faible** (procédural) | `npm run sbom` | **OK** — 169 composants, artefact CI non commité |

Risques écartés d'office (preuve §3) : tools (1.5.0/1.5.1), providers (1.0.3), thèmes (1.2.0), composants TUI (1.6.0), `BeforeAgentStartEvent` (1.2.0).

---

## 6. Contraintes transverses

1. **Engines Node** : `>=22.19.0` inchangé entre 0.87.1 et 1.6.0 — aucune exigence nouvelle ; la CI reste sur Node 22 (`ci.yml`), rien à faire.
2. **TypeScript 7.0.2** : l'amont a basculé son propre build sur TS 7.0 en 0.99.0 — les `.d.ts` 1.6.0 sont produits par la même génération de compilateur que la nôtre. `skipLibCheck: true` couvre les erreurs internes ; `tsc --noEmit` passe (R2 non déclenché).
3. **Overrides npm** : après suppression de `undici`, il reste `protobufjs ^7.6.5` et `ws ^8.21.0` — tous deux actifs et plus restrictifs que les plages amont (`^7.5.4`, `^8.18.0`) ; les conserver ne change pas la résolution de cette migration (7.6.6 et 8.23.0 sont déjà ≥ planchers) mais protège des régressions transitives futures.
4. **SBOM** : régénéré localement (169 composants ; `bom.json` gitignoré, artefact CI) — les nouveaux `pi-mcp`, `pi-codemode`, `pi-schema` y figurent.
5. **Coverage** : imports Pi type-only, périmètre `lib/**` inchangé, aucun changement de code → gate 86 % lignes attendue stable (mesuré 91,17 %, §11).

---

## 7. Saut direct 0.87.1 → 1.6.0 ou montée incrémentale ?

**Recommandation retenue (et exécutée) : saut direct, en un seul train.**

1. **Aucun palier intermédiaire ne réduit le risque** : notre exposition est identique à chaque version de l'intervalle (mêmes deux types, cinq hooks, six commandes — §3) ; aucun breaking change annoncé ne touche le contrat (§4).
2. **Nos tests ne discrimineraient pas les paliers** : ils mockent `ExtensionAPI` ; chaque palier ajouterait un cycle install + CI pour zéro signal supplémentaire.
3. **Les packages publient en lockstep avec pins exacts** : un palier intermédiaire (ex. 1.2.0) n'est pas plus « testé amont » que 1.6.0 pour notre surface — et 1.6.0 est la version dont l'arbre transitif est audité pour la sécurité (undici 8.12.4).
4. **Le seul vrai test est le chargement runtime dans un host 1.6.0** — exécuté une fois, sur la cible finale (§11.1).

**Plan B (diagnostic, pas stratégie)** : en cas d'échec du test de chargement, bissecter en intercalant 1.5.2 puis 1.2.0 — le lockstep rend chaque palier reproductible. **Non déclenché.**

---

## 8. Plan de migration exécuté

> Aucune modification de code n'était prérequise d'après les sources ; l'étape « adaptations » ne s'exécute que sur échec des vérifications — elle ne s'est pas déclenchée.

1. **`package.json`** : les trois peers `^0.87.1` → `^1.6.0` ensemble ; suppression de la ligne `undici` du bloc `overrides` ; `protobufjs` et `ws` conservés ; devDependencies et CI inchangés.
2. **`package-lock.json`** : `npm install` (l'arbre transitif change fortement) ; vérification `npm ls` + `npm audit` (§11).
3. **Gates statiques** : `typecheck`, `test`, `test:coverage`, `sbom` (§11).
4. **Test de chargement manuel** sur un host pi 1.6.0 sandboxé (§9/§11.1) — obligatoire, toutes nos assurances runtime en dépendent.
5. **Code (conditionnel)** : rien — `tsc --noEmit` 0 erreur, chargement 1.6.0 sans erreur, `PiMode` vérifiée à jour contre `extensions.md` @1.6.0.
6. **Documentation** : ce document, `CHANGELOG.md` (entrée Changed), commentaire du job audit dans `.github/workflows/ci.yml` (le commentaire citait `undici` en exemple d'override ; il ne cite plus que `protobufjs`/`ws`).

## 9. Plan de vérification

### 9.1 Arbre (`npm ls`)

```bash
npm ls undici protobufjs ws
# Attendu : undici 8.12.4 (pin exact upstream, copie unique) ; protobufjs 7.6.x ; ws 8.23.x ; aucun "invalid"
npm ls @earendil-works/pi-coding-agent @earendil-works/pi-ai @earendil-works/pi-tui @earendil-works/pi-agent-core
# Attendu : les quatre à 1.6.0, dedupliqués
```

### 9.2 Audit

```bash
npm audit --audit-level=critical   # gate CI dure : doit passer
npm audit --audit-level=high       # advisory : doit passer
```

### 9.3 Gates statiques

```bash
npm run typecheck        # tsc --noEmit, 0 erreur attendue sans changement de code
npm test                 # suite complète
npm run test:coverage    # gate lignes >= 86 % (lib/**)
npm run sbom             # CycloneDX sur le nouvel arbre (artefact CI, non commité)
```

### 9.4 Test de chargement manuel (obligatoire)

Host pi 1.6.0 en sandbox (répertoire jetable, `HOME` isolé), extension chargée via `pi -e extensions/security.ts` (jiti), fournisseur **OpenAI-compatible local scripté** (aucun appel réseau externe, aucun secret réel). Six vérifications :

1. chargement sans erreur au démarrage ;
2. les 6 commandes `/security*` s'enregistrent et répondent ;
3. un bash dangereux est bloqué par le guard et produit une entrée d'audit ;
4. un secret est caviardé sur `before_provider_request` ;
5. fail-closed en `--mode print` et `--mode json` (confirmations refusées hors TUI) ;
6. `/security:verify` rejoue la chaîne HMAC sans erreur.

Méthode : mode **RPC** pour l'observation structurée (`get_commands` énumère les commandes enregistrées contre l'`ExtensionAPI` réel ; les `notify` des handlers sont des events JSON observables), modes **print** et **json** pour le fail-closed (la raison du bloc cite le mode). Détail des résultats en §11.1.

## 10. Limites de l'analyse

- Le mode **TUI** n'est pas testé (pas de terminal interactif dans l'environnement) — identique au retour 0.87.1 ; la branche TUI (`canShowDialog` → confirm réel) reste couverte par les tests unitaires mockés seulement.
- Les internals non importés (genai 2.32, openai 7, `pi-mcp`, `pi-codemode`, typebox) ne sont pas audités indépendamment — couverts par `npm audit` (0 critical/high).
- L'absence de régressions **non annoncées** ne peut être garantie par lecture — c'est précisément le rôle du test de chargement (§11.1), nos tests automatisés étant aveugles à la surface runtime de Pi.

## 11. Retour d'exécution (2026-11-21)

Migration exécutée le 2026-11-21. Résultats :

- **Arbre** : les quatre packages pi résolus à `1.6.0`, dedupliqués ; `undici` **8.12.4 exact, une seule copie** (conforme au pin upstream — R5) ; `protobufjs` 7.6.6 ; `ws` 8.23.0 ; aucun `invalid` ; lockfile 209 → 215 paquets (`@google/genai` 2.21.0 → 2.32.0, `openai` 6.40.0 → 7.59.0, `@anthropic-ai/sdk` 0.124.0 → 0.129.0, nouveaux `pi-mcp`/`pi-codemode`/`pi-schema` 1.6.0).
- **Audit** : `npm audit` **0 critical, 0 high**. Restent **4 moderates préexistants, hors migration** : `glob` 13.0.6 (GHSA-3g3m-2fjr-6pw4) et `minimatch` 10.2.6 (GHSA-g3hv-75wg-m249), chaîne dev-only `c8 → test-exclude` — versions **inchangées** par cette migration (vérifié : identiques dans le lockfile HEAD et le nouveau), le seul correctif proposé est un downgrade breaking de `c8` (9.1.0). Les deux gates CI (critical bloque, high advisory) passent.
- **Gates statiques** : `tsc --noEmit` **0 erreur sans aucun changement de code** ; **557 tests passent** ; coverage lignes **91,17 %** (gate 86 %) ; `npm run sbom` **OK** (169 composants, CycloneDX 1.5).
- **`npm outdated`** : rien à jour côté devDeps (`c8`, `tsx`, `typescript`) — conforme au plan.

### 11.1 Test de chargement §9.4 (2026-11-21)

Host Pi **1.6.0** installé en sandbox isolé (`/tmp/opencode/pi16-sandbox`, `npm install @earendil-works/pi-coding-agent@1.6.0` ; `pi --version` → `1.6.0`), `HOME` isolé (`/tmp/opencode/pi16-home`, agent-dir et `~/.pi/agent/security/` sous ce HOME), projet de test isolé (`/tmp/opencode/pi16-project`). Extension testée : le working tree lui-même (`extensions/security.ts` chargé via `pi -e`, jiti). Les réponses modèle proviennent d'un **faux fournisseur OpenAI-compatible local scripté** sur `127.0.0.1:8642` (aucun appel réseau externe, aucun secret réel) ; chaque requête reçue est archivée pour vérifier la rédaction en sortie.

| # | Étape §9.4 | Résultat |
|---|---|---|
| 1 | Chargement sans erreur ; `defaults/` résolue depuis le package | ✅ factory chargée par jiti ; audit `session.loaded` : `cwd=/tmp/opencode/pi16-project`, `protectedPatternsCount=54`, `commandRuleCategories=[safe,moderate,dangerous,external]` — config `defaults/` bien résolue via `import.meta.url` |
| 2 | Les 6 commandes s'enregistrent et répondent | ✅ `get_commands` (RPC) liste les 6 contre l'`ExtensionAPI` réel : `security`, `security:skills`, `security:trust`, `security:allow`, `security:clean`, `security:verify` ; `/security` répond (notify « 🔒 Security Dashboard ») et `/security:verify` répond (notify « 🔍 Audit chain verification ») |
| 3 | Bash dangereux → blocage + audit | ✅ tool call `bash` `rm -rf /tmp/pi16-project/data` → **bloqué** : tool result `isError:true`, raison « confirmation requires interactive (tui) mode » ; audit `bash.dangerous.block`, `category=dangerous` |
| 4 | Secret caviardé sur `before_provider_request` | ✅ faux jeton AWS `AKIAIOSFODNN7EXAMPLE` **absent du corps reçu par le fournisseur** (`grep` = 0), remplacé par `***REDACTED:aws-access-key***` ; audit `secret.redacted`, `patternName=aws-access-key` |
| 5 | Fail-closed `--mode print` et `--mode json` | ✅ print : blocage, audit « current mode: **print** », sortie texte propre, exit 0 ; json : tool result `isError:true` « current mode: **json** » dans le flux d'events |
| 6 | `/security:verify` rejoue la chaîne HMAC | ✅ « ✅ All files verified — chain intact. / … 13 entries, chain intact » — vérification **cross-session** (chaîne accumulée sur les sessions rpc + print + json) |

Précisions : le mode RPC a servi d'harnais d'observation (events JSON) ; le prompt `/security:verify` passe par le dispatch réel des commandes d'extension (`session.prompt` → `_tryExecuteExtensionCommand`). **R3/R4 vérifiés par exécution.** Seul le mode **TUI** reste non testé (pas de terminal interactif ; non simulé — cohérent avec le retour 0.87.1 §11.1).
