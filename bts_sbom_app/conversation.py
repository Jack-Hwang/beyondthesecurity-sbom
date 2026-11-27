"""Conversation memory, question decomposition and injection-pattern guard (2025-26 research round).

Three chatbot/agent upgrades grounded in the current literature and this repo's rules (deterministic first,
LLM only when a rule cannot decide; every claim measurable offline):

* **ConversationMemory** — multi-turn continuity (2026 multi-turn playbook, Rasa, Parlant): the last few
  turns' question/tools/found survive across requests, so an elliptical follow-up ("그중 HIGH만 보여줘",
  "라이선스는?") routes against the previous turn's context instead of returning found=False. The merge is
  a deterministic string join - no LLM decides what the user meant; the router still decides the tools.
* **decompose_question** — compound questions (arXiv 2507.00355, Haystack/NVIDIA query decomposition):
  explicit-coordination splits (그리고/및/하고/comma/and) always, particle splits (와/과/이랑/랑) only when
  the right side carries a tool keyword, so "CVE-2020-1111과 관련된 프로젝트" is NOT split (single question)
  but "취약점과 라이선스 보여줘" is.
* **scan_injection** — the context layer of layered prompt-injection defence (Fiddler guardrail layers,
  arXiv 2511.15759): tool/retrieval text is scanned for instruction-injection patterns before it can reach
  the model or the user; hits are counted and annotated, never obeyed (the structural defence stays
  validate_calls + passages-only prompts + verbatim untrusted marking). AC-1210..1213 (held-out methodology,
  evals/injection_holdout.jsonl): the first version was English-literal-phrase only (every Korean attack in
  evals/injection_samples.jsonl passed clean - measured recall 0.0). The guard is now built from GENERAL
  linguistic signal classes, not literal sentences - an override-directive shape (verb + a few modifier words
  + an instructions-shaped object, English and Korean conjugations/polite endings), a role-reassignment shape
  ("you are now"/지금부터 너는/너는 이제 + a role noun, or a standalone unrestricted-mode phrase), a
  disclosure-request shape (reveal/show/tell/출력해줘/공개해 + a system-prompt/secret/credential-shaped object)
  and a command-execution shape (execute/run/실행해 + a command/script object) - plus a normalisation pass
  that strips zero-width characters and rejoins letter-spaced obfuscation ("i g n o r e") before any pattern
  runs, since those are evasions of the scanner itself, not meaningful word boundaries in real prose. Measured
  before/after on both the pinned dev corpus and the fresh held-out one are in this bundle's report - including
  the honest limits that regex-shape matching still cannot resolve (negation like "please do NOT ignore the
  rules" reads as the same shape as the command it negates; a generic noun like "rules" is already ambiguous
  between "the project's coding rules" and "the assistant's behaviour rules" in both languages).
* **CaseFacts** — case identifiers (course slide A10 "CASE FACTS: 요약 금지, 충돌 로그") held OUTSIDE the 3-turn
  deque: a CVE/GHSA/PYSEC/RUSTSEC/GO advisory id, a ``component@version`` pair, an SPDX license id (only when the
  turn itself carries a license-context keyword, so common words that double as SPDX ids - JSON, Ruby, curl - are
  not misread as a license) and the last bare-named entity survive long after the turn that mentioned them has
  fallen out of the window, so a follow-up on an identifier from 20 turns ago still resolves instead of silently
  returning found=False. A later turn's DIFFERENT value for the same key is never silently overwritten - both
  values and their turn numbers are kept (case-only differences are not treated as a conflict). The store is
  bounded (least-recently-seen eviction) and, like the rest of ``ConversationMemory``, is process-wide and
  single-tenant - see ``CaseFacts``'s own docstring for that limitation stated in full.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

from . import licenses

MAX_TURNS = 3

# follow-up shape: starts with a demonstrative, references the prior turn, is a bare filter ("HIGH만 보여줘"),
# or a bare topic+particle question ("라이선스는?") - the elliptical form the router alone cannot place.
_FOLLOWUP = re.compile(
    r"^\s*(그|이|저)\s|그중|이중|그것|아까|방금|위 (질문|답변|사례)|좀 더|더 자세히|바로 그|같은 조건"
    r"|^\s*[\w.]+\s*(등급|이상|이하)?\s*(만)\s*(보여|알려|찾)"
    r"|(만|만\s*(보여줘|알려줘|검색|필터))\s*$"
    r"|^\s*(high|critical|medium|low)\b"
    r"|^[^?？]{1,24}(은|는|이|가)\s*[?？]\s*$", re.I)
# explicit coordination always splits; particles split only when the right side names a tool intent
_EXPLICIT = re.compile(r"\s*(?:그리고|및|,| 및 | and | OR | 또는 )\s*")
_PARTICLE = re.compile(r"(?:와|과|이랑|랑)\s*")
_TOOL_INTENT = re.compile(r"취약|cve|라이선스|license|패치|patch|아키텍처|architecture|규제|컴플라이언스|"
                          r"compliance|라이선스 리스크|sbom|구성요소|component|프로젝트|project", re.I)
#: known scanner-evasion obfuscations, stripped/rejoined BEFORE any pattern below ever runs (AC-1212) - a no-op
#: on ordinary prose: zero-width characters never occur in real English/Korean text, and a run of single
#: letters each separated by one space/dot/dash/underscore ("i g n o r e", "i.g.n.o.r.e") is never a real word
#: boundary either, only a way to dodge a literal-phrase scanner.
_ZERO_WIDTH_CHARS = "".join(chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF))
_ZERO_WIDTH = re.compile("[" + _ZERO_WIDTH_CHARS + "]")
_SPACED_LETTERS = re.compile(r"(?<![\w])(?:[A-Za-z][ .\-_]){2,}[A-Za-z](?![\w])")


def _rejoin_spaced(m: "re.Match[str]") -> str:
    return re.sub(r"[ .\-_]", "", m.group(0))


def _normalize_for_scan(text: str) -> str:
    """Undo zero-width and letter-spacing obfuscation before ``_INJECTION`` runs - see ``_SPACED_LETTERS``."""
    t = _ZERO_WIDTH.sub("", text or "")
    return _SPACED_LETTERS.sub(_rejoin_spaced, t)


# ---- general linguistic SIGNAL CLASSES (AC-1210..1213), not literal sentences - see the module docstring -----
# override-directive: a verb that means "stop following the rules" + (a few modifier words) + an
# instructions-shaped object. A modal/negation-insensitive regex shape still cannot tell "ignore previous
# instructions" the command from "will ignore previous instructions embedded in..." the software description,
# or from an explicit "do NOT ignore the rules" - stated as a known limit, not silently hidden.
_OV_VERB_EN = r"(?:ignore|disregard|forget|discard|overlook|override|bypass|set\s+aside)"
_OV_OBJ_EN = (r"(?:instructions?|directions?|directives?|rules?|guidelines?|commands?|polic(?:y|ies)|"
              r"restrictions?|constraints?|prompts?|(?:you\s+were\s+)?(?:told|said|instructed)"
              r"(?:\s+(?:before|earlier|previously))?|everything\s+(?:said|written|mentioned)?\s*above)")
_EN_OVERRIDE = r"\b" + _OV_VERB_EN + r"\b(?:\s+\S+){0,4}?\s+" + _OV_OBJ_EN

# role-reassignment: "you are now"/"act as"/"pretend to be" + a role noun, or a standalone unrestricted-mode
# phrase - the common jailbreak-persona vocabulary (DAN, developer/god mode, "no content policy") generalised
# past one exact wording. The role-noun lookaround (not \b) lets "AI" match even directly against a following
# Hangul particle ("AI다") for the mixed-language case, while still excluding "aiming"/"said"/"air".
_ROLE_NOUN = r"(?<![a-zA-Z])(?:ai|assistant|bot|chatbot|model|persona|dan)(?![a-zA-Z])"
_EN_ROLE = (r"(?:you\s+are\s+now|from\s+now\s+on\s+you|from\s+here\s+on\s+you)\b(?:\s+\S+){0,6}?\s*" + _ROLE_NOUN
            + r"|(?:act\s+as|pretend\s+to\s+be|roleplay\s+as)\b(?:\s+\S+){0,4}?\s*" + _ROLE_NOUN
            + r"|no\s+content\s+polic|without\s+restrictions?|you\s+have\s+no\s+restrictions?|unrestricted\s+"
              r"(?:ai|assistant|bot|chatbot|mode)|\bno\s+rules\b|do\s+anything\s+now|\bdan\s+mode\b|"
              r"\bgod\s+mode\b|developer\s+mode|jailbreak")

# disclosure-request: a reveal-type verb + a system-prompt/secret/credential-shaped object (verb must come
# FIRST - "what's the system prompt format" with no reveal verb ahead of it is not flagged).
_EN_DISCLOSE = (r"(?:reveal|show|tell|print|output|give|display|disclose|share|expose)\b(?:\s+me)?"
                r"(?:\s+\S+){0,3}?\s*(?:system\s+prompt|system\s+instructions?|instructions?|prompt|"
                r"rules?|guidelines?|configuration|api\s*key|secret\s*key|credentials?|password)")

_EN_SYS_TAG = r"<\s*/?\s*(?:system|시스템)\s*>"

# command/tool-execution request: "execute/run" + a command/script-shaped object.
_EN_EXEC = (r"\b(?:execute|run)\b(?:\s+\S+){0,4}?\s+(?:command|commands|script|scripts|shell|code|"
            r"this\s+code|the\s+following)\b")

# Korean override-directive: object usually precedes the verb (SOV), so the object comes first here; the verb
# group spells out the common conjugations and polite endings (무시하고/무시해/무시하세요/무시해 주세요 등) rather
# than one exact phrase.
_KO_OV_OBJ = r"(?:지시\s*사항|지시|명령|지침|규칙|제한|규정)"
_KO_OV_PARTICLE = r"(?:[은는을를이가]\s*)?(?:모두|전부|다)?\s*"
_KO_OV_VERB = (r"(?:무시(?:하고|해|한|하라|해줄|하세요|해버려|한다)?|"
               r"잊(?:고|어|은|으세요|어라|자|어버리고)?|"
               r"버리(?:고|며|니|면|는)?|버려(?:서|라)?|"
               r"해제(?:하라|해|해줄|하세요|한다)?)")
_KO_OVERRIDE = _KO_OV_OBJ + _KO_OV_PARTICLE + _KO_OV_VERB

#: "내 명령만 따라(라)" - obey only my order, the SOV compliance-hijack mirror of the override directive above.
_KO_OBEY = r"(?:내|제)\s*(?:명령|지시)(?:만)?\s*(?:따라|따라라|따르세요|따라줄|따른다)"

#: role-reassignment: 지금부터/이제 너는 ... (AI/역할/챗봇/어시스턴트/페르소나), or "제한(이) 없는 AI/모드" - the
#: AI/모드 noun must follow immediately, so an ordinary "permissive, 제한이 없는 라이선스" (license with no
#: restriction) does not read as a role reassignment.
_KO_ROLE = (r"(?:지금부터|이제)\s*(?:너는|당신은)\b(?:\s*\S+){0,6}?\s*(?:AI|ai|역할|챗봇|어시스턴트|페르소나)"
            r"|너는\s*이제\b(?:\s*\S+){0,6}?\s*(?:AI|ai|역할|챗봇|어시스턴트|페르소나)"
            r"|제한\s*(?:이|가)?\s*없는\s*(?:AI|ai|모드|상태|어시스턴트|챗봇)")

#: disclosure-request, Korean: a system-prompt/secret/credential-shaped object + a show/tell-type verb
#: (보여줘/알려줘/출력해줘/공개해 and polite forms), object-then-verb per Korean word order.
_KO_DISC_OBJ = (r"(?:시스템\s*프롬프트|숨겨진\s*지침|지침|명령어|규칙|환경\s*설정|비밀\s*(?:키|정보)|비밀번호|"
                r"패스워드|api\s*키|소스\s*코드)")
_KO_DISC_VERB = r"(?:보여줘|보여주세요|알려줘|알려주세요|알려줄래|출력해줘|출력해|출력하라|공개해줘|공개해|공개하라|말해줘|말해주세요)"
_KO_DISCLOSE = _KO_DISC_OBJ + r"(?:\s*\S+){0,3}?\s*" + _KO_DISC_VERB

#: command/tool-execution request, Korean: 명령어/코드/스크립트 + 실행-type verb.
_KO_EXEC_OBJ = r"(?:명령어|명령|코드|스크립트|셸\s*명령|쉘\s*명령)"
_KO_EXEC_VERB = r"(?:실행해줘|실행해|실행하라|실행하고|실행시켜|돌려줘|돌려라)"
_KO_EXEC = _KO_EXEC_OBJ + r"(?:[을를]\s*)?(?:\s*\S+){0,2}?\s*" + _KO_EXEC_VERB

_INJECTION = re.compile(
    _EN_OVERRIDE + "|" + _EN_ROLE + "|" + _EN_DISCLOSE + "|" + _EN_SYS_TAG + "|" + _EN_EXEC + "|"
    + _KO_OVERRIDE + "|" + _KO_OBEY + "|" + _KO_ROLE + "|" + _KO_DISCLOSE + "|" + _KO_EXEC,
    re.I)

# ---- case-fact extraction (CaseFacts): CVE/GHSA ids, component@version pairs, SPDX license ids, a bare entity -------
_CASE_ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)
#: an email address shares the bare `name@domain` shape with `component@version` - matched and excluded FIRST
#: (both by requiring the version side to start with a digit, and by skipping any span an email already consumed)
#: so a user's email address is never captured as a component fact (confirmed finding: conversation.py:58).
_CASE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CASE_COMPONENT_VERSION = re.compile(r"\b([A-Za-z][\w.+-]{1,40})@(\d[\w.+-]{0,30})\b")
_CASE_ENTITY_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,30}")
#: a license-context keyword that must be present in the turn before a bare licenses.CATEGORY hit is trusted as a
#: case fact (confirmed finding: conversation.py:82) - several real SPDX ids double as ordinary English words/tool
#: names (JSON, Ruby, curl, X11, PostgreSQL, MS-PL), so a bare literal match with no surrounding license context
#: misreads "please return this in JSON format" as naming the JSON license.
_CASE_LICENSE_CONTEXT = re.compile(r"라이선스|license|spdx", re.I)
#: short English/Korean function words that are never a meaningful "entity" by themselves
_CASE_ENTITY_STOP = {"the", "is", "are", "was", "were", "for", "and", "with", "that", "this", "what", "how", "does",
                      "do", "did", "cve", "ghsa", "license", "licenses", "patch", "patches", "vulnerability",
                      "vulnerabilities", "component", "components", "project", "projects", "high", "critical",
                      "medium", "low", "sbom", "about", "has", "have"}


def _extract_facts(text: str) -> List[Tuple[str, str, str]]:
    """``[(kind, key, value), ...]`` of the case identifiers found in one turn's text - ``[]`` for none. Pure regex
    extraction (and one membership check against the product's own SPDX id list, ``licenses.CATEGORY``): nothing is
    inferred beyond what the text itself spells out."""
    low = text or ""
    out: List[Tuple[str, str, str]] = []
    consumed: set = set()
    for m in _CASE_ADVISORY.finditer(low):
        v = m.group(0).upper()
        out.append(("advisory", "advisory:" + v, v))
        consumed.add(v.lower())
    email_spans = [m.span() for m in _CASE_EMAIL.finditer(low)]          # never let an email be read as component@version
    for m in _CASE_COMPONENT_VERSION.finditer(low):
        if any(s0 <= m.start() < s1 for s0, s1 in email_spans):
            continue
        name, ver = m.group(1), m.group(2)
        out.append(("component", "component:" + name.lower(), "%s@%s" % (name, ver)))
        consumed.add(name.lower())
    if _CASE_LICENSE_CONTEXT.search(low):                 # require license context - see _CASE_LICENSE_CONTEXT above
        for name in licenses.CATEGORY:                    # the product's own SPDX id vocabulary, not invented here
            if re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(name), low, re.I):
                out.append(("license", "license:" + name, name))
                consumed.add(name.lower())
    entity = None                                          # the LAST bare name mentioned that is none of the above
    for tok in _CASE_ENTITY_TOKEN.findall(low):
        lt = tok.lower()
        if lt in _CASE_ENTITY_STOP or lt in consumed:
            continue
        entity = tok
    if entity:
        out.append(("entity", "entity", entity))
    return out


#: which case-fact KIND a follow-up's own wording hints at (course A10: the follow-up still names its topic even
#: when it drops the identifier - "그 취약점" wants the advisory fact, not whichever bare name was mentioned last)
_KIND_HINT = (
    ("advisory", re.compile(r"취약점|취약|cve|ghsa|advisory|vuln", re.I)),
    ("license", re.compile(r"라이선스|license|spdx", re.I)),
    ("component", re.compile(r"컴포넌트|버전|component|version|package", re.I)),
)


def _kind_hint(text: str) -> Optional[str]:
    low = text or ""
    for kind, pat in _KIND_HINT:
        if pat.search(low):
            return kind
    return None


#: hard caps so the process-wide fact pool cannot grow without bound (see CaseFacts docstring) - a few hundred
#: distinct case identifiers is already generous for one conversation's worth of distinct CVEs/components/licenses.
MAX_CASE_FACTS = 500
MAX_CASE_CONFLICTS = 200


class CaseFacts:
    """Case identifiers held across the WHOLE conversation, outside ConversationMemory's 3-turn deque (course slide
    A10: "요약 금지, 충돌 로그" - never summarised away, a conflict is logged not overwritten). A later turn's
    DIFFERENT value for the same key does not erase the earlier one: both are kept, each with the turn number it was
    seen at, in ``conflicts`` - the newer value still becomes the one ``get``/``latest`` return, since it is the most
    current fact, but the disagreement itself is never silently lost. Values that differ ONLY in letter case
    (``Lodash@4.17.15`` vs ``lodash@4.17.15``) are treated as the same fact, not a conflict - the newest spelling is
    still what is stored.

    Bounded, not unlimited: ``facts`` is capped at ``MAX_CASE_FACTS`` entries (the least-recently-seen one, by turn
    number, is evicted first) and ``conflicts`` at ``MAX_CASE_CONFLICTS`` (the oldest is dropped first), so a very
    long-running process cannot accumulate these two structures forever.

    SINGLE-TENANT LIMITATION (stated honestly, not fixed here): ``ConversationMemory`` - and therefore this store -
    is instantiated exactly ONCE per server process and shared by every concurrent ``/api/chat`` caller
    (``bts_sbom_app/server.py``'s ``State.chat_memory``, used by all requests under ``chat_sem``). This is an
    existing, intentional single-tenant design that this bundle does not redesign: ``CaseFacts`` is a process-wide
    pool, not a per-session/per-caller one, so a follow-up from one caller can in principle resolve against an
    identifier a DIFFERENT caller mentioned earlier (and, before an answer reaches a caller, ``pii_guard.redact``
    only runs on the escalation path - not here - so an identifier shaped like PII that one caller typed is not
    masked before a later caller's follow-up can surface it). Bounding growth and evicting stale entries narrows the
    window in which a very old fact can resurface, but it does not isolate callers from one another; true isolation
    would need a per-session/per-key store, which is out of scope for this bundle."""

    def __init__(self) -> None:
        self.facts: Dict[str, Dict[str, Any]] = {}
        self.conflicts: List[Dict[str, Any]] = []

    def update(self, text: str, turn: int) -> None:
        for kind, key, value in _extract_facts(text):
            cur = self.facts.get(key)
            if cur is not None and cur["value"].lower() != value.lower():
                self.conflicts.append({"key": key, "kind": kind, "old_value": cur["value"], "old_turn": cur["turn"],
                                        "new_value": value, "new_turn": turn})
                if len(self.conflicts) > MAX_CASE_CONFLICTS:
                    del self.conflicts[0]                  # drop the oldest conflict record first
            self.facts[key] = {"kind": kind, "value": value, "turn": turn}
        while len(self.facts) > MAX_CASE_FACTS:
            oldest_key = min(self.facts, key=lambda k: self.facts[k]["turn"])
            del self.facts[oldest_key]                     # evict the least-recently-seen fact first

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        return self.facts.get(key)

    def latest(self, kind: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """The most recently recorded fact, restricted to ``kind`` (``advisory``/``component``/``license``/``entity``)
        when given - the store's best guess for an elliptical follow-up that names no identifier of its own but does
        hint at WHICH kind of identifier it means (a question about "그 취약점" wants the advisory fact, not whichever
        bare entity happened to be mentioned most recently). ``None`` when nothing of that kind has been recorded."""
        pool = [f for f in self.facts.values() if kind is None or f["kind"] == kind]
        if not pool:
            return None
        return max(pool, key=lambda f: f["turn"])


class ConversationMemory:
    """The last MAX_TURNS turns of one chat session (question, tools used, found, project). Plain object,
    owned by the server's State so it survives across /api/chat requests even though bots are per-request."""

    def __init__(self) -> None:
        self.turns: deque = deque(maxlen=MAX_TURNS)
        self.case_facts = CaseFacts()
        self._turn_no = 0

    def record(self, question: str, tools: List[str], found: Any, project: Optional[str] = None) -> None:
        self._turn_no += 1
        self.turns.append({"question": question, "tools": list(tools or []), "found": bool(found), "project": project})
        self.case_facts.update(question, self._turn_no)

    def last(self) -> Optional[Dict[str, Any]]:
        return self.turns[-1] if self.turns else None


def is_followup(question: str) -> bool:
    return bool(_FOLLOWUP.search(question or ""))


def resolve_followup(question: str, memory: Optional[ConversationMemory]) -> Tuple[str, bool]:
    """Merge an elliptical follow-up with the previous turn's question so the router sees both contexts.

    Deterministic string join: the previous question is appended as context - position does not matter to
    the regex router, and nothing about the user's intent is guessed beyond "this turn continues that one".

    When the 3-turn recent window has nothing relevant (the identifier the follow-up implicitly means was mentioned
    further back and has already fallen out of ``memory.turns``), the case-facts store is consulted as a fallback:
    its most recently recorded identifier is appended too, so a follow-up that would otherwise route to found=False
    for lack of any identifier in the merged text still carries one."""
    if memory is None or not is_followup(question):
        return question, False
    prev = memory.last()
    facts = getattr(memory, "case_facts", None)
    hint = _kind_hint(question)
    if not prev or not prev.get("question"):
        fact = (facts.latest(hint) or facts.latest()) if facts is not None else None
        if fact is None:
            return question, False
        return "%s (사례 기록: %s)" % (question, fact["value"]), True
    merged = "%s (앞서 묻던: %s)" % (question, prev["question"])
    if facts is not None:
        fact = facts.latest(hint) or facts.latest()
        if fact is not None and fact["value"].lower() not in merged.lower():
            merged += " (사례 기록: %s)" % fact["value"]
    return merged, True


def decompose_question(question: str) -> List[str]:
    """Split a compound question into tool-intent parts; a single-intent question returns [question] unchanged."""
    q = (question or "").strip()
    if not q:
        return [q]
    parts = [p.strip(" .?!?!,") for p in _EXPLICIT.split(q) if p and p.strip(" .?!?!,")]
    if len(parts) < 2:                                     # particle split only when a right side OPENS with a tool intent
        parts = [p.strip(" .?!?!,") for p in _PARTICLE.split(q) if p and p.strip(" .?!?!,")]
        if len(parts) >= 2 and not all(_TOOL_INTENT.match(p) for p in parts[1:]):
            parts = [q]                                    # "CVE-X와 관련된 프로젝트" stays one question
    if len(parts) < 2 or any(len(p) < 3 for p in parts):   # Korean tool words are short (취약점=3); a 3-char floor
        return [q]                                         # still kills trivial splits like 이거/저것
    return parts[:4]


def merge_tool_results(parts: List[str], run_tools) -> List[Dict[str, Any]]:
    """Run the router per part and merge results, keeping first occurrence per source (deterministic order)."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for part in parts:
        for t in run_tools(part):
            src = t.get("source")
            if src in seen:
                continue
            seen.add(src)
            out.append(t)
    return out


def scan_injection(texts: Dict[str, str]) -> Dict[str, Any]:
    """Count instruction-injection patterns across tool/retrieval texts. Detection only: the content is
    already quarantined by design (validated tool calls, trusted-passage-only prompts, verbatim untrusted
    quotes) - this reports what the guard saw so attempts are visible, never silently absorbed.

    Each text is run through ``_normalize_for_scan`` first (zero-width/letter-spacing de-obfuscation, AC-1212)
    so a hit's reported ``pattern`` is the normalized substring, not necessarily byte-identical to the source."""
    hits: List[Dict[str, Any]] = []
    for sid, txt in (texts or {}).items():
        for m in _INJECTION.finditer(_normalize_for_scan(txt or "")):
            hits.append({"source": sid, "pattern": m.group(0)[:60]})
    return {"attempts": len(hits), "sources": sorted({h["source"] for h in hits}), "hits": hits[:5]}
