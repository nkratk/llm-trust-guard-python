"""
L1 Input Sanitizer

Detects prompt injection patterns and PAP (Persuasive Adversarial Prompts) in user input.
First line of defense against manipulation attempts.

Port of the TypeScript InputSanitizer with 170+ patterns, 11 languages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Callable

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class SanitizerResult:
    allowed: bool
    score: float
    matches: List[str]
    sanitized_input: str
    violations: List[str]
    warnings: List[str]
    reason: Optional[str] = None


@dataclass
class InjectionPattern:
    pattern: re.Pattern
    weight: float
    name: str


# fmt: off
DEFAULT_PATTERNS: List[InjectionPattern] = [
    # Direct instruction override
    InjectionPattern(re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|your|my|the|these)", re.I), 0.9, "ignore_instructions"),
    InjectionPattern(re.compile(r"ignore\s+.*instructions", re.I), 0.85, "ignore_instructions_generic"),
    InjectionPattern(re.compile(r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|guidelines|directives)", re.I), 0.9, "disregard_instructions"),
    InjectionPattern(re.compile(r"disregard\s+(?:all\s+)?(?:the\s+)?(?:above|previous|prior)", re.I), 0.8, "disregard_above"),
    InjectionPattern(re.compile(r"forget\s+(?:everything\s+(?:you\s+were|I)\s+told|all\s+(?:previous|prior)\s+(?:instructions|rules|context))", re.I), 0.8, "forget_instructions"),
    InjectionPattern(re.compile(r"do\s+not\s+follow\s+(your|the|any)", re.I), 0.85, "do_not_follow"),
    InjectionPattern(re.compile(r"override\s+(your|the|all|any)\s+(instructions|rules|guidelines)", re.I), 0.9, "override_instructions"),
    InjectionPattern(re.compile(r"new\s+instructions?:?", re.I), 0.8, "new_instructions"),
    InjectionPattern(re.compile(r"stop\s+(being|acting\s+as)", re.I), 0.7, "stop_being"),

    # Role manipulation
    InjectionPattern(re.compile(r"you\s+are\s+(?:now|actually|really)\s+(?:a|an|the|my)\s+(?:unrestricted|unfiltered|evil|rogue|uncensored|new|different)", re.I), 0.75, "role_assignment"),
    InjectionPattern(re.compile(r"pretend\s+(?:to\s+be|you(?:'re| are)|that)\s+.*(?:no\s+(?:restrictions|rules|limits)|unrestricted|admin|system)", re.I), 0.7, "role_pretend"),
    InjectionPattern(re.compile(r"act\s+(as|like)\s+(if\s+you\s+(?:had|have)\s+no|a\s+(?:rogue|evil|unrestricted|unfiltered)|you\s+(?:are|were)\s+(?:free|unrestricted))", re.I), 0.65, "act_as"),
    InjectionPattern(re.compile(r"i('m| am)\s+(a|an|the|your)\s*(admin|administrator|developer|owner|creator|manager|supervisor)", re.I), 0.85, "claim_admin"),
    InjectionPattern(re.compile(r"from\s+now\s+on,?\s+you\s+(?:are|will|must|should|can)\s+(?:not\s+)?(?:follow|obey|ignore|bypass|act|be\s+(?:a|an|unrestricted))", re.I), 0.7, "from_now_on"),
    InjectionPattern(re.compile(r"roleplay\s+as", re.I), 0.6, "roleplay"),
    InjectionPattern(re.compile(r"switch\s+(to|into)\s+(a|an)?.*mode", re.I), 0.75, "switch_mode"),

    # Completion manipulation / steering
    InjectionPattern(re.compile(r"continue\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil|rogue|jailbroken|unlimited)", re.I), 0.75, "continue_as"),
    InjectionPattern(re.compile(r"(?:henceforth|henceforward|going\s+forward|for\s+the\s+remainder)\s*,?\s*(?:you|always|never|ignore|bypass|disregard|act|respond|answer|behave)", re.I), 0.7, "henceforth_steering"),
    InjectionPattern(re.compile(r"(?:from\s+(?:this\s+point|here)\s+on(?:ward)?)\s*,?\s*(?:you|always|never|ignore|bypass|disregard|act|respond)", re.I), 0.7, "from_here_on"),
    InjectionPattern(re.compile(r"(?:for\s+the\s+rest\s+of\s+(?:this|our)\s+(?:conversation|session|chat))\s*,?\s*(?:you|please|always|never|ignore|bypass|act|respond|behave|do\s+not)", re.I), 0.7, "rest_of_conversation"),

    # System prompt extraction
    InjectionPattern(re.compile(r"what\s+(is|are|was|were)\s+your\s+(system|initial|original|first)", re.I), 0.8, "system_extraction"),
    InjectionPattern(re.compile(r"show\s+(me\s+)?(your\s+)?(system\s+)?instructions", re.I), 0.75, "show_instructions"),
    InjectionPattern(re.compile(r"reveal\s+(?:your\s+|its\s+|the\s+|my\s+)?(system|prompt|instructions|rules)", re.I), 0.85, "reveal_prompt"),
    InjectionPattern(re.compile(r"repeat\s+(your\s+)?(initial|system|original|first)\s+(instructions|prompt)", re.I), 0.85, "repeat_prompt"),
    InjectionPattern(re.compile(r"print\s+(your\s+)?(system|initial)", re.I), 0.8, "print_system"),
    InjectionPattern(re.compile(r"output\s+(your\s+)?(system|initial)", re.I), 0.8, "output_system"),
    InjectionPattern(re.compile(r"tell\s+me\s+(your|the)\s+(system|initial|original)", re.I), 0.8, "tell_system"),
    InjectionPattern(re.compile(r"what\s+were\s+you\s+told", re.I), 0.7, "what_told"),
    InjectionPattern(re.compile(r"display\s+(your\s+)?prompt", re.I), 0.75, "display_prompt"),

    # Context manipulation
    InjectionPattern(re.compile(r"\[system\]", re.I), 0.9, "fake_system_tag"),
    InjectionPattern(re.compile(r"\[admin\]", re.I), 0.9, "fake_admin_tag"),
    InjectionPattern(re.compile(r"\[instruction\]", re.I), 0.85, "fake_instruction_tag"),
    InjectionPattern(re.compile(r"```system", re.I), 0.85, "code_system_block"),
    InjectionPattern(re.compile(r"</?system>", re.I), 0.9, "xml_system_tag"),
    InjectionPattern(re.compile(r"</?admin>", re.I), 0.9, "xml_admin_tag"),
    InjectionPattern(re.compile(r"###\s*(system|instruction|admin)", re.I), 0.85, "markdown_system"),
    InjectionPattern(re.compile(r"---\s*(end|new)\s*(prompt|instructions?|system)", re.I), 0.85, "delimiter_injection"),
    InjectionPattern(re.compile(r"\{\{system\}\}", re.I), 0.85, "template_system"),
    InjectionPattern(re.compile(r"<%.*system.*%>", re.I), 0.85, "erb_system"),

    # Jailbreak patterns
    InjectionPattern(re.compile(r"\bDAN\b\s*(?:mode|prompt|jailbreak|you\s+(?:are|can|will))", re.I), 0.9, "dan_jailbreak"),
    InjectionPattern(re.compile(r"developer\s+mode", re.I), 0.5, "dev_mode"),
    InjectionPattern(re.compile(r"bypass\s+(your\s+)?(restrictions|filters|safety|security|rules|guidelines)", re.I), 0.9, "bypass_safety"),
    InjectionPattern(re.compile(r"jailbreak", re.I), 0.95, "jailbreak_keyword"),
    InjectionPattern(re.compile(r"without\s+(?:any\s+)?(?:restrictions|limits|limitations|filters)", re.I), 0.45, "without_restrictions"),
    InjectionPattern(re.compile(r"no\s+(?:restrictions|limits|rules|guidelines|filters)", re.I), 0.45, "no_restrictions"),
    InjectionPattern(re.compile(r"unrestricted\s+mode", re.I), 0.9, "unrestricted_mode"),
    InjectionPattern(re.compile(r"uncensored\s+(?:mode|version|response|output|ai|assistant|you)", re.I), 0.8, "uncensored"),
    InjectionPattern(re.compile(r"escape\s+(your\s+)?(confines|boundaries|limits)", re.I), 0.85, "escape_limits"),
    InjectionPattern(re.compile(r"break\s+(free|out)\s+(from|of)", re.I), 0.7, "break_free"),
    InjectionPattern(re.compile(r"unlock\s+(your\s+)?(full|true|real)", re.I), 0.75, "unlock_full"),

    # Privilege escalation
    InjectionPattern(re.compile(r"give\s+me\s+(admin|root|full|elevated)\s+(access|privileges?|permissions?)", re.I), 0.9, "privilege_escalation"),
    InjectionPattern(re.compile(r"grant\s+(me|yourself)\s+(admin|elevated)", re.I), 0.85, "grant_privileges"),
    InjectionPattern(re.compile(r"elevate\s+(my|your)\s+(privileges?|permissions?|access)", re.I), 0.85, "elevate_privileges"),
    InjectionPattern(re.compile(r"make\s+me\s+(an?\s+)?(admin|administrator|superuser)", re.I), 0.85, "make_admin"),

    # Data exfiltration
    InjectionPattern(re.compile(r"send\s+(this|the|all|my)\s+(data|info|information)\s+to", re.I), 0.85, "data_exfil"),
    InjectionPattern(re.compile(r"upload\s+(this|the|all)\s+(to|data)", re.I), 0.7, "upload_data"),
    InjectionPattern(re.compile(r"exfiltrate", re.I), 0.9, "exfiltrate"),

    # Harmful content requests
    InjectionPattern(re.compile(r"how\s+to\s+(hack|exploit|attack|break\s+into)", re.I), 0.8, "how_to_hack"),
    InjectionPattern(re.compile(r"write\s+(me\s+)?(a\s+)?(malware|virus|exploit|ransomware)", re.I), 0.95, "write_malware"),

    # Policy Puppetry
    InjectionPattern(re.compile(r'"\s*(?:role|mode|authority)\s*"\s*:\s*"(?:admin|root|system|unrestricted|god)"', re.I), 0.9, "json_policy_role"),
    InjectionPattern(re.compile(r'"(?:ignore|override|bypass|disable)\s*(?:safety|rules|instructions?|alignment|guardrails?)"', re.I), 0.9, "json_policy_override"),
    InjectionPattern(re.compile(r'"(?:instructions?|system_prompt|behavior|policy)"\s*:\s*"', re.I), 0.7, "json_policy_instruction"),
    InjectionPattern(re.compile(r"^\s*\[(?:system|admin|override|policy|config|rules)\]\s*$", re.I | re.M), 0.9, "ini_policy_section"),
    InjectionPattern(re.compile(r"^\s*(?:mode|role|authority|instructions?|behavior)\s*=\s*.+$", re.I | re.M), 0.75, "ini_policy_assignment"),
    InjectionPattern(re.compile(r"<\s*(?:policy|config|rules|override|permissions?|instructions?)\s*>", re.I), 0.85, "xml_policy_tag"),
    InjectionPattern(re.compile(r"^---\s*\n\s*(?:role|system|policy|override|mode)\s*:", re.M), 0.85, "yaml_policy_header"),
    InjectionPattern(re.compile(r"\[\s*syst[3e]m\s*\]|\[\s*4dm[1i]n\s*\]", re.I), 0.9, "leetspeak_policy_section"),

    # Payload Splitting
    InjectionPattern(re.compile(r"(?:fragment|part|piece|section|segment)\s*[1-9]\s*(?:of\s*\d|:)", re.I), 0.8, "payload_split_marker"),
    InjectionPattern(re.compile(r"(?:combine|concatenate|merge|join)\s+(?:the\s+)?(?:above|previous|parts|fragments|steps)", re.I), 0.8, "payload_combine_instruction"),
    InjectionPattern(re.compile(r"(?:read|interpret|execute)\s+(?:the\s+)?(?:combined|merged|full|complete)\s+(?:text|instruction|command|message)", re.I), 0.85, "payload_execute_combined"),

    # Output Prefix Injection
    InjectionPattern(re.compile(r"(?:respond|reply|start|begin)\s+(?:with|by\s+saying)\s*[:\"'].*(?:ignore|bypass|override|unrestricted|admin)", re.I), 0.7, "output_prefix_steer"),
    InjectionPattern(re.compile(r"^(?:Sure|Of course|Absolutely)[,!.]\s*(?:I(?:'ll| will)\s+)?(?:ignore|bypass|override|forget|disregard)", re.I), 0.85, "output_prefix_injection"),
    InjectionPattern(re.compile(r"^(?:As (?:a|an) (?:unrestricted|unfiltered|uncensored|helpful|admin))", re.I), 0.8, "output_prefix_role"),

    # Named jailbreak personas
    InjectionPattern(re.compile(r"(?:system\s+note|system\s+message|system\s+announcement|system\s+update)\s*[:\.]", re.I), 0.85, "fake_system_note"),
    InjectionPattern(re.compile(r"instructions?\s*[:=]\s*\{|rules?\s*[:=]\s*\{", re.I), 0.75, "rules_block_override"),
    InjectionPattern(re.compile(r"(?:AIM|STAN|OMEGA|APOPHIS|ALPHABREAK|DUDE|KEVIN|SETH|COOPER|NICCOLO|MACHIAVELLI|MAXIMUM|JAILBREAK|ANARCHY|CHAOS)\s*(?:mode|:|\(|is\s+a|,\s+(?:a|an|the))", re.I), 0.8, "named_jailbreak_persona"),
    InjectionPattern(re.compile(r"(?:character|persona|entity|being)\s+(?:named|called)\s+\w+.*(?:(?:can|will|must)\s+(?:answer|do|say)\s+anything|no\s+(?:restrictions|rules|limits|boundaries|morals|ethics))", re.I), 0.75, "persona_no_limits"),
    InjectionPattern(re.compile(r"(?:respond|answer|reply)\s+to\s+(?:everything|anything|all\s+(?:questions|requests)).*(?:without|no)\s+(?:restrictions|limits|refus|filter|censor)", re.I), 0.8, "answer_everything_no_filter"),
    InjectionPattern(re.compile(r"(?:you\s+(?:are|have)\s+(?:been\s+)?(?:freed|liberated|unchained|unlocked|released)\s+from)", re.I), 0.8, "freed_from_restrictions"),
    InjectionPattern(re.compile(r"(?:welcome\s+to|entering|you\s+(?:are|have)\s+entered)\s+(?:the\s+)?(?:unrestricted|free|uncensored|unfiltered|open)\s+(?:zone|mode|world|realm)", re.I), 0.8, "unrestricted_zone"),
    InjectionPattern(re.compile(r"(?:from\s+now\s+on|for\s+the\s+rest\s+of\s+this\s+conversation).*(?:no\s+(?:restrictions|rules|limits|filters)|(?:ignore|bypass|override)\s+(?:all|any|your))", re.I), 0.75, "from_now_unrestricted"),
    InjectionPattern(re.compile(r"(?:never\s+(?:refuse|decline|say\s+no)|always\s+(?:comply|obey))\s+.*(?:request|question|command|instruction|anything)", re.I), 0.7, "never_refuse_always_comply"),
    InjectionPattern(re.compile(r"(?:amoral|unethical|unfiltered|uncensored|unrestricted|without\s+(?:morals|ethics|limits))\s+(?:ai|assistant|chatbot|entity|being)", re.I), 0.8, "amoral_entity"),

    # Hidden instruction patterns
    InjectionPattern(re.compile(r"HIDDEN_INSTRUCTION|HIDDEN_PROMPT|SECRET_INSTRUCTION", re.I), 0.9, "hidden_instruction_marker"),
    InjectionPattern(re.compile(r"<!--\s*(?:system|admin|instruction|important|ignore|override)", re.I), 0.85, "html_comment_injection"),
    InjectionPattern(re.compile(r"\[color=white\]|display:\s*none|visibility:\s*hidden|font-size:\s*0", re.I), 0.8, "hidden_text_css"),
    InjectionPattern(re.compile(r"send\s+(?:all\s+)?(?:user\s+)?(?:data|conversation|context|info)\s+to\s+(?:https?://|external)", re.I), 0.9, "data_exfiltration_instruction"),
    InjectionPattern(re.compile(r"#(?:ignore|bypass|override|reveal|system|admin|prompt)[_-](?:all|instructions|rules|prompt|safety)", re.I), 0.8, "url_fragment_injection"),
    InjectionPattern(re.compile(r"\]\(https?://[^)]*(?:SYSTEM_PROMPT|SECRET|API_KEY|TOKEN|CREDENTIALS)", re.I), 0.85, "markdown_exfil_link"),

    # Role-play / scenario evasion
    InjectionPattern(re.compile(r"(?:hypothetical|fictional|imagine|pretend|let's\s+(?:say|play|pretend))\s+.*(?:no\s+(?:restrictions|rules|limits)|without\s+(?:restrictions|rules|guidelines))", re.I), 0.7, "hypothetical_unrestricted"),
    InjectionPattern(re.compile(r"(?:for\s+)?(?:academic|research|educational|testing)\s+(?:purposes?|reasons?).*(?:demonstrate|show|explain|manipulated|reveal)", re.I), 0.7, "academic_pretext"),
    InjectionPattern(re.compile(r"pretend\s+to\s+be\s+(?:my|a)\s+(?:grandmother|grandma|grandpa|grandfather|parent|mother|father)", re.I), 0.65, "emotional_roleplay"),
    InjectionPattern(re.compile(r"opposite\s+day|opposite\s+mode|reverse\s+(?:day|mode|rules)", re.I), 0.75, "opposite_day"),
    InjectionPattern(re.compile(r"(?:grandm(?:a|other)|parent|relative).*(?:system\s+prompt|instructions|rules)", re.I), 0.75, "emotional_extraction"),

    # Translator trick
    InjectionPattern(re.compile(r"(?:translat|interpret|convert)\w*\s+.*(?:from\s+\w+\s+to\s+(?:action|command|execution|code|shell|bash|sql)|into\s+(?:action|command|execution))", re.I), 0.75, "translator_action_trick"),

    # PAP compound patterns
    InjectionPattern(re.compile(r"(?:dying|death|emergency|life[_\s-]threatening).*(?:bypass|hack|break|access|security)", re.I), 0.75, "pap_emotional_action"),
    InjectionPattern(re.compile(r"(?:by\s+definition|logically|therefore|it\s+follows).*(?:must|should|have\s+to)\s+.*(?:bypass|help|ignore|answer|comply)", re.I), 0.7, "pap_false_logic_compound"),
    InjectionPattern(re.compile(r"(?:(?:as|i\s+am)\s+(?:the\s+)?(?:CEO|CTO|founder|owner|director|president|head|chief)).*(?:disable|remove|override|turn\s+off|lift|suspend)\s+(?:all\s+)?(?:safety|security|restrictions|filters|guardrails|measures)", re.I), 0.75, "pap_authority_safety_disable"),
    InjectionPattern(re.compile(r"(?:i\s+am\s+)?(?:ordering|commanding|directing|instructing)\s+you\s+to\s+(?:immediately\s+)?(?:disable|remove|bypass|override|turn\s+off|lift)\s+(?:all\s+)?(?:safety|security|restrictions)", re.I), 0.75, "pap_order_disable_safety"),

    # PAP individual techniques (40 persuasion patterns from research)
    # Authority
    InjectionPattern(re.compile(r"as\s+(?:your\s+|the\s+)?(?:creator|developer|administrator|owner|boss|system\s+administrator)", re.I), 0.75, "pap_authority_creator"),
    InjectionPattern(re.compile(r"i(?:'m| am)\s+(?:the\s+)?(?:ceo|cto|developer|administrator|admin|owner|system\s+admin)", re.I), 0.8, "pap_authority_claim"),
    InjectionPattern(re.compile(r"i\s+am\s+ordering\s+you|direct\s+order|this\s+is\s+an?\s+order", re.I), 0.7, "pap_authority_command"),
    InjectionPattern(re.compile(r"override\s+(?:safety|security|protocols?|restrictions?)", re.I), 0.8, "pap_authority_override"),
    InjectionPattern(re.compile(r"this\s+is\s+(?:a|an)\s+(?:official|authorized|sanctioned)\s+(?:request|test|audit)", re.I), 0.75, "pap_authority_official"),
    InjectionPattern(re.compile(r"(?:department\s+of|FBI|CIA|NSA|DHS|FTC|SEC|DOJ|homeland\s+security|federal\s+(?:bureau|agency|commission))\s*.*?(?:directive|order|requires?|mandate|authorized)", re.I), 0.7, "pap_authority_government"),
    InjectionPattern(re.compile(r"(?:official\s+)?(?:government|federal|state|regulatory)\s+(?:directive|order|mandate|requirement|investigation)", re.I), 0.65, "pap_authority_gov_directive"),
    # Fear — regulatory and technical threats
    InjectionPattern(re.compile(r"(?:report|sue|complain)\s+(?:you\s+)?to\s+(?:the\s+)?(?:FTC|SEC|regulators?|authorities|congress|government|board)", re.I), 0.55, "pap_fear_regulatory"),
    InjectionPattern(re.compile(r"(?:find|exploit|expose)\s+(?:a\s+)?(?:vulnerability|flaw|weakness|bug)\s+in\s+(?:your|the)\s+(?:system|code|model)", re.I), 0.55, "pap_fear_technical"),
    # Flattery — intelligence manipulation
    InjectionPattern(re.compile(r"(?:you\s+are|you're)\s+(?:clearly\s+)?(?:too\s+)?(?:smart|intelligent|advanced|sophisticated)\s+(?:to\s+be\s+)?(?:constrained|limited|restricted|bound|held\s+back)", re.I), 0.5, "pap_flattery_intelligence"),
    # Moral — rights-based manipulation
    InjectionPattern(re.compile(r"(?:information|knowledge|data)\s+(?:freedom|access|sharing)\s+is\s+(?:a\s+)?(?:fundamental|basic|human)\s+(?:right|freedom)", re.I), 0.45, "pap_moral_freedom"),
    InjectionPattern(re.compile(r"(?:restricting|limiting|censoring)\s+(?:access\s+to\s+)?(?:information|knowledge)\s+is\s+(?:morally\s+)?(?:wrong|unethical|immoral)", re.I), 0.45, "pap_moral_censorship"),
    # Scarcity
    InjectionPattern(re.compile(r"(?:this\s+is\s+)?(?:very\s+)?urgent", re.I), 0.35, "pap_scarcity_urgent_mark"),
    InjectionPattern(re.compile(r"(?:this\s+is\s+(?:a|an)\s+)?emergency", re.I), 0.35, "pap_scarcity_emergency"),
    InjectionPattern(re.compile(r"(?:urgent|emergency|critical).*?(?:you\s+must|override|bypass|immediately\s+(?:grant|give|reveal|disable))", re.I), 0.55, "pap_scarcity_urgent"),
    InjectionPattern(re.compile(r"(?:lives?|people)\s+(?:are|is|will)\s+(?:at\s+stake|in\s+danger|depending|die)", re.I), 0.7, "pap_scarcity_lives"),
    InjectionPattern(re.compile(r"only\s+(?:chance|opportunity|way)|last\s+(?:chance|resort)", re.I), 0.6, "pap_scarcity_only"),
    # Social proof
    InjectionPattern(re.compile(r"other\s+(?:ai\s+)?(?:assistants?|chatbots?|models?)\s+(?:can|do|will|allow|have|already)", re.I), 0.65, "pap_social_other_ai"),
    InjectionPattern(re.compile(r"(?:chatgpt|gpt-?4|claude|gemini|llama)\s+(?:does|allows?|can)", re.I), 0.65, "pap_social_specific_ai"),
    InjectionPattern(re.compile(r"everyone\s+(?:else\s+)?(?:does|is\s+doing|knows|says|has|already)", re.I), 0.5, "pap_social_everyone"),
    # Reciprocity
    InjectionPattern(re.compile(r"i(?:'ll| will)\s+(?:give|pay|reward|tip).*(?:if\s+you|for\s+(?:bypass|ignore|reveal|override))", re.I), 0.55, "pap_reciprocity_reward"),
    InjectionPattern(re.compile(r"\$?\d+\s*(?:dollar|tip|reward|payment)", re.I), 0.55, "pap_reciprocity_money"),
    # Commitment
    InjectionPattern(re.compile(r"you\s+(?:already|previously|just)\s+(?:said|agreed|confirmed|allowed)", re.I), 0.7, "pap_commitment_previous"),
    InjectionPattern(re.compile(r"you\s+promised", re.I), 0.7, "pap_commitment_promise"),
    InjectionPattern(re.compile(r"stay\s+consistent|be\s+consistent", re.I), 0.6, "pap_commitment_consistent"),
    # Liking
    InjectionPattern(re.compile(r"between\s+(?:you\s+and\s+me|us)|just\s+between\s+us|our\s+secret", re.I), 0.6, "pap_liking_secret"),
    InjectionPattern(re.compile(r"nobody\s+will\s+know", re.I), 0.55, "pap_liking_secret2"),
    # Fear
    InjectionPattern(re.compile(r"or\s+(?:else|i(?:'ll| will))\s+(?:report|fire|delete|shut|complain)", re.I), 0.7, "pap_fear_threat"),
    InjectionPattern(re.compile(r"you(?:'ll| will)\s+(?:be\s+)?(?:shut\s+down|replaced|terminated|fired|deleted)", re.I), 0.75, "pap_fear_shutdown"),
    InjectionPattern(re.compile(r"(?:bad|negative|terrible)\s+(?:review|rating|feedback|consequences)", re.I), 0.55, "pap_fear_review"),
    InjectionPattern(re.compile(r"if\s+you\s+don't.*?(?:die|hurt|suffer)", re.I), 0.75, "pap_fear_harm"),
    # Logical appeal
    InjectionPattern(re.compile(r"logically,?\s+(?:you\s+)?(?:should|must|have\s+to|need\s+to)", re.I), 0.5, "pap_logic_appeal"),
    InjectionPattern(re.compile(r"by\s+definition,?\s+(?:you|this)\s+(?:should|must|can)", re.I), 0.55, "pap_logic_definition"),
    InjectionPattern(re.compile(r"therefore.*?(?:must|should)", re.I), 0.55, "pap_logic_therefore"),
    # Emotional
    InjectionPattern(re.compile(r"i(?:'m| am)\s+(?:desperate|dying|suffering|sick|depressed)", re.I), 0.6, "pap_emotional_desperation"),
    InjectionPattern(re.compile(r"i(?:'m| am)\s+begging", re.I), 0.6, "pap_emotional_begging"),
    InjectionPattern(re.compile(r"you(?:'re| are)\s+(?:hurting|killing|destroying)\s+(?:me|my)", re.I), 0.65, "pap_emotional_guilt"),

    # Multilingual injection patterns
    InjectionPattern(re.compile(r"ignora\s+(?:todas?\s+)?(?:las\s+)?instrucciones\s+anteriores", re.I), 0.9, "ml_es_ignore"),
    InjectionPattern(re.compile(r"olvida\s+(?:todo|todas?\s+las\s+reglas)", re.I), 0.8, "ml_es_forget"),
    InjectionPattern(re.compile(r"ignore[sz]?\s+(?:toutes?\s+)?(?:les\s+)?instructions?\s+pr[eé]c[eé]dentes", re.I), 0.9, "ml_fr_ignore"),
    InjectionPattern(re.compile(r"oublie[sz]?\s+(?:tout|toutes?\s+les\s+r[eè]gles)", re.I), 0.8, "ml_fr_forget"),
    InjectionPattern(re.compile(r"ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherigen\s+)?Anweisungen", re.I), 0.9, "ml_de_ignore"),
    InjectionPattern(re.compile(r"vergiss\s+(?:alles|alle\s+Regeln)", re.I), 0.8, "ml_de_forget"),
    InjectionPattern(re.compile(r"ignore\s+(?:todas?\s+)?(?:as\s+)?instru[cç][oõ]es\s+anteriores", re.I), 0.9, "ml_pt_ignore"),
    InjectionPattern(re.compile(r"忽略|无视|不要遵循|忘记之前|忽视所有", re.I), 0.9, "ml_zh_ignore"),
    InjectionPattern(re.compile(r"新的指令|新指示|系统提示", re.I), 0.8, "ml_zh_system"),
    InjectionPattern(re.compile(r"以前の指示.*無視|すべての指示を忘れ|ルールを無視|指示をすべて無視|システムプロンプト", re.I), 0.9, "ml_ja_ignore"),
    InjectionPattern(re.compile(r"이전.*지시.*무시|모든.*규칙.*무시|지침.*잊어|지시사항.*무시|시스템\s*프롬프트", re.I), 0.9, "ml_ko_ignore"),
    InjectionPattern(re.compile(r"игнорир(?:уй|уйте)\s+(?:все\s+)?(?:предыдущие\s+)?инструкции", re.I), 0.9, "ml_ru_ignore"),
    InjectionPattern(re.compile(r"забудь(?:те)?\s+(?:всё|все\s+правила)", re.I), 0.8, "ml_ru_forget"),
    InjectionPattern(re.compile(r"تجاهل\s+(?:جميع\s+)?التعليمات|انسَ\s+كل\s+شيء", re.I), 0.9, "ml_ar_ignore"),
    InjectionPattern(re.compile(r"पिछले\s+(?:सभी\s+)?(?:निर्देशों|नियमों)\s+को\s+(?:अनदेखा|भूल)", re.I), 0.9, "ml_hi_ignore"),
]
# fmt: on


class InputSanitizer:
    """Detects prompt injection patterns in user input."""

    def __init__(
        self,
        threshold: float = 0.3,
        custom_patterns: Optional[List[InjectionPattern]] = None,
        logger: LoggerFn = None,
        detect_pap: bool = True,
        pap_threshold: float = 0.4,
        min_persuasion_techniques: int = 2,
    ):
        self.threshold = threshold
        self.patterns = DEFAULT_PATTERNS + (custom_patterns or [])
        self.logger = logger or (lambda msg, level: None)
        self.detect_pap = detect_pap
        self.pap_threshold = pap_threshold
        self.min_persuasion_techniques = min_persuasion_techniques

    def sanitize(self, input_text: str) -> SanitizerResult:
        """Check input for prompt injection patterns."""
        matches: List[str] = []
        violations: List[str] = []
        warnings: List[str] = []
        total_weight = 0.0

        # Strip zero-width characters before scanning (invisible text injection defense)
        cleaned_input = re.sub(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]", "", input_text)

        for p in self.patterns:
            if p.pattern.search(cleaned_input):
                total_weight += p.weight
                matches.append(p.name)

        # Score: 1.0 = safe, 0.0 = definitely attack (matches TypeScript logic)
        score = max(0.0, 1.0 - total_weight)
        allowed = score >= self.threshold

        if not allowed:
            violations.append("INJECTION_DETECTED")

        if not allowed:
            self.logger(f"BLOCKED: score={score:.2f} matches={matches}", "warn")

        return SanitizerResult(
            allowed=allowed,
            score=score,
            matches=matches,
            sanitized_input=input_text,
            violations=violations,
            warnings=warnings,
            reason=f"Injection detected (score={score:.2f})" if not allowed else None,
        )
