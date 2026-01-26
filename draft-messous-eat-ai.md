---
title: "Entity Attestation Token (EAT) Profile for Autonomous AI Agents"

category: Informational

docname: draft-messous-EAT-AI
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date: 29/10/2025
consensus: ...
v: 1
area: SEC
workgroup: RATS
keyword:
 - AI Agents
 - Entity Attestation Token (EAT) 
 - RATS
 - Trust
venue:
group: WG
type: Working Group
mail: ....
arch: ....
github: https://github.com/mmessous/draft-messous-EAT-AI/tree/main
latest: ....



authors:
 -
    fullname: Ayoub MESSOUS, Lionel MORAND
    organization: Huawei R&D
    email: ayoub.messous@huawei.com

 ---
 
# Entity Attestation Token (EAT) Profile for Autonomous AI Agents

## Abstract

This document defines a profile for the Entity Attestation Token (EAT) to support remote attestation of autonomous AI agents across domains. It specifies a set of standardized claims for attesting the integrity of AI model parameters, the provenance of training data, and the constraints of inference-time data access policies. Optional extensions for 5G/6G network functions—such as slice-type authorization—are included for interoperability with ETSI ENI and 3GPP architectures. The profile is encoded in CBOR Web Tokens (CWTs) or JSON Web Tokens (JWTs) and is designed to be used within the IETF RATS architecture.



## 1. Introduction

Autonomous AI agents—software entities that perceive, reason, and act with minimal human oversight—are deployed across cloud, edge, enterprise, and telecommunications environments. Their autonomy introduces new trust challenges: if an agent’s model is tampered, its training data is non-compliant, or its inference policy is violated, the consequences range from service disruption to regulatory breaches.

The Entity Attestation Token (EAT) [RFC9711] provides a standardized framework for remote attestation. However, EAT does not define claims specific to AI artifacts. This document fills that gap by specifying a **generic EAT profile for AI agents**, with **optional telecom-specific claims** for use in 5G/6G networks (e.g., ETSI ENI AI-Core [ETSI-GR-ENI-051], 3GPP TS 29.510).

This profile enables verifiers—such as OAuth resource servers, network function orchestrators, or policy enforcement points—to make trust decisions based on verifiable evidence about an agent’s:
- **Model integrity** (weights, architecture),
- **Training provenance** (dataset, geography, privacy),
- **Runtime authorization** (capabilities, allowed APIs, slice types).

## 2. Terminology

- **AI Agent**: AI agents are autonomous systems powered by Large Language Models (LLMs) that can reason, plan, use tools, maintain memory, and take actions to accomplish goals. (PCL: Accoring to OWASP: https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- **Model Integrity**: The property that AI model weights and architecture have not been altered from a known-good state.
- **Training Provenance**: Metadata describing the origin, scope, and privacy properties of data used to train an AI model.
- **Inference Policy**: Constraints defining the authorized input context (e.g., slice type, geography) under which an agent may operate.
- **EAT-AI**: The EAT profile defined in this document.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174].

## 3. Use Cases

### 3.1. Generic AI Agent Attestation
An enterprise AI agent attests its model hash and data retention policy before accessing a protected API. For a more extensive protection, attestation target could also include behaviorial manifests, identity, prompts, tools and capabilities, SBOM/AIBOMs etc in the future.

### 3.2. 5G/6G Network Functions (Optional Context)
In ETSI ENI AI-Core, an Execution Agent generates instructions for network slice configuration. The agent must prove:
- It runs an approved model (`ai-model-hash`),
- It was trained on GDPR-compliant data (`training-geo-region`, `dp-epsilon`),
- It is authorized for specific slice types (`allowed-slice-types`).

> **Note**: Telecom-specific claims are **optional** and **only meaningful in 3GPP/ETSI contexts**.

## 4. EAT-AI Claims Definition

Claims are defined for both **CWT (CBOR)** and **JWT (JSON)**. In CWT, claims use signed integer keys; in JWT, they use text names (with hyphens converted to underscores per convention).

### 4.1. Core Claims (Generic, Domain-Agnostic)

| Claim Name | CBOR Key | JWT Name | Type | Description |
|-----------|----------|--------|------|-------------|
| `ai-model-id` | -75000 | `ai_model_id` | text | URN-formatted model identifier (e.g., `urn:ietf:ai:model:cnn-v3`) |
| `ai-model-hash` | -75001 | `ai_model_hash` | bstr | SHA-384 hash of serialized model weights |
| `model-arch-digest` | -75002 | `model_arch_digest` | bstr | SHA-384 hash of model computational graph |
| `training-data-id` | -75003 | `training_data_id` | text | Unique ID of training dataset |
| `dp-epsilon` | -75005 | `dp_epsilon` | float | Differential privacy epsilon used during training |
| `input-policy-digest` | -75006 | `input_policy_digest` | bstr | SHA-384 hash of inference input policy |
| `data-retention-policy` | -75008 | `data_retention_policy` | text | e.g., `"none"`, `"session"`, `"24h"` |
| `owner-id` | -75009 | `owner_id` | text | Identity of principal (e.g., GPSI per 3GPP TS 29.222) |
| `capabilities` | -75010 | `capabilities` | array of text | High-level functions (e.g., `"slice-optimization"`) |
| `allowed-apis` | -75011 | `allowed_apis` | array of URI | Specific endpoints the agent may call |

(PCL): Would each ai-model-id have a different urn registration? How would this part operate? Should model owner do the submit through some flexible/dynamic methods, or RFC-like methods?URN are long-term preserved registries usually registered through RFCs but I dont know if that is the best way.
(PCL): Do you need another AI-BOM? Or this itself _is_ an AIBOM? Would be non-AI regular SBOMs be necessary?
(PCL): I see these claims might be attested by different owners? Or should 1 owner/verifier attest them all?

### 4.2. Optional Domain-Specific Claims (5G/6G)

| Claim Name | CBOR Key | JWT Name | Type | Description |
|-----------|----------|--------|------|-------------|
| `training-geo-region` | -75004 | `training_geo_region` | array of text | ISO 3166-1 alpha-2 codes (e.g., `["DE", "FR"]`) |
| `allowed-slice-types` | -75007 | `allowed_slice_types` | array of text | 3GPP-defined slice types (e.g., `"eMBB"`, `"URLLC"`) |

> **Usage**: These claims **MUST only be used** when attesting agents in **ETSI ENI or 3GPP SBA** environments.

### 4.3. Multi-Agent Support via `submods`

A single platform (e.g., UE with `ueid`) may host multiple agents. Each agent is represented as a **submodule** under the `submods` claim (CBOR key **266**, per [RFC9711]):

```cbor
{
  / ueid / 256: h'ABCD...',
  / submods / 266: {
    "agent-1": { -75000: "model-A", -75010: ["slice-opt"], ... },
    "agent-2": { -75000: "model-B", -75007: ["URLLC"], ... }
  }
}
```

Core and optional claims MAY appear in submodules, but not at top level unless attesting a single-agent system.

## 5. Security Considerations 
- All claims MUST be bound to a hardware-rooted attestation (e.g., TEE) via standard EAT platform claims (ueid, oemid, dbgstat).
- ***ai-model-hash*** MUST be computed on the serialized model file (e.g., ONNX, PyTorch), not in-memory tensors.
- **Verifiers** MUST validate claims against authoritative registries (e.g., model hash in secure model catalog).
- ***Replay attacks*** MUST be mitigated using EAT nonce (CWT key 10) or exp (key 4).

## 6. Privacy Considerations
training-geo-region reveals data origin and SHOULD be minimized.
EAT tokens SHOULD be transmitted over secure channels (e.g., TLS 1.3).
owner-id SHOULD use pseudonymous identifiers (e.g., GPSI per 3GPP TS 29.222).

## 7. IANA Considerations
## 7.1. EAT Profile Registration
IANA is requested to register in the "Entity Attestation Token (EAT) Profiles" registry:

Profile Name: Autonomous AI Agent EAT Profile
Profile URI: urn:ietf:eat:profile:ai-agent:1
Reference: [THIS DOCUMENT]
### 7.2. CWT Claims Registry
IANA is requested to register the following in the "CBOR Web Token (CWT) Claims" registry [IANA-CWT]:

|Value| Claim Name|Description|
|-----|------------|---------------|
|-75000|`ai-model-id` | AI model URN|
|-75001|`ai-model-hash` |Model weights hash|
|-75002| `model-arch-digest`| Model graph hash|
|-75003 |`training-data-id`|Training dataset ID|
|-75004 |`training-geo-region` |Training data regions|
|-75005 |`dp-epsilon` |DP epsilon|
|-75006 |`input-policy-digest` |Inference policy hash|
|-75007 |`allowed-slice-types` |Authorized slice types|
|-75008 |`data-retention-policy` |Data retention policy|
|-75009 |`owner-id` |Resource owner identifier|
|-75010 |`capabilities` |Agent capabilities|
|-75011 |`allowed-apis` |Allowed API endpoints|

The range -75000 to -75011 is reserved for this profile.

### 7.3. JWT Claims Registry
IANA is requested to register the corresponding JWT claim names in the "JSON Web Token Claims" registry [IANA-JWT].

## 8. References
## 8.1. Normative References


- [[RFC2119](https://www.rfc-editor.org/rfc/rfc2119.html)]  Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997.
- [[RFC7519](https://www.rfc-editor.org/rfc/rfc7519.html)]  Jones, M., Bradley, J., and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, DOI 10.17487/RFC7519, May 2015.
- [[RFC8174](https://www.ietf.org/rfc/rfc8174.html)]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017.
- [[RFC8392](https://datatracker.ietf.org/doc/html/rfc8392)]  Jones, M., et al., "CBOR Web Token (CWT)", RFC 8392, DOI 10.17487/RFC8392, May 2018.
- [[RFC9711](https://datatracker.ietf.org/doc/html/rfc9711)] L. Lundblade, G. Mandyam,J. O'Donoghue,C. Wallace, "The Entity Attestation Token (EAT)", RFC 9711, April 2025 ISSN:2070-1721.
- <a name="rats"> [[RFC9334](https://datatracker.ietf.org/doc/html/rfc9334)] </a>  Birkett, M., et al., "Remote ATtestation ProcedureS (RATS) Architecture", RFC 9334, DOI 10.17487/RFC9334, January 2023.
- [[RFC8126](https://datatracker.ietf.org/doc/html/rfc8126)]  Cotton, M., et al., "Guidelines for Writing an IANA Considerations Section in RFCs", RFC 8126, DOI 10.17487/RFC8126, June 2017.


### 8.2. Informative References

- <a name="etsi">[[ETSI-GR-ENI-051](https://www.etsi.org/deliver/etsi_gr/ENI/001_099/051/04.01.01_60/gr_ENI051v040101p.pdf)] </a> ETSI, **"Architectural Framework for ENI in 6G"**, GR ENI 051 V4.1.1, February 2025.
- [[3GPP-TR-33.898](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=4088)] 3GPP, **"Study on security and privacy of Artificial Intelligence/Machine Learning (AI/ML)-based services and applications in 5G"**, TR 33.898, V18.0.1  July 2023. 
- [[3GPP-TR-33.784](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=4294)] 3GPP, **"Study on security aspects of core network enhanced support for Artificial Intelligence/Machine Learning (AI/ML)"**, TR 33.784 V0.0.0, April 2025. 
- <a name="idRatsAgentiEAT">[[I-D.huang-rats-agentic-eat-cap-attest](https://datatracker.ietf.org/doc/draft-huang-rats-agentic-eat-cap-attest/)] </a> Huang, L., et al., **"Capability Attestation Extensions for the Entity Attestation Token (EAT) in Agentic AI Systems"**, Work in Progress, Internet-Draft, March 2025.
- [[draft-ni-wimse-ai-agent-identity](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)] Yuan, N., Liu, P., **"WIMSE Applicability for AI Agents"**, Work in Progress.
- [[draft-liu-oauth-a2a-profile](https://datatracker.ietf.org/doc/draft-liu-oauth-a2a-profile/)] Liu, P., Yuan, N., **"Agent-to-Agent (A2A) Profile for OAuth Transaction Tokens"**, Work in Progress.


## Appendix A. Example EAT-AI Token (CWT)

   The following is a CBOR diagnostic notation of an EAT-AI token:

```
{
/ ueid / 10: h'0102030405060708',
/ sw-name / 256: "execution-agent-v3",
/ ai-model-id / -75000: "urn:etsi:eni:model:slice-opt-cnn:v3",
/ ai-model-hash / -75001: h'9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f',
/ training-geo-region / -75004: ["DE", "FR"],
/ dp-epsilon / -75005: 0.5,
/ input-policy-digest / -75006: h'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0',
/ nonce / 19: h'abcdef1234567890'
}
```


## Appendix B. Relationship to Existing Standards & Initaitives

This document complements:
- [IETF RATS](#rats): Provides the architectural context for EAT.
- [ETSI GR ENI 051](#etsi): Defines the AI-Core where these claims are applied.

It differs from [I-D.huang-rats-agentic-eat-cap-attest](#idRatsAgentiEAT) by specifying measurable, cryptographically verifiable claims rather than abstract capabilities.

# Acknowledgments
The authors thanks the ETSI ENI ISG and IETF RATS WG for their foundational work on AI trust and remote attestation.



Authors' Address:
Ayoub MESSOUS, Lionel MORAND
Huawei
Email: ayoub.messous@huawei.com
