"""Pydantic models for the certificate rotation planning API."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_ACTIONS = 12


class Certificate(BaseModel):
    """A certificate participating in the rotation scenario.

    ``subject`` / ``issuer`` are distinguished names; a self-signed root has
    issuer == subject. Validity instants are ISO-8601 (timezone recommended,
    naive datetimes are treated as UTC).
    """

    cert_id: str = Field(..., min_length=1, examples=["root-old"])
    subject: str = Field(..., min_length=1)
    issuer: str = Field(..., min_length=1)
    not_valid_before: datetime
    not_valid_after: datetime


class TrustAnchor(BaseModel):
    """A certificate that a client trusts *before* the plan starts."""

    client_id: str = Field(..., min_length=1)
    cert_id: str = Field(..., min_length=1)


class Endpoint(BaseModel):
    """A TLS endpoint with its current and target certificate chains.

    Chains are ordered leaf-first and must finish at a self-signed root.
    """

    endpoint_id: str = Field(..., min_length=1)
    current_chain: list[str] = Field(..., min_length=1)
    target_chain: list[str] = Field(..., min_length=1)


class Relationship(BaseModel):
    """A communication relationship that must keep a valid trust path."""

    client_id: str = Field(..., min_length=1)
    endpoint_id: str = Field(..., min_length=1)


class _BaseAction(BaseModel):
    action_id: str = Field(..., min_length=1)
    allowed_stages: list[int] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _check_stages(self) -> "_BaseAction":
        for stage in self.allowed_stages:
            if stage < 1:
                raise ValueError("allowed_stages entries must be positive integers")
        if len(set(self.allowed_stages)) != len(self.allowed_stages):
            raise ValueError("allowed_stages must not contain duplicates")
        self.allowed_stages = sorted(self.allowed_stages)
        return self


class AddTrustAction(_BaseAction):
    """增信: a client starts trusting a certificate as an anchor."""

    type: Literal["add_trust"]
    client_id: str
    anchor_cert_id: str


class RemoveTrustAction(_BaseAction):
    """撤信: a client stops trusting a certificate anchor."""

    type: Literal["remove_trust"]
    client_id: str
    anchor_cert_id: str


class ReplaceCertAction(_BaseAction):
    """换证: an endpoint switches to a new leaf-first certificate chain."""

    type: Literal["replace_cert"]
    endpoint_id: str
    new_chain: list[str] = Field(..., min_length=1)


Action = Annotated[
    Union[AddTrustAction, RemoveTrustAction, ReplaceCertAction],
    Field(discriminator="type"),
]


class PlanRequest(BaseModel):
    certificates: list[Certificate] = Field(..., min_length=1)
    trust_anchors: list[TrustAnchor] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(..., min_length=1)
    relationships: list[Relationship] = Field(..., min_length=1)
    actions: list[Action] = Field(default_factory=list)
    plan_time: Optional[datetime] = Field(
        default=None,
        description="Planning instant; defaults to current UTC. Certificates "
        "expired (or not yet valid) at this instant are rejected.",
    )

    @model_validator(mode="after")
    def _check_action_limit(self) -> "PlanRequest":
        if len(self.actions) > MAX_ACTIONS:
            raise ValueError(
                f"at most {MAX_ACTIONS} actions are supported "
                f"(got {len(self.actions)})"
            )
        return self


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PlannedStage(BaseModel):
    stage: int
    action_ids: list[str]


class PlanSuccess(BaseModel):
    status: Literal["ok"] = "ok"
    stage_count: int
    stages: list[PlannedStage]


class RelationshipRef(BaseModel):
    client_id: str
    endpoint_id: str


class ChainCert(BaseModel):
    cert_id: str
    subject: str
    issuer: str


class Failure(BaseModel):
    status: Literal["infeasible", "invalid"]
    stage: int = Field(..., description="Stage that first breaks a relationship; 0 = initial state")
    relationship: RelationshipRef
    blocking_action: Optional[str] = Field(
        ..., description="Action that first breaks the relationship, or null at stage 0"
    )
    reason: str
    chain: list[ChainCert]
    trusted_anchors: list[str]
    message: str


class VerifyResult(BaseModel):
    status: Literal["valid"] = "valid"
    stage_count: int
    stages: list[PlannedStage]


# ---------------------------------------------------------------------------
# /scenarios/normalize: PEM bundle -> planner-ready scenario data
# ---------------------------------------------------------------------------


class NormalizeEndpointRef(BaseModel):
    """An endpoint whose current/target leaves are identified by fingerprint."""

    endpoint_id: str = Field(..., min_length=1)
    current_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="Lower-case (case-insensitive) SHA-256 fingerprint of the "
                    "leaf currently served, hex-encoded.",
    )
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint of the leaf that will be served after "
                    "the rotation.",
    )


class NormalizeRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; each element may contain one or more "
                    "concatenated PEM CERTIFICATE blocks. Duplicates are "
                    "deduplicated by DER fingerprint.",
    )
    endpoints: list[NormalizeEndpointRef] = Field(..., min_length=1)
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="SHA-256 fingerprints of self-signed roots that are "
                    "allowed to terminate a reconstructed chain.",
    )


class NormalizedCertificate(Certificate):
    """Certificate metadata; ``cert_id`` is the lower-case SHA-256 fingerprint."""


class NormalizedEndpoint(BaseModel):
    endpoint_id: str
    current_chain: list[str] = Field(
        ...,
        description="Reconstructed leaf-first fingerprint chain currently "
                    "served; the final element is a trust root.",
    )
    target_chain: list[str]


class NormalizeResult(BaseModel):
    certificates: list[NormalizedCertificate]
    endpoints: list[NormalizedEndpoint]


# -- 422 detail payloads -----------------------------------------------------


class NormalizePemIssue(BaseModel):
    index: int = Field(..., description="Index of the bad element in pem_certificates.")
    message: str


class NormalizeFingerprintIssue(BaseModel):
    fingerprint: str
    referred_by: str = Field(
        ...,
        description="Request location that referenced this fingerprint.",
    )


class NormalizeChainIssue(BaseModel):
    endpoint_id: str
    leaf_role: Literal["current", "target"]
    leaf: str = Field(..., description="Fingerprint of the leaf that could not be resolved.")
    candidate_issuers: list[str] = Field(
        ...,
        description="Fingerprints whose public key cryptographically verifies "
                    "the leaf's signature (the real issuance candidates; "
                    "empty when nothing signed it).",
    )
    candidate_paths: list[list[str]] = Field(
        ...,
        description="Bounded diagnostic sample (at most 64) of leaf-first "
                    "simple paths over verified issuance edges found while "
                    "resolving this leaf, including paths that do not end at "
                    "a trust root. The sample may be truncated in heavily "
                    "cross-signed bundles; the no_trust_path / ambiguous_chain "
                    "verdict itself is always exact.",
    )
    reason: Literal["no_trust_path", "ambiguous_chain"]


class NormalizeErrorDetail(BaseModel):
    error: str = Field(
        ...,
        description="Machine-readable error code, e.g. no_trust_path or "
                    "ambiguous_chain.",
    )
    message: str
    pem_issues: list[NormalizePemIssue] = Field(default_factory=list)
    fingerprint_issues: list[NormalizeFingerprintIssue] = Field(default_factory=list)
    chain_issues: list[NormalizeChainIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /deployments/precheck: target-leaf identity (SAN + name constraints) checks
# ---------------------------------------------------------------------------


class PrecheckIdentity(BaseModel):
    """An identity the endpoint claims to speak for.

    Only subjectAltName is consulted (CN is never a fallback). DNS identities
    are case-folded, IDNA A-label encoded and have a single trailing dot
    stripped; IP identities must be literal IPv4/IPv6 addresses and are
    matched exactly (no DNS syntax, no subnetting).
    """

    type: Literal["dns", "ip"]
    value: str = Field(..., min_length=1)


class PrecheckEndpoint(BaseModel):
    endpoint_id: str = Field(..., min_length=1)
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the "
                    "target leaf certificate in the PEM bundle.",
    )
    identities: list[PrecheckIdentity] = Field(
        ...,
        min_length=1,
        description="DNS/IP identities claimed for this endpoint. Each is "
                    "checked against the target leaf's SANs and the "
                    "accumulated name constraints of the intermediate CAs "
                    "above it.",
    )


class PrecheckRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize.",
    )
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="Self-signed root fingerprints allowed to terminate the "
                    "target chain.",
    )
    endpoints: list[PrecheckEndpoint] = Field(..., min_length=1)


class PrecheckUnsupportedConstraint(BaseModel):
    ca_fingerprint: str = Field(
        ...,
        description="Fingerprint of the intermediate CA carrying the "
                    "constraint that cannot be evaluated for DNS/IP "
                    "identities (e.g. rfc822Name/URI/directoryName/otherName, "
                    "or a malformed iPAddress constraint).",
    )
    section: Literal["permitted", "excluded"]
    general_name_type: str = Field(
        ...,
        description="GeneralName type tag, one of dns_name, ip_address, "
                    "rfc822_name, directory_name, edi_party_name, uri, "
                    "x400_address, registered_id, other_name, or "
                    "malformed_ip_address when an iPAddress constraint is "
                    "not a valid 8/32-byte address+mask.",
    )


class PrecheckViolation(BaseModel):
    """One machine-readable reason an endpoint fails the identity pre-check.

    Sorted stably in every response: first by reason in the precedence order
    unsupported_constraint_type -> excluded_by_name_constraint ->
    not_within_permitted_subtree -> identity_not_covered, then by identity
    type/value and the remaining fields.
    """

    reason: Literal[
        "identity_not_covered",
        "excluded_by_name_constraint",
        "not_within_permitted_subtree",
        "unsupported_constraint_type",
    ]
    identity_type: Optional[Literal["dns", "ip"]] = Field(
        ...,
        description="Claimed identity the violation pertains to; null when "
                    "an unsupported constraint disqualifies the endpoint "
                    "independently of any specific identity.",
    )
    identity_value: Optional[str] = Field(
        ...,
        description="Normalized declared identity value, or null.",
    )
    san: Optional[str] = Field(
        ...,
        description="The offending same-type SAN entry (normalized), or "
                    "null for a claimed identity that no SAN covers / for an "
                    "unsupported constraint.",
    )
    constraint: Optional[str] = Field(
        ...,
        description="The name constraint responsible (DNS subtree string, "
                    "or an IP network in CIDR notation), or null.",
    )
    ca_fingerprint: Optional[str] = Field(
        ...,
        description="Intermediate CA whose constraint triggered this "
                    "violation, or null.",
    )


class PrecheckIdentityResult(BaseModel):
    type: Literal["dns", "ip"]
    value: str = Field(..., description="Normalized identity value.")
    covered: bool = Field(
        ...,
        description="True iff at least one same-type SAN of the target leaf "
                    "covers this identity.",
    )


class PrecheckEndpointResult(BaseModel):
    endpoint_id: str
    target_leaf_fingerprint: str
    eligible: bool = Field(
        ...,
        description="True only when every declared identity is covered by a "
                    "SAN that survives the accumulated name constraints; "
                    "only eligible endpoints may be handed to /plans.",
    )
    reason: Literal["ok",
                    "identity_not_covered",
                    "excluded_by_name_constraint",
                    "not_within_permitted_subtree",
                    "unsupported_constraint_type"]
    chain: list[str] = Field(
        ...,
        description="Cryptographically verified leaf-first fingerprint chain "
        "from the target leaf to a declared trust root (the target_chain to "
        "hand to the planning API); present for every endpoint.",
    )
    dns_sans: list[str] = Field(
        ...,
        description="Target leaf's dNSName SAN entries, normalized "
                    "(lower-case, trailing dot stripped, A-label encoded).",
    )
    ip_sans: list[str] = Field(
        ..., description="Target leaf's iPAddress SAN entries (normalized)."
    )
    identities: list[PrecheckIdentityResult]
    violations: list[PrecheckViolation]


class PrecheckResult(BaseModel):
    results: list[PrecheckEndpointResult] = Field(
        ...,
        description="Per-endpoint verdicts, sorted by endpoint_id.",
    )


class PrecheckIdentityIssue(BaseModel):
    endpoint_id: str
    index: int = Field(
        ..., description="Index of the bad identity in the endpoint's list.",
    )
    message: str


class PrecheckErrorDetail(NormalizeErrorDetail):
    identity_issues: list[PrecheckIdentityIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /deployments/ocsp-precheck: offline OCSP stapling response pre-check
# ---------------------------------------------------------------------------


class OcspPrecheckRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize. Must contain the leaf identified by "
                    "leaf_fingerprint and its issuer certificate.",
    )
    leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the leaf "
                    "certificate the OCSP response is expected to be about.",
    )
    ocsp_response: str = Field(
        ...,
        min_length=1,
        description="Base64-encoded DER OCSP response (RFC 6960) exactly as "
                    "would be stapled on the wire; whitespace is tolerated.",
    )
    check_time: datetime = Field(
        ...,
        description="Instant at which the stapled response is evaluated "
                    "(ISO-8601; naive datetimes are treated as UTC).",
    )
    allowed_skew_seconds: int = Field(
        default=300,
        ge=0,
        le=300,
        description="Tolerance for responder clock skew, applied to the "
                    "freshness window on both sides; at most 300 seconds.",
    )


OCSP_REASONS = (
    "ok",
    "invalid_ocsp_response",
    "unexpected_single_response_count",
    "response_not_successful",
    "serial_mismatch",
    "certid_issuer_mismatch",
    "responder_untrusted",
    "invalid_signature",
    "certificate_revoked",
    "certificate_unknown",
    "produced_at_too_late",
    "missing_next_update",
    "before_this_update",
    "after_next_update",
)


class OcspPrecheckResult(BaseModel):
    eligible: bool = Field(
        ...,
        description="True only when the response is successful, the CertID "
                    "matches the named leaf and its issuer, the signature is "
                    "valid under the issuer or an authorized delegated "
                    "responder, certStatus is good, and check_time lies in the "
                    "(thisUpdate - skew, nextUpdate + skew) window with "
                    "producedAt no later than check_time + skew.",
    )
    reason: Literal[
        "ok",
        "invalid_ocsp_response",
        "unexpected_single_response_count",
        "response_not_successful",
        "serial_mismatch",
        "certid_issuer_mismatch",
        "responder_untrusted",
        "invalid_signature",
        "certificate_revoked",
        "certificate_unknown",
        "produced_at_too_late",
        "missing_next_update",
        "before_this_update",
        "after_next_update",
    ]
    check_time: datetime = Field(
        ..., description="The evaluation instant, normalized to UTC."
    )
    response_status: Optional[str] = Field(
        ...,
        description="RFC 6960 responseStatus enum name (successful, "
                    "malformed_request, internal_error, try_later, "
                    "sig_required, unauthorized); null when the DER is not a "
                    "parseable OCSPResponse.",
    )
    cert_status: Optional[str] = Field(
        ...,
        description="SingleResponse certStatus enum name (good, revoked, "
                    "unknown); null for a non-successful or unparseable "
                    "response.",
    )
    produced_at: Optional[datetime] = None
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    revocation_time: Optional[datetime] = Field(
        default=None,
        description="revocationTime (UTC) when certStatus is revoked; "
                    "otherwise null.",
    )
    revocation_reason: Optional[str] = Field(
        default=None,
        description="RFC 5280 CRLReason enum name (e.g. key_compromise); "
                    "null for a non-revoked response or when the responder "
                    "omits the reason (defaults to unspecified).",
    )
    responder_type: Optional[Literal["by_name", "by_key"]] = Field(
        default=None,
        description="Which ResponderID form the response carries; null for a "
                    "non-successful or unparseable response.",
    )
    signer_fingerprint: Optional[str] = Field(
        default=None,
        description="SHA-256 fingerprint of the certificate whose public key "
                    "verified the response signature (the issuer itself or a "
                    "delegated id-kp-OCSPSigning responder certificate).",
    )
    message: str


# ---------------------------------------------------------------------------
# /plans/reconcile: infer a safe resumption point after a deployment outage
# ---------------------------------------------------------------------------


class ReconcileStage(BaseModel):
    """One stage of the plan that was generated before the interruption."""

    stage: int = Field(..., ge=1)
    action_ids: list[str] = Field(
        ...,
        description="Actions scheduled at this absolute stage number; may be "
                    "empty for an explicit no-op gap, exactly as /plans emits.",
    )

    @field_validator("action_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("action_ids within a stage must be unique")
        return v


class ReconcileAnchorObservation(BaseModel):
    """Partial observation of one client's trust anchor set.

    Only observed (client, anchor) pairs are reported; anything unobserved
    stays unknown and must never be treated as absent.
    """

    client_id: str = Field(..., min_length=1)
    anchor_cert_id: str = Field(..., min_length=1)
    present: bool = Field(
        ...,
        description="Observed state of this exact trust edge: true = the "
                    "client currently trusts this anchor; false = it "
                    "currently does not. Absence of the observation means "
                    "unknown, never false.",
    )


class ReconcileChainObservation(BaseModel):
    """Partial observation of one endpoint's currently served chain."""

    endpoint_id: str = Field(..., min_length=1)
    chain: list[str] = Field(
        ...,
        min_length=1,
        description="The leaf-first chain observed on the endpoint right now. "
                    "Endpoints not listed stay unknown.",
    )


class ReconcileRequest(PlanRequest):
    stages: list[ReconcileStage] = Field(
        ...,
        description="The generated plan (as /plans returned): stages numbered "
                    "consecutively from 1, every scenario action scheduled "
                    "exactly once.",
    )
    anchor_observations: list[ReconcileAnchorObservation] = Field(
        default_factory=list,
        description="Observed client/anchor trust edges. Unreported edges are "
                    "unknown rather than absent.",
    )
    chain_observations: list[ReconcileChainObservation] = Field(
        default_factory=list,
        description="Observed current endpoint chains. Unreported endpoints "
                    "are unknown.",
    )

    @model_validator(mode="after")
    def _unique_observations(self) -> "ReconcileRequest":
        anchors = [
            (o.client_id, o.anchor_cert_id) for o in self.anchor_observations
        ]
        if len(set(anchors)) != len(anchors):
            raise ValueError(
                "anchor_observations: each (client_id, anchor_cert_id) pair "
                "may be observed at most once"
            )
        endpoints = [o.endpoint_id for o in self.chain_observations]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError(
                "chain_observations: each endpoint_id may be observed at "
                "most once"
            )
        return self


class ReconcileProgress(BaseModel):
    completed_stages: int = Field(
        ...,
        description="Stages whose actions have all executed. null current "
                    "stage means the whole plan is finished.",
    )
    current_stage: Optional[int] = Field(
        ...,
        description="The stage the deployment may be resuming at: the first "
                    "stage with unexecuted actions; null once every action "
                    "has executed.",
    )
    completed_action_ids: list[str] = Field(
        ...,
        description="Every action that has definitely executed in this "
                    "possible progress (all ended-stage actions plus any "
                    "subset of the current stage), sorted by action_id.",
    )


class ReconcileResult(BaseModel):
    status: Literal["ok"] = "ok"
    safe_next_actions: list[str] = Field(
        ...,
        description="Actions that, in every possible progress, belong to the "
                    "current stage, are not yet completed, and still keep "
                    "every relationship valid when applied alone. Sorted by "
                    "action_id; empty once the plan is finished.",
    )
    possible_progress: list[ReconcileProgress] = Field(
        ...,
        description="All plan-ordered states consistent with the observations "
                    "in which every relationship still has a trust path; "
                    "sorted by (completed_stages, completed_action_ids).",
    )


class ReconcileConflictObservation(BaseModel):
    """An observation that contradicts every compatible reachable state.

    For an anchor observation ``anchor_cert_id`` / ``present`` are set and
    ``chain`` is null; for a chain observation ``endpoint_id`` / ``chain``
    are set and ``anchor_cert_id`` / ``present`` are null.
    """

    kind: Literal["anchor", "endpoint_chain"]
    client_id: Optional[str] = None
    anchor_cert_id: Optional[str] = None
    present: Optional[bool] = None
    endpoint_id: Optional[str] = None
    chain: Optional[list[str]] = None
    reason: str = Field(
        ...,
        description="Machine-readable code: anchor_present_mismatch, "
                    "anchor_absent_mismatch, endpoint_chain_mismatch, or "
                    "no_safe_reachable_state.",
    )
    message: str


class ReconcileConflict(BaseModel):
    status: Literal["conflict"] = "conflict"
    reason: Literal[
        "observation_conflict", "no_safe_reachable_state"
    ] = Field(
        ...,
        description="observation_conflict: the observations rule out every "
                    "plan-ordered healthy state; no_safe_reachable_state: "
                    "every plan-ordered state already breaks a relationship "
                    "(including before any observation).",
    )
    message: str
    conflicts: list[ReconcileConflictObservation] = Field(
        ...,
        description="Stably sorted observations responsible for the "
                    "contradiction (greedy first-incompatible cut).",
    )
