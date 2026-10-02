class ThresholdSafeError(Exception):
    code = "internal_error"
    status = 500


class ValidationError(ThresholdSafeError):
    code = "validation_error"
    status = 400


class NotFoundError(ThresholdSafeError):
    code = "not_found"
    status = 404


class ConflictError(ThresholdSafeError):
    code = "conflict"
    status = 409


class ShareMismatch(ValidationError):
    code = "share_mismatch"


class InsufficientShares(ConflictError):
    code = "insufficient_shares"


class InsufficientApprovals(ConflictError):
    code = "insufficient_approvals"


class StaleShare(ConflictError):
    code = "stale_share"


class ShareNotDistributed(ConflictError):
    code = "share_not_distributed"


class ShareAlreadyDistributed(ConflictError):
    code = "share_already_distributed"


class DuplicateApproval(ConflictError):
    code = "duplicate_approval"


class IntegrityFailure(ConflictError):
    code = "integrity_failure"


class BackupIntegrity(ConflictError):
    code = "backup_integrity"


class SecretFrozen(ConflictError):
    code = "secret_frozen"


class SecretNotFrozen(ConflictError):
    code = "secret_not_frozen"


class PolicyDenied(ConflictError):
    code = "policy_denied"
