"""How a scan step says it could not do its work.

Kept apart from the pipeline so the lease, the writer and the stages can all
raise the same errors without importing the class that drives them.
"""


class ScanVanished(Exception):
    """The scan a step was queued for is gone.

    Not a :class:`ScanStepError`: there is no step outcome to record against a
    scan that no longer exists, and the rows a settle would write would be
    orphans.
    """


class ScanStepError(Exception):
    """A step could not do its work, and said why in terms a customer can read.

    Distinguished from an unexpected exception because the two deserve
    different treatment: this is a condition the pipeline anticipated, so its
    message is the one shown, and there is nothing to retry when the reason is
    "the subscription is gone".
    """

    retryable: bool = False


class ScanScopeEmpty(ScanStepError):
    """Nothing in scope. Retrying resolves the same empty set."""


class CollectionUnavailable(ScanStepError):
    """The scope this step was created for is no longer reachable."""


class NothingToAnalyze(ScanStepError):
    """Every collection failed, so there is nothing to interpret."""


class StepLeaseLost(ScanStepError):
    """This worker is no longer the one running this step.

    Raised by the lease keeper when a renewal is refused, which means the step
    was reclaimed while this process was working -- it stopped reporting for
    longer than the lease, the reaper returned the step to PENDING, and another
    worker has it now. The right response is to stop immediately: the work is
    being done elsewhere, and everything this attempt would still write is a
    duplicate of it.

    Not retryable, because there is nothing to retry. The step is already back
    in the queue or already running somewhere else, and the settle that follows
    is fenced out anyway.
    """

    retryable = False
