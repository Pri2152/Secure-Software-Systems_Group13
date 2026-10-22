"""
Workstream C ballot models.

SR-03: Eligibility and single-vote enforcement
SR-08: Ballot-voter unlinkability
SR-09: Receipt-free confirmation
SR-10: Ballot integrity and tamper detection
"""

from records import db


class VotingEligibility(db.Model):
    """
    Stores the voting eligibility status for each voter
    in a specific election.
    """

    __tablename__ = "voting_eligibility"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    voter_id = db.Column(
        db.String(128),
        nullable=False,
        index=True
    )

    election_id = db.Column(
        db.String(64),
        nullable=False,
        index=True
    )

    electoral_division = db.Column(
        db.String(128),
        nullable=False
    )

    state_code = db.Column(
        db.String(8),
        nullable=False
    )

    eligible = db.Column(
        db.Boolean,
        nullable=False,
        default=True
    )

    has_voted = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    # A voter should only have one eligibility
    # record for each election.
    __table_args__ = (
        db.UniqueConstraint(
            "voter_id",
            "election_id",
            name="uq_voter_election"
        ),
    )


class BallotCredential(db.Model):
    """Identity-side authorisation only; never stores ballot data."""

    __tablename__ = "ballot_credentials"

    verifier = db.Column(db.String(256), primary_key=True)
    voter_id = db.Column(db.String(128), nullable=False)
    election_id = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.Float, nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "voter_id", "election_id", name="uq_credential_voter_election"
        ),
    )


class AnonymousBallot(db.Model):
    """
    Stores an accepted ballot without voter identity.
    """

    __tablename__ = "anonymous_ballots"

    ballot_id = db.Column(
        db.String(64),
        primary_key=True
    )

    election_id = db.Column(
        db.String(64),
        nullable=False,
        index=True
    )

    electoral_division = db.Column(
        db.String(128),
        nullable=False,
        index=True
    )

    encrypted_ballot_json = db.Column(
        db.Text,
        nullable=False
    )

    chain_index = db.Column(db.Integer, nullable=False)
    previous_hash = db.Column(db.String(71), nullable=False)
    record_hash = db.Column(db.String(71), nullable=False)

    __table_args__ = (
        db.UniqueConstraint(
            "election_id", "electoral_division", "chain_index",
            name="uq_ballot_chain_position",
        ),
        db.CheckConstraint("chain_index > 0", name="ck_ballot_positive_index"),
    )


class BallotChainState(db.Model):
    """Ballot-domain expected count/head, authenticated without identity metadata."""

    __tablename__ = "ballot_chain_state"

    election_id = db.Column(db.String(64), primary_key=True)
    electoral_division = db.Column(db.String(128), primary_key=True)
    record_count = db.Column(db.Integer, nullable=False)
    head_hash = db.Column(db.String(71), nullable=False)
    checkpoint_json = db.Column(db.Text, nullable=False)

    __table_args__ = (
        db.CheckConstraint("record_count >= 0", name="ck_chain_nonnegative_count"),
    )
