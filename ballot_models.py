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
