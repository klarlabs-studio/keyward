//! Action taxonomy — the reversibility × consequence model that determines the
//! autonomy floor. This is where "propose-not-commit" lives.

use serde::{Deserialize, Serialize};

/// A normalized origin (scheme+host lowercased). Capabilities bind to one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin(pub String);

impl Origin {
    pub fn normalized(s: &str) -> Origin {
        Origin(s.trim().to_lowercase())
    }
}

/// The consequence tier of an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consequence {
    Low,
    High,
}

/// What an agent wants to do. Split into broadly-unattended (reversible /
/// proposable) and never-unattended (irreversible, high-consequence) verbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionVerb {
    // --- broadly-unattended: reversible / low-consequence / proposable ---
    Read,
    RunTests,
    FetchData,
    OpenPullRequest,
    DraftMessage,
    StageChange,
    MintReadToken,
    // --- never-unattended: irreversible / high-consequence (commit forms) ---
    DeleteData,
    MoveMoney,
    ShipToProduction,
    SendCommsAsUser,
    RotateOrRevokeOtherCredential,
}

impl ActionVerb {
    /// The locked never-unattended set: no agent may *commit* these without a
    /// human, no matter how well-scoped the credential is.
    pub fn never_unattended(&self) -> bool {
        use ActionVerb::*;
        matches!(
            self,
            DeleteData | MoveMoney | ShipToProduction | SendCommsAsUser | RotateOrRevokeOtherCredential
        )
    }

    pub fn reversible(&self) -> bool {
        !self.never_unattended()
    }

    pub fn consequence(&self) -> Consequence {
        if self.never_unattended() {
            Consequence::High
        } else {
            Consequence::Low
        }
    }

    /// The reviewable, proposable counterpart of an irreversible commit, if one
    /// exists. This is the heart of propose-not-commit: the agent can produce a
    /// reviewable artifact instead of committing the irreversible action.
    pub fn propose_variant(&self) -> Option<ActionVerb> {
        use ActionVerb::*;
        match self {
            ShipToProduction => Some(OpenPullRequest),
            SendCommsAsUser => Some(DraftMessage),
            DeleteData => Some(StageChange),
            _ => None,
        }
    }

    /// Parse a verb name (case-insensitive, snake_case or CamelCase) as sent
    /// over the MCP wire.
    pub fn parse(s: &str) -> Option<ActionVerb> {
        use ActionVerb::*;
        Some(match s.trim().to_lowercase().replace('_', "").as_str() {
            "read" => Read,
            "runtests" => RunTests,
            "fetchdata" => FetchData,
            "openpullrequest" | "openpr" => OpenPullRequest,
            "draftmessage" => DraftMessage,
            "stagechange" => StageChange,
            "mintreadtoken" => MintReadToken,
            "deletedata" => DeleteData,
            "movemoney" => MoveMoney,
            "shiptoproduction" | "shiptoprod" => ShipToProduction,
            "sendcommsasuser" => SendCommsAsUser,
            "rotateorrevokeothercredential" => RotateOrRevokeOtherCredential,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        use ActionVerb::*;
        match self {
            Read => "Read",
            RunTests => "RunTests",
            FetchData => "FetchData",
            OpenPullRequest => "OpenPullRequest",
            DraftMessage => "DraftMessage",
            StageChange => "StageChange",
            MintReadToken => "MintReadToken",
            DeleteData => "DeleteData",
            MoveMoney => "MoveMoney",
            ShipToProduction => "ShipToProduction",
            SendCommsAsUser => "SendCommsAsUser",
            RotateOrRevokeOtherCredential => "RotateOrRevokeOtherCredential",
        }
    }
}

/// A concrete request: do `verb` against `target`.
#[derive(Clone, Debug)]
pub struct Action {
    pub verb: ActionVerb,
    pub target: Origin,
}

impl Action {
    pub fn new(verb: ActionVerb, target: &str) -> Action {
        Action {
            verb,
            target: Origin::normalized(target),
        }
    }
}
