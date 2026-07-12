//! Proctor provider profiles — **external, pluggable TOML descriptors**.
//!
//! A profile is pure data, keyed on the *credential type* (not the tool), that
//! says two things: (1) how the credential is presented to a process (which env
//! vars), and (2) which command invocations mutate (for the risk gate). Because
//! env conventions are shared across tools, one profile (e.g. `aws`) serves the
//! aws-cli, Terraform, Pulumi, and every SDK.
//!
//! New providers — GitLab, Azure, whatever arises — are added by dropping a
//! `*.toml` file into the profiles directory. No recompile. See ADR-0002.

use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("io error reading {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("parse error in {path}: {source}")]
    Parse { path: String, source: toml::de::Error },
    #[error("invalid profile '{id}': {reason}")]
    Invalid { id: String, reason: String },
    #[error("duplicate profile id '{0}'")]
    Duplicate(String),
    #[error("credential does not match profile '{id}': {reason}")]
    Compose { id: String, reason: String },
}

/// How risky an argv is, per the profile's patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskClass {
    /// Matches a read pattern — safe to auto-allow (subject to policy).
    Read,
    /// Matches a mutate pattern — must be gated (step-up / propose-not-commit).
    Mutate,
    /// Matches nothing — treated as mutate by default (safe when incomplete).
    Unknown,
}

/// An external provider profile (deserialized from TOML).
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Single-token providers: the credential goes into this one env var.
    #[serde(default)]
    pub env_var: Option<String>,
    /// Multi-field providers: the credential is a JSON object; each field maps
    /// to an env var. (e.g. AWS access_key_id -> AWS_ACCESS_KEY_ID)
    #[serde(default)]
    pub env_map: Option<BTreeMap<String, String>>,
    /// Which minter kind produces short-lived creds for this provider
    /// (e.g. "github-app", "token-exchange", "aws-sts"). None → vault-read only.
    #[serde(default)]
    pub mint: Option<String>,
    /// CLI binaries this profile is typically used with (informational).
    #[serde(default)]
    pub commands: Vec<String>,
    /// Regexes matched against the joined argv → Read.
    #[serde(default)]
    pub read_patterns: Vec<String>,
    /// Regexes matched against the joined argv → Mutate.
    #[serde(default)]
    pub mutate_patterns: Vec<String>,
}

impl Profile {
    /// Validate structure + regex compilation. Called at load.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.id.trim().is_empty() {
            return Err(ProfileError::Invalid { id: self.id.clone(), reason: "empty id".into() });
        }
        match (&self.env_var, &self.env_map) {
            (Some(_), Some(_)) => return Err(ProfileError::Invalid {
                id: self.id.clone(),
                reason: "set exactly one of env_var or env_map, not both".into(),
            }),
            (None, None) => return Err(ProfileError::Invalid {
                id: self.id.clone(),
                reason: "set one of env_var or env_map".into(),
            }),
            _ => {}
        }
        for p in self.read_patterns.iter().chain(self.mutate_patterns.iter()) {
            Regex::new(p).map_err(|e| ProfileError::Invalid {
                id: self.id.clone(),
                reason: format!("bad pattern '{p}': {e}"),
            })?;
        }
        Ok(())
    }

    /// Compose the environment to inject for `secret`.
    /// - `env_var`: the secret goes into that one variable.
    /// - `env_map`: the secret is parsed as a JSON object and each field mapped.
    pub fn compose_env(&self, secret: &str) -> Result<BTreeMap<String, String>, ProfileError> {
        let mut out = BTreeMap::new();
        if let Some(var) = &self.env_var {
            out.insert(var.clone(), secret.to_string());
            return Ok(out);
        }
        if let Some(map) = &self.env_map {
            let v: serde_json::Value = serde_json::from_str(secret).map_err(|_| ProfileError::Compose {
                id: self.id.clone(),
                reason: "secret must be a JSON object for a multi-field profile".into(),
            })?;
            let obj = v.as_object().ok_or_else(|| ProfileError::Compose {
                id: self.id.clone(),
                reason: "secret must be a JSON object".into(),
            })?;
            for (field, var) in map {
                let val = obj.get(field).and_then(|x| x.as_str()).ok_or_else(|| ProfileError::Compose {
                    id: self.id.clone(),
                    reason: format!("secret missing string field '{field}'"),
                })?;
                out.insert(var.clone(), val.to_string());
            }
            return Ok(out);
        }
        Err(ProfileError::Compose { id: self.id.clone(), reason: "no env mapping".into() })
    }

    /// Classify an argv. Mutate wins over Read; no match → Unknown (gated).
    pub fn classify(&self, argv: &[String]) -> RiskClass {
        let joined = argv.join(" ");
        let any = |pats: &[String]| pats.iter().any(|p| Regex::new(p).map(|r| r.is_match(&joined)).unwrap_or(false));
        if any(&self.mutate_patterns) {
            RiskClass::Mutate
        } else if any(&self.read_patterns) {
            RiskClass::Read
        } else {
            RiskClass::Unknown
        }
    }
}

/// A loaded set of profiles, keyed by id.
#[derive(Debug, Default)]
pub struct Registry {
    profiles: BTreeMap<String, Profile>,
}

impl Registry {
    pub fn new() -> Self {
        Registry::default()
    }

    /// Load every `*.toml` in `dir`. A missing directory yields an empty
    /// registry (profiles are optional); a malformed file is a hard error.
    pub fn load_dir(dir: &Path) -> Result<Registry, ProfileError> {
        let mut reg = Registry::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(reg),
            Err(e) => return Err(ProfileError::Io { path: dir.display().to_string(), source: e }),
        };
        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().map(|x| x == "toml").unwrap_or(false))
            .collect();
        paths.sort();
        for path in paths {
            let text = std::fs::read_to_string(&path).map_err(|e| ProfileError::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            let profile: Profile = toml::from_str(&text).map_err(|e| ProfileError::Parse {
                path: path.display().to_string(),
                source: e,
            })?;
            reg.insert(profile)?;
        }
        Ok(reg)
    }

    pub fn insert(&mut self, profile: Profile) -> Result<(), ProfileError> {
        profile.validate()?;
        if self.profiles.contains_key(&profile.id) {
            return Err(ProfileError::Duplicate(profile.id));
        }
        self.profiles.insert(profile.id.clone(), profile);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.values()
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hetzner() -> Profile {
        toml::from_str(
            r#"
            id = "hetzner"
            description = "Hetzner Cloud"
            env_var = "HCLOUD_TOKEN"
            commands = ["hcloud", "terraform"]
            read_patterns = ['\b(list|describe|get)\b']
            mutate_patterns = ['\b(create|delete|rebuild)\b']
        "#,
        )
        .unwrap()
    }

    fn aws() -> Profile {
        toml::from_str(
            r#"
            id = "aws"
            env_map = { access_key_id = "AWS_ACCESS_KEY_ID", secret_access_key = "AWS_SECRET_ACCESS_KEY" }
            read_patterns = ['\b(describe|list|get|ls)\b']
            mutate_patterns = ['\b(delete|terminate|rm|put)\b']
        "#,
        )
        .unwrap()
    }

    #[test]
    fn single_token_compose_env() {
        let p = hetzner();
        p.validate().unwrap();
        let env = p.compose_env("tok_123").unwrap();
        assert_eq!(env.get("HCLOUD_TOKEN").unwrap(), "tok_123");
    }

    #[test]
    fn multi_field_compose_env_from_json() {
        let p = aws();
        let env = p
            .compose_env(r#"{"access_key_id":"AKIA...","secret_access_key":"abc/def"}"#)
            .unwrap();
        assert_eq!(env.get("AWS_ACCESS_KEY_ID").unwrap(), "AKIA...");
        assert_eq!(env.get("AWS_SECRET_ACCESS_KEY").unwrap(), "abc/def");
    }

    #[test]
    fn multi_field_rejects_non_json_secret() {
        assert!(aws().compose_env("just-a-string").is_err());
    }

    #[test]
    fn classify_reads_mutates_and_unknown() {
        let p = aws();
        assert_eq!(p.classify(&["s3".into(), "ls".into()]), RiskClass::Read);
        assert_eq!(p.classify(&["s3".into(), "rm".into(), "x".into()]), RiskClass::Mutate);
        assert_eq!(p.classify(&["whoami".into()]), RiskClass::Unknown);
    }

    #[test]
    fn both_env_forms_is_invalid() {
        let p: Profile = toml::from_str(
            r#"id = "x"
               env_var = "T"
               env_map = { a = "B" }"#,
        )
        .unwrap();
        assert!(p.validate().is_err());
    }

    #[test]
    fn load_dir_reads_toml_files() {
        let dir = std::env::temp_dir().join(format!("proctor-prof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hetzner.toml"), "id=\"hetzner\"\nenv_var=\"HCLOUD_TOKEN\"\n").unwrap();
        std::fs::write(dir.join("gitlab.toml"), "id=\"gitlab\"\nenv_var=\"GITLAB_TOKEN\"\n").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let reg = Registry::load_dir(&dir).unwrap();
        assert_eq!(reg.len(), 2);
        assert!(reg.get("gitlab").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dir_is_empty_not_error() {
        let reg = Registry::load_dir(Path::new("/no/such/proctor/dir")).unwrap();
        assert!(reg.is_empty());
    }
}
