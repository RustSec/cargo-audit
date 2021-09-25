#![cfg(feature = "osv-export")]

use crate::error::Error;
use git2::Time;
use std::{cmp::max, collections::HashMap, path::PathBuf};

use super::GitPath;

/// Tracks the time of latest modification of files in git.
pub struct GitModificationTimes {
    mtimes: HashMap<PathBuf, Time>,
}

impl GitModificationTimes {
    /// Performance: collects all modification times on creation
    /// and caches them. This is more efficient for looking up lots of files,
    /// but wasteful if you just need to look up a couple files.
    pub fn new(repo: &super::Repository) -> Result<Self, Error> {
        // Sadly I had to hand-roll this; there is no good off-the-shelf impl.
        // libgit2 has had a feature request for this for over a decade:
        // https://github.com/libgit2/libgit2/issues/495
        // as does git2-rs: https://github.com/rust-lang/git2-rs/issues/588
        // To make sure this works I've verified it against a naive shell script using `git log`
        // as well as `git whatchanged`
        let mut mtimes: HashMap<PathBuf, Time> = HashMap::new();
        let repo = git2::Repository::open(repo.path())?;
        let mut revwalk = repo.revwalk()?;
        revwalk.set_sorting(git2::Sort::TIME)?;
        revwalk.push_head()?;
        for commit_id in revwalk {
            let commit_id = commit_id?;
            let commit = repo.find_commit(commit_id)?;
            // Ignore merge commits (2+ parents) because that's what 'git whatchanged' does.
            if commit.parent_count() <= 1 {
                let tree = commit.tree()?;
                let prev_tree = match commit.parent_count() {
                    1 => Some(commit.parent(0)?.tree()?), // Diff with the previous commit
                    0 => None, // We've found the initial commit, diff with empty repo
                    _ => unreachable!(), // Ruled out by the `if` above
                };
                let diff = repo.diff_tree_to_tree(prev_tree.as_ref(), Some(&tree), None)?;
                for delta in diff.deltas() {
                    let file_path = delta.new_file().path().unwrap();
                    let file_mod_time = commit.time();
                    mtimes
                        .entry(file_path.to_owned())
                        .and_modify(|t| *t = max(*t, file_mod_time))
                        .or_insert(file_mod_time);
                }
            }
        }
        Ok(GitModificationTimes { mtimes })
    }

    /// Looks up the Git modification time for a given file path.
    /// The path must be relative to the root of the repository.
    pub fn for_path(&self, path: GitPath<'_>) -> &Time {
        self.mtimes.get(path.path()).unwrap()
    }
}
