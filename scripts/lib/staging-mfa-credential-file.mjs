import {
  closeSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  unlinkSync,
  writeFileSync
} from "node:fs";

/**
 * Atomically claims a private credential path. A concurrent losing attempt
 * MUST NOT unlink the first operator's credential file after EEXIST.
 * Once the database callback starts, retain the protected file on *any*
 * error: a database COMMIT may have succeeded even if its acknowledgment was
 * lost. Before the callback starts, cleanup may remove only a file created
 * by this invocation whose filesystem identity still matches.
 */
export async function withPrivateMfaCredentialFile(path, contents, onPrepared) {
  let fileDescriptor;
  let ownedFile;
  let databaseMayHaveChanged = false;
  try {
    fileDescriptor = openSync(path, "wx", 0o600);
    const fileStat = fstatSync(fileDescriptor);
    ownedFile = { ino: fileStat.ino, dev: fileStat.dev };
    if (!fileStat.isFile() || (fileStat.mode & 0o077) !== 0) {
      throw new Error("Private staging credential permissions were not enforced.");
    }
    writeFileSync(fileDescriptor, contents, { encoding: "utf8" });
    fsyncSync(fileDescriptor);
    closeSync(fileDescriptor);
    fileDescriptor = undefined;
    databaseMayHaveChanged = true;
    return await onPrepared();
  } catch (error) {
    if (fileDescriptor !== undefined) {
      try { closeSync(fileDescriptor); } catch { /* cleanup continues */ }
    }
    if (ownedFile && !databaseMayHaveChanged) {
      try {
        const live = lstatSync(path);
        if (live.isFile() && live.ino === ownedFile.ino && live.dev === ownedFile.dev) {
          unlinkSync(path);
        }
      } catch { /* failure must not erase another process's credentials */ }
    }
    throw error;
  }
}
