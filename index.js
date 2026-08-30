const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp();
}

/**
 * 🔐 ADMIN-ONLY: Change another affiliate's real Firebase Auth login email.
 *
 * This MUST live in a Cloud Function (never in client-side code) because it
 * uses the Admin SDK, which requires a service account with full project
 * access — that key can never be shipped to a browser.
 *
 * The caller's identity is verified from their Firebase Auth token (which
 * cannot be forged from the client), and their role is checked against
 * their OWN Firestore user document before anything is changed.
 *
 * Client call example:
 *   const fn = httpsCallable(functions, "adminUpdateUserEmail");
 *   await fn({ targetUid: "...", newEmail: "new@example.com" });
 */
exports.adminUpdateUserEmail = onCall(async (request) => {
  // 1. Must be signed in
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "You must be logged in to perform this action.");
  }

  const callerUid = request.auth.uid;

  // 2. Caller must have role == 'admin' in Firestore (server-side check — cannot be spoofed)
  const callerDoc = await admin.firestore().collection("users").doc(callerUid).get();
  if (!callerDoc.exists || callerDoc.data().role !== "admin") {
    throw new HttpsError("permission-denied", "Only admins can change another affiliate's login email.");
  }

  // 3. Validate input
  const { targetUid, newEmail } = request.data || {};
  if (!targetUid || typeof targetUid !== "string") {
    throw new HttpsError("invalid-argument", "A valid targetUid is required.");
  }
  if (!newEmail || typeof newEmail !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
    throw new HttpsError("invalid-argument", "A valid newEmail is required.");
  }

  // 4. Prevent an admin from accidentally locking themselves out via this tool
  //    (self email changes should go through the normal "Account Settings" flow,
  //    which correctly re-authenticates and sends a verification link).
  if (targetUid === callerUid) {
    throw new HttpsError("failed-precondition", "Use Account Settings to change your own email.");
  }

  // 5. Perform the actual Auth email change (Admin SDK — server-side only)
  try {
    await admin.auth().updateUser(targetUid, {
      email: newEmail,
      emailVerified: false, // Force re-verification of the new address
    });

    // 6. Keep the Firestore record in sync so the UI reflects the change immediately
    await admin.firestore().collection("users").doc(targetUid).update({
      email: newEmail,
    });

    return { success: true, message: `Login email updated to ${newEmail}.` };
  } catch (err) {
    if (err.code === "auth/email-already-exists") {
      throw new HttpsError("already-exists", "This email is already used by another account.");
    }
    if (err.code === "auth/user-not-found") {
      throw new HttpsError("not-found", "This affiliate's login account could not be found.");
    }
    throw new HttpsError("internal", err.message || "Failed to update login email.");
  }
});
