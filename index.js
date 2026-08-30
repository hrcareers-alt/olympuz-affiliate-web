const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp();
}

/**
 * 🔐 ADMIN-ONLY: Change another affiliate's real Firebase Auth login email.
 * Added cors: true option to prevent CORS preflight blocking.
 */
exports.adminUpdateUserEmail = onCall({ cors: true }, async (request) => {
  // 1. Must be signed in
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "You must be logged in to perform this action.");
  }

  const callerUid = request.auth.uid;

  // 2. Caller must have role == 'admin' in Firestore
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

  if (targetUid === callerUid) {
    throw new HttpsError("failed-precondition", "Use Account Settings to change your own email.");
  }

  // 4. Perform the actual Auth email change
  try {
    await admin.auth().updateUser(targetUid, {
      email: newEmail,
      emailVerified: false,
    });

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
