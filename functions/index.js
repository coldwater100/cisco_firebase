// Firebase SDK (modular v9+ compatible)
const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

const db = admin.firestore();

const validator = "06d272f9850054abe38117af91dfd589245122e8";
const secret = "bluefence";

const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// 📡 1. Meraki Location Webhook 수신 함수 (Firestore 저장)
exports.scanning = functions.https.onRequest(async (req, res) => {
  switch (req.method) {
    case "GET":
      return res.status(200).send(validator);

    case "POST": {
      const body = req.body;
      const incomingSecret = body.secret;

      if (incomingSecret !== secret) {
        console.warn("❌ Invalid secret received.");
        return res.status(403).send("Forbidden");
      }

      console.log("✅ Secret verified. Data received:", JSON.stringify(body));

      const timestamp = Date.now();
      const type = body.type || "unknown";

      if (body.data && Array.isArray(body.data.observations)) {
        const batch = db.batch();

        for (const client of body.data.observations) {
          const docId = `${type}_${client.clientMac}`;
          const docRef = db.collection("locations").doc(docId);

          const docSnapshot = await docRef.get();
          if (docSnapshot.exists) {
            batch.update(docRef, {
              ...client,
              type,
              timestamp,
            });
          } else {
            batch.set(docRef, {
              ...client,
              type,
              timestamp,
            });
          }
        }

        await batch.commit();
      }

      return res.status(200).json({
        message: "Data stored in Firestore.",
      });
    }

    default:
      return res.status(405).send("Method Not Allowed");
  }
});

// 🔐 2. MAC 등록 및 OTP 발급 함수
exports.deviceHandler = functions.https.onRequest(async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).send("Only POST allowed");
  }

  const {action, mac} = req.body;

  if (!action || typeof action !== "string") {
    return res.status(400).json({
      message: "Missing or invalid 'action' parameter.",
    });
  }

  try {
    switch (action) {
      case "register": {
        if (!mac || typeof mac !== "string") {
          return res.status(400).json({
            message: "Invalid or missing MAC address.",
          });
        }

        const existing = await db
            .collection("macOtpPairs")
            .where("mac", "==", mac)
            .get();

        if (!existing.empty) {
          const existingDoc = existing.docs[0].data();
          return res.status(200).json({
            message: "MAC already exists.",
            mac,
            otp: existingDoc.otp,
          });
        }

        const otp = generateOTP();

        await db.collection("macOtpPairs").add({
          mac,
          otp,
          timestamp: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`✅ New MAC registered: ${mac} → OTP: ${otp}`);

        const buttonEvents = await db
            .collection("buttonEvents")
            .where("mac", "==", mac)
            .get();

        const deletes = [];
        buttonEvents.forEach((doc) => {
          deletes.push(
              db.collection("buttonEvents").doc(doc.id).delete(),
          );
        });

        await Promise.all(deletes);

        console.log(`🗑️ Deleted ${deletes.length} buttonEvents for ${mac}`);

        return res.status(200).json({
          message: "New MAC registered and OTP issued.",
          mac,
          otp,
        });
      }

      case "delete":
        return res.status(501).json({
          message: "'delete' action not implemented yet.",
        });

      case "reset":
        return res.status(501).json({
          message: "'reset' action not implemented yet.",
        });

      case "get":
        return res.status(501).json({
          message: "'get' action not implemented yet.",
        });

      default:
        return res.status(400).json({
          message: `Unknown action '${action}'`,
        });
    }
  } catch (error) {
    console.error("❌ Error processing request:", error);
    return res.status(500).json({message: "Internal server error."});
  }
});
