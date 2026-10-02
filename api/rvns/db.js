// rvns/db.js
import admin from 'firebase-admin';

let dbInstance = null;

try {
  if (!admin.apps.length) {
    const key = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    if (!key) {
      console.error('[DB] FIREBASE_PRIVATE_KEY tidak di-set');
    } else {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: key
        }),
        databaseURL: process.env.FIREBASE_DATABASE_URL
      });
      dbInstance = admin.database();
    }
  } else {
    dbInstance = admin.database();
  }
} catch (e) {
  console.error('[DB] Init error:', e?.message || e);
}

export const db = dbInstance || {
  ref: () => ({
    once: async () => { throw new Error('DB not initialized'); },
    set: async () => { throw new Error('DB not initialized'); },
    push: () => ({ key: 'temp_' + Date.now() }),
    update: async () => { throw new Error('DB not initialized'); },
    remove: async () => { throw new Error('DB not initialized'); }
  })
};

export default admin;