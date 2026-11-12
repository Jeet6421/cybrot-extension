// Settings for the CYBROT extension.
//
// engineUrl: address of the local CYBROT Python engine.
// If you change the port, also change host_permissions in manifest.json,
// or the browser will block the requests.
const CYBROT_CONFIG = {
  engineUrl: "http://127.0.0.1:8000",
  dashboardUrl: "http://127.0.0.1:8000/dashboard",
  pollIntervalMs: 1500,
};
