const defaults = {
  apiBase: "https://api.xgenguardian.com",
  portalApiBase: "https://api.xgenguardian.com",
  enabled: true,
  enforceWarn: false,
  telemetry: true,
  paranoidMode: false,
};

async function load() {
  const cfg = await chrome.storage.sync.get(defaults);
  document.getElementById("apiBase").value          = cfg.apiBase;
  document.getElementById("portalApiBase").value    = cfg.portalApiBase;
  document.getElementById("enabled").checked        = cfg.enabled;
  document.getElementById("enforceWarn").checked    = cfg.enforceWarn;
  document.getElementById("telemetry").checked      = cfg.telemetry;
  document.getElementById("paranoidMode").checked   = cfg.paranoidMode;
}

async function save() {
  const prevCfg = await chrome.storage.sync.get(defaults);
  const newParanoid = document.getElementById("paranoidMode").checked;
  const toSet = {
    apiBase:       document.getElementById("apiBase").value || defaults.apiBase,
    portalApiBase: document.getElementById("portalApiBase").value || defaults.portalApiBase,
    enabled:       document.getElementById("enabled").checked,
    enforceWarn:   document.getElementById("enforceWarn").checked,
    telemetry:     document.getElementById("telemetry").checked,
    paranoidMode:  newParanoid,
  };
  // Track when paranoid mode was first enabled so the 24-hour warmup window
  // in verdict-api (services/.../strictness.Apply) lines up with what the
  // backend uses. Zero out when disabled.
  if (newParanoid && !prevCfg.paranoidMode) {
    toSet.paranoidEnabledAt = Date.now();
  } else if (!newParanoid) {
    toSet.paranoidEnabledAt = 0;
  }
  await chrome.storage.sync.set(toSet);

  const el = document.getElementById("saved");
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 1500);
}

document.addEventListener("DOMContentLoaded", load);
document.getElementById("save").addEventListener("click", save);
