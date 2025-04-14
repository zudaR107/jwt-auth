const API = "http://localhost:8080";

let accessToken = "";
let refreshToken = "";

function showResponse(text) {
  document.getElementById("response").textContent = text;
}

// Универсальная обёртка fetch с JSON-обработкой и выводом ошибок
function fetchJson(url, options = {}) {
  return fetch(url, options).then(async res => {
    const text = await res.text();
    if (!res.ok) throw new Error(text);
    try {
      return JSON.parse(text);
    } catch (e) {
      throw new Error("Invalid JSON: " + text);
    }
  });
}

function register() {
  const username = document.getElementById("reg-username").value;
  const password = document.getElementById("reg-password").value;

  fetch(`${API}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  })
    .then(res => res.text())
    .then(showResponse)
    .catch(err => showResponse("Register failed: " + err.message));
}

function login() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;

  fetchJson(`${API}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  })
    .then(data => {
      accessToken = data.access_token;
      refreshToken = data.refresh_token;
      document.getElementById("access-token").value = accessToken;
      document.getElementById("refresh-token").value = refreshToken;
      showResponse("Login successful");
    })
    .catch(err => showResponse("Login failed: " + err.message));
}

function refresh() {
  fetchJson(`${API}/refresh`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${refreshToken}`,
      "Content-Type": "application/json",
    },
    body: "{}",
  })
    .then(data => {
      accessToken = data.access_token;
      document.getElementById("access-token").value = accessToken;
      showResponse("Access token refreshed");
    })
    .catch(err => showResponse("Refresh failed: " + err.message));
}

function getSecureData() {
  fetch(`${API}/secure/data`, {
    headers: {
      "Authorization": `Bearer ${accessToken}`,
    },
  })
    .then(res => res.text())
    .then(showResponse)
    .catch(err => showResponse("Error: " + err.message));
}

function logout() {
  fetch(`${API}/logout`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${refreshToken}`,
      "Content-Type": "application/json",
    },
    body: "{}",
  })
    .then(res => res.text())
    .then(showResponse)
    .catch(err => showResponse("Logout failed: " + err.message));
}
