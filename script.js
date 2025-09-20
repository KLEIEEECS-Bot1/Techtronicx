// --- DOM Elements ---
const authContainer = document.getElementById('auth-container');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const confirmPasswordContainer = document.getElementById('confirm-password-container');
const confirmPasswordInput = document.getElementById('confirm-password');
const primaryAuthBtn = document.getElementById('primary-auth-btn');
const guestBtn = document.getElementById('guest-btn');
const authError = document.getElementById('auth-error');
const authTitle = document.getElementById('auth-title');
const authSubtitle = document.getElementById('auth-subtitle');
const authToggleText = document.getElementById('auth-toggle-text');
const authToggleBtn = document.getElementById('auth-toggle-btn');
const appContainer = document.getElementById('app-container');
const logoutBtn = document.getElementById('logout-btn');
const userEmailSpan = document.getElementById('user-email');
const cryptoSelect = document.getElementById('crypto-select');
const cryptoSearchInput = document.getElementById('crypto-search');
const cryptoIconPrice = document.getElementById('crypto-icon-price');
const alertCondition = document.getElementById('alert-condition');
const priceThresholdInput = document.getElementById('price-threshold');
const addAlertBtn = document.getElementById('add-alert-btn');
const activeAlertsList = document.getElementById('active-alerts-list');
const notificationsList = document.getElementById('notifications-list');
const toast = document.getElementById('toast');

// --- STATE MANAGEMENT ---
let activeAlerts = [];
let triggeredAlerts = [];
let prices = {};
let availableCryptos = [];
let currentUserEmail = null;
let priceInterval;
let isLoginView = true;
let appInitialized = false;

// --- MOCK AUTHENTICATION & LOCAL STORAGE ---

/**
 * Hashes a password using the SHA-256 algorithm.
 * @param {string} password The password to hash.
 * @returns {Promise<string>} A promise that resolves to the hex-encoded hash.
 */
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

/**
 * Verifies a password against a stored hash.
 * @param {string} password The password entered by the user.
 * @param {string} storedHash The hash retrieved from storage.
 * @returns {Promise<boolean>} A promise that resolves to true if passwords match.
 */
async function verifyPassword(password, storedHash) {
    const hashOfInput = await hashPassword(password);
    return hashOfInput === storedHash;
}

function checkLoginStatus() {
    currentUserEmail = sessionStorage.getItem('cryptoUser');
    if (currentUserEmail) {
        showApp();
    } else {
        showAuth();
    }
}

function showApp() {
    userEmailSpan.textContent = currentUserEmail;
    authContainer.classList.add('hidden');
    appContainer.classList.remove('hidden');
    loadAlertsFromLocalStorage();
    if (!appInitialized) {
        initApp(); 
        appInitialized = true;
    }
}

function showAuth() {
    currentUserEmail = null;
    authContainer.classList.remove('hidden');
    appContainer.classList.add('hidden');
    activeAlerts = [];
    triggeredAlerts = [];
    isLoginView = true;
    updateAuthView();
    if (priceInterval) clearInterval(priceInterval);
    appInitialized = false;
}

function updateAuthView() {
    authError.textContent = '';
    emailInput.value = '';
    passwordInput.value = '';
    confirmPasswordInput.value = '';
    if (isLoginView) {
        authTitle.textContent = 'Welcome Back!';
        authSubtitle.textContent = 'Login to access your dashboard.';
        primaryAuthBtn.textContent = 'Login';
        confirmPasswordContainer.classList.add('hidden');
        authToggleText.textContent = "Don't have an account?";
        authToggleBtn.textContent = 'Sign Up';
    } else {
        authTitle.textContent = 'Create an Account';
        authSubtitle.textContent = 'Get started in seconds.';
        primaryAuthBtn.textContent = 'Create Account';
        confirmPasswordContainer.classList.remove('hidden');
        authToggleText.textContent = 'Already have an account?';
        authToggleBtn.textContent = 'Login';
    }
}

function showLoginViewWithSuccess(message) {
    isLoginView = true;
    updateAuthView();
    authError.textContent = message;
    authError.classList.remove('text-red-500');
    authError.classList.add('text-green-500');
}

authToggleBtn.addEventListener('click', () => {
    isLoginView = !isLoginView;
    updateAuthView();
});

primaryAuthBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;
    const users = JSON.parse(localStorage.getItem('cryptoUsers')) || {};

    // Reset error message style
    authError.textContent = '';
    authError.classList.remove('text-green-500');
    authError.classList.add('text-red-500');

    if (!email || !password) {
        authError.textContent = 'Email and password cannot be empty.';
        return;
    }
    if (password.length < 6) {
        authError.textContent = 'Password must be at least 6 characters.';
        return;
    }

    if (isLoginView) { // Login logic
        const userData = users[email];
        if (userData && await verifyPassword(password, userData.hash)) {
            sessionStorage.setItem('cryptoUser', email);
            checkLoginStatus();
        } else {
            authError.textContent = 'Invalid email or password.';
        }
    } else { // Sign-up logic
        if (password !== confirmPasswordInput.value) {
            authError.textContent = 'Passwords do not match.';
            return;
        }
        if (users[email]) {
            authError.textContent = 'An account with this email already exists.';
            return;
        }
        const hashedPassword = await hashPassword(password);
        users[email] = { hash: hashedPassword, signedUp: new Date().toISOString() };
        localStorage.setItem('cryptoUsers', JSON.stringify(users));
        
        showLoginViewWithSuccess('Account created successfully! Please log in.');
    }
});

guestBtn.addEventListener('click', () => {
    sessionStorage.setItem('cryptoUser', 'Guest User');
    checkLoginStatus();
});

logoutBtn.addEventListener('click', () => {
    sessionStorage.removeItem('cryptoUser');
    checkLoginStatus();
});

// --- LOCAL STORAGE DATA HANDLING ---
function getAlertsStorageKey() {
    return `cryptoAlerts_${currentUserEmail}`;
}

function saveAlertsToLocalStorage() {
    if (!currentUserEmail) return;
    localStorage.setItem(getAlertsStorageKey(), JSON.stringify({ active: activeAlerts, triggered: triggeredAlerts }));
}

function loadAlertsFromLocalStorage() {
    if (!currentUserEmail) return;
    const savedData = localStorage.getItem(getAlertsStorageKey());
    if (savedData) {
        const data = JSON.parse(savedData);
        activeAlerts = data.active || [];
        triggeredAlerts = data.triggered || [];
    } else {
        activeAlerts = [];
        triggeredAlerts = [];
    }
    renderAlerts();
    renderNotifications();
}

// --- CORE APP LOGIC ---
function showToast(message, type = 'bg-green-500') {
    toast.textContent = message;
    toast.className = `fixed top-5 right-5 text-white py-2 px-4 rounded-lg shadow-lg ${type}`;
    toast.classList.remove('hidden');
    setTimeout(() => toast.classList.add('hidden'), 3000);
}

async function fetchCryptoList() {
    try {
        const response = await fetch('https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&order=market_cap_desc&per_page=100&page=1');
        if (!response.ok) throw new Error('Network response was not ok');
        availableCryptos = await response.json();
        populateCryptoDropdown();
        fetchPrices();
    } catch (error) {
        console.error("Error fetching crypto list:", error);
        showToast("Could not fetch crypto data.", "bg-red-500");
    }
}

function populateCryptoDropdown(searchTerm = '') {
    const lowerCaseSearchTerm = searchTerm.toLowerCase().trim();
    const filteredCryptos = availableCryptos.filter(coin => 
        coin.name.toLowerCase().includes(lowerCaseSearchTerm) || 
        coin.symbol.toLowerCase().includes(lowerCaseSearchTerm)
    );
    cryptoSelect.innerHTML = filteredCryptos.map(coin => `<option value="${coin.id}">${coin.name} (${coin.symbol.toUpperCase()})</option>`).join('');
    if (filteredCryptos.length > 0) {
        updateCurrentPrice(cryptoSelect.value);
    }
}

function updateCurrentPrice(cryptoId) {
    const coin = availableCryptos.find(c => c.id === cryptoId);
    if (!coin) return;
    const currentPrice = prices[cryptoId] ? `$${prices[cryptoId].toLocaleString()}` : 'Loading...';
     cryptoIconPrice.innerHTML = `
        <img src="${coin.image}" alt="${coin.name}" class="w-10 h-10 mr-3 rounded-full">
        <div>
            <p class="font-bold text-lg">${coin.name}</p>
            <p id="current-price-${cryptoId}" class="text-gray-400 text-sm">${currentPrice}</p>
        </div>
    `;
}

async function fetchPrices() {
    if (availableCryptos.length === 0) return;
    const ids = availableCryptos.map(c => c.id).join(',');
    try {
        const response = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd`);
        if (!response.ok) throw new Error('Network response was not ok for prices');
        const priceData = await response.json();
        for (const id in priceData) {
            prices[id] = priceData[id].usd;
        }
        updateCurrentPrice(cryptoSelect.value);
        checkAlerts();
    } catch (error) {
        console.error('Error fetching prices:', error);
    }
}

function checkAlerts() {
    const newlyTriggered = [];
    activeAlerts = activeAlerts.filter(alert => {
        const currentPrice = prices[alert.id];
        if (!currentPrice) return true; 

        const conditionMet = (alert.condition === 'above' && currentPrice > alert.threshold) ||
                             (alert.condition === 'below' && currentPrice < alert.threshold);

        if (conditionMet) {
            newlyTriggered.push({ ...alert, triggeredAt: new Date().toISOString(), triggeredPrice: currentPrice });
            return false;
        }
        return true;
    });

    if (newlyTriggered.length > 0) {
        triggeredAlerts.unshift(...newlyTriggered);
        renderAlerts();
        renderNotifications();
        saveAlertsToLocalStorage();
        showToast(`You have ${newlyTriggered.length} new triggered alert(s)!`, 'bg-blue-500');
    }
}

function renderAlerts() {
    if (activeAlerts.length === 0) {
        activeAlertsList.innerHTML = '<p class="text-gray-400 text-center">No active alerts.</p>';
        return;
    }
    activeAlertsList.innerHTML = activeAlerts.map(alert => {
        const coin = availableCryptos.find(c => c.id === alert.id);
        if (!coin) return '';
        return `
            <div class="flex justify-between items-center bg-gray-700 p-3 rounded-lg">
                <div class="flex items-center">
                    <img src="${coin.image}" class="w-8 h-8 mr-3 rounded-full">
                    <div>
                        <p class="font-medium">${coin.symbol.toUpperCase()}</p>
                        <p class="text-sm text-gray-400">
                            <i class="fas ${alert.condition === 'above' ? 'fa-arrow-up text-green-400' : 'fa-arrow-down text-red-400'}"></i> 
                            ${alert.condition} $${alert.threshold.toLocaleString()}
                        </p>
                    </div>
                </div>
                <button class="text-gray-400 hover:text-white btn-danger rounded-full w-8 h-8 flex items-center justify-center remove-alert-btn" data-alert='${JSON.stringify(alert)}'>
                    <i class="fas fa-times"></i>
                </button>
            </div>`;
    }).join('');
}

function renderNotifications() {
    if (triggeredAlerts.length === 0) {
        notificationsList.innerHTML = '<p class="text-gray-400 text-center">No triggered alerts yet.</p>';
        return;
    }
    notificationsList.innerHTML = triggeredAlerts.map(alert => {
        const coin = availableCryptos.find(c => c.id === alert.id);
        if (!coin) return '';
        const time = new Date(alert.triggeredAt).toLocaleTimeString();
        return `
            <div class="flex items-center text-sm p-2 rounded-md bg-gray-700 notification">
                <i class="fas fa-check-circle mr-3 ${alert.condition === 'above' ? 'text-green-400' : 'text-red-400'}"></i>
                <div>
                    <strong>${coin.symbol.toUpperCase()}</strong> went ${alert.condition} $${alert.threshold.toLocaleString()}
                    <span class="text-gray-400 ml-1">(@ $${alert.triggeredPrice.toLocaleString()} at ${time})</span>
                </div>
            </div>`;
    }).join('');
}

// --- EVENT LISTENERS ---
cryptoSearchInput.addEventListener('input', (e) => populateCryptoDropdown(e.target.value));
cryptoSelect.addEventListener('change', () => updateCurrentPrice(cryptoSelect.value));

addAlertBtn.addEventListener('click', () => {
    const id = cryptoSelect.value;
    const threshold = parseFloat(priceThresholdInput.value);
    const condition = alertCondition.value;

    if (!id || !threshold || threshold <= 0) {
        showToast('Please enter a valid price threshold.', 'bg-red-500');
        return;
    }
    const existingAlert = activeAlerts.find(a => a.id === id && a.threshold === threshold && a.condition === condition);
    if (existingAlert) {
        showToast('This alert already exists.', 'bg-yellow-500');
        return;
    }

    activeAlerts.push({ id, threshold, condition });
    renderAlerts();
    saveAlertsToLocalStorage();
    showToast(`Alert set for ${id.charAt(0).toUpperCase() + id.slice(1)}!`);
    priceThresholdInput.value = '';
});

activeAlertsList.addEventListener('click', e => {
    const removeBtn = e.target.closest('.remove-alert-btn');
    if (removeBtn) {
        const alertToRemove = JSON.parse(removeBtn.dataset.alert);
        activeAlerts = activeAlerts.filter(a => 
            !(a.id === alertToRemove.id && a.threshold === alertToRemove.threshold && a.condition === alertToRemove.condition)
        );
        renderAlerts();
        saveAlertsToLocalStorage();
        showToast('Alert removed.', 'bg-yellow-500');
    }
});

// --- APP INITIALIZATION ---
function initApp() {
    fetchCryptoList();
    if (priceInterval) clearInterval(priceInterval);
    priceInterval = setInterval(fetchPrices, 30000);
}

// Initialize Auth View on first load
if (!window.crypto || !window.crypto.subtle) {
    authError.textContent = "Crypto API not supported. Use a secure (HTTPS) connection.";
    primaryAuthBtn.disabled = true;
    guestBtn.disabled = true;
} else {
    checkLoginStatus();
    updateAuthView();
}