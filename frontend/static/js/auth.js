// Authentication module
// base64-js is loaded globally via script tag
const base64js = window.base64js;

console.log('Auth script loading...');


// Derive encryption key from server-provided session ID and timestamp
function deriveEncryptionKey() {
    try {
        if (!window.__SERVER_DATA || !window.__SERVER_DATA.session_id || !window.__SERVER_DATA.timestamp) {
            throw new Error('Missing server data for key derivation');
        }

        const { session_id, timestamp } = window.__SERVER_DATA;
        // Match backend's bcrypt cost factor of 14 and explicit timestamp conversion
        const key = dcodeIO.bcrypt.hashSync(session_id + timestamp.toString(), 14);
        
        // Convert to Uint8Array and ensure exactly 32 bytes
        const keyBytes = new TextEncoder().encode(key);
        return keyBytes.slice(0, 32);
    } catch (error) {
        console.error('Key derivation failed:', error);
        throw error;
    }
}

// Encrypt username with password only
async function encryptUsername(username, password) {
    const passwordKey = await deriveKeyFromPassword(password);
    return encryptWithKey(username, passwordKey);
}

// Encrypt data with specified key and version
async function encryptWithKey(data, key, version = 1) {
    try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const alg = { name: 'AES-GCM', iv };
        
        // Ensure key is Uint8Array with exactly 32 bytes
        const keyBytes = key instanceof Uint8Array ? key : new TextEncoder().encode(key);
        const finalKey = keyBytes.slice(0, 32);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            finalKey,
            alg,
            false,
            ['encrypt']
        );
        
        const encrypted = await crypto.subtle.encrypt(
            alg, 
            cryptoKey, 
            new TextEncoder().encode(data)
        );
        
        // Combine IV and ciphertext into single buffer
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);
        
        // Return Base64 encoded string with version info
        return {
            version,
            iv: base64js.fromByteArray(iv),
            data: base64js.fromByteArray(new Uint8Array(encrypted))
        };
    } catch (error) {
        console.error('Encryption failed:', error);
        throw new Error('ENCRYPTION_FAILED');
    }
}

// Handle key rotation errors by retrying with latest version
async function handleKeyRotationError(operation, data, key, retries = 1) {
    try {
        const currentVersion = window.__SERVER_DATA?.keyVersion || 1;
        const result = await operation(data, key, currentVersion);
        return result;
    } catch (error) {
        if (error.message === 'KEY_VERSION_MISMATCH' && retries > 0) {
            // Refresh key version from server and retry
            await fetchKeyVersion();
            return handleKeyRotationError(operation, data, key, retries - 1);
        }
        throw error;
    }
}

// Fetch current key version from server
async function fetchKeyVersion() {
    try {
        const res = await fetch('/api/v1/crypto/version', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (res.ok) {
            const data = await res.json();
            if (data.version) {
                window.__SERVER_DATA = window.__SERVER_DATA || {};
                window.__SERVER_DATA.keyVersion = data.version;
            }
        }
    } catch (error) {
        console.error('Failed to fetch key version:', error);
    }
}

// Derive key from password (for username encryption)
async function deriveKeyFromPassword(password) {
    // Match backend's bcrypt cost factor of 14
    const key = dcodeIO.bcrypt.hashSync(password, 14);
    // Ensure exactly 32 bytes (256 bits) for AES-GCM
    const keyBytes = new TextEncoder().encode(key);
    return keyBytes.slice(0, 32);
}

// Global state for signup validation
const signupState = {
    // Validation states
    usernameValid: false,
    passwordValid: false,
    confirmValid: false,
    identityGenerated: false,

    // Form elements
    elements: {
        usernameInput: null,
        passwordInput: null,
        confirmInput: null,
        passwordError: null,
        confirmError: null,
        signupButton: null,
        publicKeyDisplay: null
    },

    // Initialize form elements
    initElements() {
        this.elements = {
            usernameInput: document.getElementById('signup-username-input'),
            passwordInput: document.getElementById('signup-password-input'),
            confirmInput: document.getElementById('confirm-password-input'),
            passwordError: document.getElementById('signup-password-error'),
            confirmError: document.getElementById('signup-confirm-password-error'),
            signupButton: document.getElementById('signup-button'),
            publicKeyDisplay: document.getElementById('public-key-display')
        };
        return this.checkElementsExist();
    },

    // Check all required elements exist
    checkElementsExist() {
        const {elements} = this;
        const allExist = elements.usernameInput && elements.passwordInput && 
                        elements.confirmInput && elements.passwordError && 
                        elements.confirmError && elements.signupButton &&
                        elements.publicKeyDisplay;
        
        if (!allExist) {
            console.error('Missing form elements', {
                usernameInput: !!elements.usernameInput,
                passwordInput: !!elements.passwordInput,
                confirmInput: !!elements.confirmInput,
                passwordError: !!elements.passwordError,
                confirmError: !!elements.confirmError,
                signupButton: !!elements.signupButton,
                publicKeyDisplay: !!elements.publicKeyDisplay
            });
        }
        return allExist;
    },

    get allValid() {
        return this.usernameValid && 
               this.passwordValid && 
               this.confirmValid && 
               this.identityGenerated;
    },

    updateButton() {
        if (this.elements.signupButton) {
            this.elements.signupButton.disabled = !this.allValid;
            this.elements.signupButton.classList.toggle('ghost', !this.allValid);
        }
    }
};

// Wallet connection functions
// Handle form submission for signup
export async function handleSignup(e) {
    e.preventDefault();
    
    const form = e.target;
    const username = form.elements['username'].value;
    const password = form.elements['password'].value;
    
    // Generate hashes and encrypted data
    const usernameHash = dcodeIO.bcrypt.hashSync(username, 14);
    const passwordHash = dcodeIO.bcrypt.hashSync(password, 14);
    const usernameEncrypted = await encryptUsername(username, password);

    try {
        // Generate identity first
        const identityRes = await fetch('/api/v1/identity/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        });

        if (!identityRes.ok) {
            throw new Error('Failed to generate identity');
        }

        const identityData = await identityRes.json();
        if (!identityData.success) {
            throw new Error('Identity generation failed');
        }

        // Prepare signup data
        const signupData = {
            username_hash: dcodeIO.bcrypt.hashSync(username, 14),
            username_encrypted: usernameEncrypted,
            password_hash: dcodeIO.bcrypt.hashSync(password, 14),
            alias: signupState.currentIdentity.alias,
            public_key: signupState.currentIdentity.publicKey
        };

        // Encrypt entire signup data object with session key and handle rotation errors
        const encryptedSignupData = await handleKeyRotationError(
            async (data, key, version) => {
                return encryptWithKey(JSON.stringify(data), key, version);
            },
            signupData,
            deriveEncryptionKey()
        );
        
        console.log('Encrypted signup request data:', encryptedSignupData);
        
        const signupRes = await fetch('/api/v1/auth/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                ...encryptedSignupData,
                key_version: encryptedSignupData.version
            }),
            credentials: 'same-origin'
        });

        if (!signupRes.ok) {
            const errorData = await signupRes.json();
            throw new Error(errorData.detail || 'Signup failed');
        }

        const data = await signupRes.json();
        if (data.success && data.redirect) {
            window.location.href = data.redirect;
        }
    } catch (error) {
        console.error('Signup error:', error);
        alert('Signup failed: ' + error.message);
    }
}

export async function connectPhantom() {
    try {
        if (!window.solana || !window.solana.isPhantom) {
            throw new Error('Phantom wallet not detected');
        }
        
        const response = await window.solana.connect();
        const publicKey = response.publicKey.toString();
        const timestamp = generateTimestampNonce();
        
        const authResponse = await fetch('/api/v1/auth/wallet', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                walletAddress: publicKey,
                walletType: 'phantom',
                timestamp: timestamp
            })
        });
        
        if (!authResponse.ok) {
            throw new Error('Authentication failed');
        }
        
        const data = await authResponse.json();
        if (data.success && data.redirect) {
            window.location.href = data.redirect;
        }
    } catch (error) {
        console.error('Phantom connection error:', error);
        alert('Failed to connect Phantom wallet: ' + error.message);
    }
}

export async function connectMetaMask() {
    try {
        if (!window.ethereum || !window.ethereum.isMetaMask) {
            throw new Error('MetaMask not detected');
        }
        
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const publicKey = accounts[0];
        const timestamp = generateTimestampNonce();
        
        const authResponse = await fetch('/api/v1/auth/wallet', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                walletAddress: publicKey,
                walletType: 'metamask',
                timestamp: timestamp
            })
        });
        
        if (!authResponse.ok) {
            throw new Error('Authentication failed');
        }
        
        const data = await authResponse.json();
        if (data.success && data.redirect) {
            window.location.href = data.redirect;
        }
    } catch (error) {
        console.error('MetaMask connection error:', error);
        alert('Failed to connect MetaMask: ' + error.message);
    }
}

// Decrypt data with specified key
async function decryptWithKey(encryptedData, key) {
    try {
        // Convert key to Uint8Array if needed
        const keyBytes = key instanceof Uint8Array ? key : new TextEncoder().encode(key);
        const finalKey = keyBytes.slice(0, 32);
        
        // Decode Base64 IV and ciphertext
        const iv = base64js.toByteArray(encryptedData.iv);
        const ciphertext = base64js.toByteArray(encryptedData.data);
        
        const alg = { name: 'AES-GCM', iv };
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            finalKey,
            alg,
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            alg,
            cryptoKey,
            ciphertext
        );
        
        return new TextDecoder().decode(decrypted);
    } catch (error) {
        console.error('Decryption failed:', error);
        throw error;
    }
}

// Encrypt data with password using AES-GCM with bcrypt key derivation
async function encryptWithPassword(data, password) {
    const salt = dcodeIO.bcrypt.genSaltSync(10);
    const derivedKey = dcodeIO.bcrypt.hashSync(password, salt).slice(0, 32);
    const keyBuffer = new TextEncoder().encode(derivedKey);
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const alg = { name: 'AES-GCM', iv };
    const cryptoKey = await crypto.subtle.importKey(
        'raw', keyBuffer, alg, false, ['encrypt']
    );
    
    const dataUtf8 = new TextEncoder().encode(data);
    const cipherBuffer = await crypto.subtle.encrypt(alg, cryptoKey, dataUtf8);
    
    const cipherArray = Array.from(new Uint8Array(cipherBuffer));
    const ciphertext = cipherArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
    
    return ivHex + ':' + ciphertext;
}

// Password strength utilities
export function checkPasswordStrength(password) {
    let strength = 0;
    let maxstrength = 4;
    
    if (password.length >= 16)  strength += 1;
    if (/[A-Z]/.test(password)) strength += 1;
    if (/[a-z]/.test(password)) strength += 1;
    if (/[0-9]/.test(password)) strength += 1;
    if (/[^A-Za-z0-9]/.test(password)) strength += 1;
    
    if (password.length < 6) strength = 0;
    if (password === password.toLowerCase()) strength = Math.max(0, strength - 1);
    if (password === password.toUpperCase()) strength = Math.max(0, strength - 1);
    if (/^[0-9]+$/.test(password)) strength = Math.max(0, strength - 1);

    strength = Math.min(4, strength);
    if (strength == maxstrength && password.length < 16) strength--;
    if (strength == maxstrength-1 && password.length < 12) strength--;
    if (strength == maxstrength && !(/[^A-Za-z0-9]/.test(password))) strength--;

    strength = Math.min (4, strength); 

    return strength;
}

export function updatePasswordStrength(password) {
    const strength = checkPasswordStrength(password);
    const strengthBar = document.getElementById('password-strength-bar');
    const strengthText = document.getElementById('password-strength-text');
    
    if (!strengthBar || !strengthText) return;
    
    let width = 0;
    let color = '';
    let text = '';
    
    switch(strength) {
        case 0:
            width = 10;
            color = 'var(--radix-colors-red-9)';
            text = 'Very weak';
            break;
        case 1:
            width = 25;
            color = 'var(--radix-colors-orange-9)';
            text = 'Weak';
            break;
        case 2:
            width = 50;
            color = 'var(--radix-colors-yellow-9)';
            text = 'Medium';
            break;
        case 3:
            width = 75;
            color = 'var(--radix-colors-yellow-green-9)';
            text = 'Strong';
            break;
        case 4:
            width = 100;
            color = 'var(--radix-colors-green-9)';
            text = 'Very strong';
            break;
    }
    
    strengthBar.style.width = `${width}%`;
    strengthBar.style.backgroundColor = color;
    strengthText.textContent = text;
    strengthText.style.color = color;
}

// Validation system
function validateField(input, errorId) {
    const errorElement = document.getElementById(errorId);
    const isValid = input.checkValidity();
    
    input.style.borderColor = '';
    errorElement.textContent = '';
    errorElement.style.display = 'none';
    
    if (!isValid) {
        let message = input.validationMessage;
        if (input.validity.valueMissing) {
            message = 'This field is required';
        } else if (input.validity.tooShort) {
            message = `Minimum length is ${input.minLength} characters`;
        } else if (input.validity.patternMismatch) {
            if (input.id === 'signup-username-input') {
                message = 'Username must start with a letter and contain only letters, numbers and underscores';
            } else if (input.id === 'password-input') {
                message = 'Password must contain at least one number, one uppercase and lowercase letter';
            }
        }
        
        errorElement.textContent = message;
        errorElement.style.display = 'block';
        input.style.borderColor = 'var(--radix-colors-red-9)';
    }
    
    return isValid;
}

function setupValidation() {
    console.log('Setting up validation...');
    
    // Initialize form elements
    if (!signupState.initElements()) {
        console.error('Cannot setup validation - missing form elements');
        return;
    }

    const forms = [
        document.getElementById('signin-form-element'),
        document.getElementById('signup-form-element')
    ].filter(Boolean);
    
    forms.forEach(form => {
        const inputs = form.querySelectorAll('input');
        
        inputs.forEach(input => {
            input.addEventListener('input', () => {
                const isValid = validateField(input, input.dataset.error);
                
                if (input.id === 'signup-username-input') {
                    signupState.usernameValid = isValid;
                    signupState.updateButton();
                }
                else if (input.id === 'signup-password-input') {
                    updatePasswordStrength(input.value);
                }
                
                if (input.id === 'signup-password-input' || input.id === 'confirm-password-input') {
                    const passwordInput = signupState.elements.passwordInput;
                    const confirmInput = signupState.elements.confirmInput;
                    
                    if (!passwordInput || !confirmInput) return;
                    
                    const password = passwordInput.value;
                    const confirmPassword = confirmInput.value;
                    const passwordError = document.getElementById('signup-password-error');
                    const confirmError = document.getElementById('signup-confirm-password-error');
                    
                    const {elements} = signupState;
                    
                    // Validate password strength
                    if (input.id === 'signup-password-input' && password) {
                        const hasUpper = /[A-Z]/.test(password);
                        const hasLower = /[a-z]/.test(password);
                        const hasNumber = /[0-9]/.test(password);
                        
                        const hasLetter = /[a-zA-Z]/.test(password);
                        if (!hasUpper || !hasLower || !hasNumber || !hasLetter || password.length < 8) {
                            elements.passwordError.textContent = 'Password must contain at least one letter, one uppercase, one lowercase, one number and be at least 8 characters';
                            elements.passwordError.style.display = 'block';
                            input.style.borderColor = 'var(--radix-colors-red-9)';
                            signupState.passwordValid = false;
                        } else {
                            elements.passwordError.style.display = 'none';
                            input.style.borderColor = '';
                            signupState.passwordValid = true;
                        }
                    }
                    
                    // Validate password match
                    if ((input.id === 'signup-password-input' || input.id === 'confirm-password-input') && 
                        password && confirmPassword) {
                        if (!elements.confirmInput) return;
                        
                        if (password !== confirmPassword) {
                            elements.confirmError.textContent = 'Passwords do not match';
                            elements.confirmError.style.display = 'block';
                            elements.confirmInput.style.borderColor = 'var(--radix-colors-red-9)';
                            signupState.confirmValid = false;
                        } else {
                            elements.confirmError.style.display = 'none';
                            elements.confirmInput.style.borderColor = '';
                            signupState.confirmValid = true;
                        }
                    }
                    
                    // Update identity generated state
                    signupState.identityGenerated = elements.publicKeyDisplay?.textContent !== 'Will be generated by server';
                    
                    // Update button state after all validations
                    signupState.updateButton();
                }
            });
            
            input.addEventListener('blur', () => {
                const isValid = validateField(input, input.dataset.error);
                if (input.id === 'signup-username-input') {
                    signupState.usernameValid = isValid;
                    signupState.updateButton();
                }
            });
        });
    });
}

// Tab initialization
function initTabs() {
    const signinTab = document.getElementById('signin-tab');
    const signupTab = document.getElementById('signup-tab');
    
    if (!signinTab || !signupTab) {
        console.error('Tab elements not found!');
        return;
    }

    function switchToSignin() {
        document.getElementById('signin-form').style.display = 'block';
        document.getElementById('signup-form').style.display = 'none';
        signinTab.classList.add('ghost');
        signupTab.classList.remove('ghost');
        signupTab.style.backgroundColor = 'var(--radix-colors-blue-9)';
        signupTab.style.color = 'white';
        signinTab.style.backgroundColor = '';
        signinTab.style.color = '';
        signinTab.disabled = true;
        signupTab.disabled = false;
    }

    function switchToSignup() {
        document.getElementById('signin-form').style.display = 'none';
        document.getElementById('signup-form').style.display = 'block';
        signinTab.classList.remove('ghost');
        signupTab.classList.add('ghost');
        signinTab.style.backgroundColor = 'var(--radix-colors-blue-9)';
        signinTab.style.color = 'white';
        signupTab.style.backgroundColor = '';
        signupTab.style.color = '';
        signupTab.disabled = true;
        signinTab.disabled = false;
        
        // Show identity placeholder and setup signup button
        document.getElementById('public-key-display').textContent = 'Will be generated by server';
        document.getElementById('alias-display').textContent = 'Loading...';
        const avatarCard = document.getElementById('avatar-card');
        avatarCard.innerHTML = '<svg width="80" height="80" viewBox="0 0 80 80" style="width: 80px; height: 80px;"><rect width="80" height="80" fill="var(--radix-colors-gray-3)"/></svg>';
        const signupButton = document.getElementById('signup-button');
        // Reset validation state when switching to signup
        signupState.usernameValid = false;
        signupState.passwordValid = false;
        signupState.confirmValid = false;
        signupState.identityGenerated = false;
        signupState.updateButton();
        
        updatePasswordStrength(document.getElementById('signup-password-input').value);
    }

    signinTab.addEventListener('click', switchToSignin);
    signupTab.addEventListener('click', switchToSignup);
    switchToSignin();
}

// Handle identity generation
function setupIdentityGeneration() {
    document.getElementById('generate-identity')?.addEventListener('click', () => {
        // Show loading state
        document.getElementById('public-key-display').textContent = 'Generating...';
        document.getElementById('alias-display').textContent = 'Generating...';
        document.getElementById('signup-button').disabled = true;
        
        // Call backend to generate identity
        fetch('/api/v1/identity/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to generate identity');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Store the current identity data
                signupState.currentIdentity = {
                    publicKey: data.userKey,
                    alias: data.userAlias,
                    avatarSVG: data.avatarSVG,
                    sessionID: data.sessionID
                };

                // Update identity card
                document.getElementById('alias-display').textContent = data.userAlias;
                document.getElementById('public-key-display').textContent = data.userKey;
                
                // Set avatar SVG from backend
                const avatarCard = document.getElementById('avatar-card');
                avatarCard.innerHTML = data.avatarSVG;

                // Check all validation conditions
                const signupButton = document.getElementById('signup-button');
                // Use centralized element references
                const {elements} = signupState;
                
                if (!signupState.checkElementsExist()) {
                    return;
                }
                
                const username = elements.usernameInput.value;
                const password = elements.passwordInput.value;
                const confirmPassword = elements.confirmInput.value;
                
                const allFieldsFilled = username.length > 0 && 
                                      password.length > 0 && 
                                      confirmPassword.length > 0;
                                      
                const allValid = !elements.passwordError.style.display && 
                              !elements.confirmError.style.display &&
                              allFieldsFilled;
                
                // Update validation states
                signupState.usernameValid = username.length > 0 && 
                    elements.usernameInput.checkValidity();
                
                const hasUpper = /[A-Z]/.test(password);
                const hasLower = /[a-z]/.test(password);
                const hasNumber = /[0-9]/.test(password);
                const hasLetter = /[a-zA-Z]/.test(password);
                
                signupState.passwordValid = password.length >= 8 && 
                    hasUpper && hasLower && hasNumber && hasLetter;
                
                signupState.confirmValid = confirmPassword === password;
                signupState.identityGenerated = true;
                
                // Update UI based on validation
                elements.passwordError.style.display = signupState.passwordValid ? 'none' : 'block';
                elements.confirmError.style.display = signupState.confirmValid ? 'none' : 'block';
                
                // Update button state
                signupState.updateButton();
            }
        })
        .catch(error => {
            console.error('Error generating identity:', error);
            document.getElementById('public-key-display').textContent = 'Error generating identity';
            document.getElementById('alias-display').textContent = 'Please try again';
        });
    });
}

// Toggle password visibility
function setupPasswordToggles() {
    const passwordInput = document.getElementById('signup-password-input');
    const confirmInput = document.getElementById('confirm-password-input');
    const passwordToggle = document.querySelector('#signup-password-input + button.password-toggle');
    const confirmToggle = document.querySelector('#confirm-password-input + button.password-toggle');

    function updateToggleState(isVisible) {
        // Update both inputs
        passwordInput.type = isVisible ? 'text' : 'password';
        confirmInput.type = isVisible ? 'text' : 'password';
        
        // Update both icons
        const svgPath = isVisible ? 
            `<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
             <line x1="1" y1="1" x2="23" y2="23"></line>` :
            `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
             <circle cx="12" cy="12" r="3"></circle>`;

        [passwordToggle, confirmToggle].forEach(toggle => {
            const svg = toggle.querySelector('svg');
            if (svg) {
                svg.innerHTML = svgPath;
                svg.setAttribute('stroke', 'var(--radix-colors-gray-11)');
            }
        });
    }

    // Handle toggle clicks
    [passwordToggle, confirmToggle].forEach(toggle => {
        toggle.addEventListener('click', () => {
            const isCurrentlyPassword = passwordInput.type === 'password';
            updateToggleState(isCurrentlyPassword);
        });
    });
}

// Handle secure sign in with encrypted credentials
export async function handleSignIn(e) {
    e.preventDefault();
    
    const form = e.target;
    const username = form.elements['username'].value;
    const password = form.elements['password'].value;
    
    // Generate ephemeral key pair
    const ephemeralKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        true,
        ["deriveKey"]
    );
    
    // Export public key
    const ephemeralPublicKey = await window.crypto.subtle.exportKey(
        "jwk",
        ephemeralKeyPair.publicKey
    );

    // Get server's public key (pre-loaded or fetched)
    const serverPublicKey = window.__SERVER_DATA?.publicKey;
    if (!serverPublicKey) {
        throw new Error("Missing server public key");
    }

    // Derive shared secret
    const sharedSecret = await window.crypto.subtle.deriveKey(
        {
            name: "ECDH",
            public: await window.crypto.subtle.importKey(
                "jwk",
                serverPublicKey,
                { name: "ECDH", namedCurve: "P-256" },
                false,
                []
            )
        },
        ephemeralKeyPair.privateKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt"]
    );

    // Encrypt password with shared secret
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedPassword = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        sharedSecret,
        new TextEncoder().encode(password)
    );

    // Prepare secure signin data
    const signinData = {
        username_hash: dcodeIO.bcrypt.hashSync(username, 14),
        encrypted_password: {
            iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
            data: Array.from(new Uint8Array(encryptedPassword)).map(b => b.toString(16).padStart(2, '0')).join('')
        },
        ephemeral_public_key: ephemeralPublicKey
    };

    // Encrypt entire signin data object with session key and handle rotation errors
    const encryptedSigninData = await handleKeyRotationError(
        async (data, key, version) => {
            return encryptWithKey(JSON.stringify(data), key, version);
        },
        signinData,
        deriveEncryptionKey()
    );
    
    try {
        const response = await fetch('/api/v1/auth/signin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                ...encryptedSigninData,
                key_version: encryptedSigninData.version
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Sign in failed');
        }

        const data = await response.json();
        if (data.success && data.redirect) {
            window.location.href = data.redirect;
        }
    } catch (error) {
        console.error('Sign in error:', error);
        alert('Sign in failed: ' + error.message);
    }
}

// Initialize authentication system
export function initAuth() {
    console.log('Initializing auth system...');

    // Verify server data is present
    if (!window.__SERVER_DATA || !window.__SERVER_DATA.session_id || !window.__SERVER_DATA.timestamp) {
        console.error('Missing required server data');
        return;
    }
    
    // Setup form handlers
    document.getElementById('signin-form-element')?.addEventListener('submit', handleSignIn);
    document.getElementById('signup-form-element')?.addEventListener('submit', handleSignup);
    
    // Setup wallet connection buttons
    document.getElementById('connect-phantom')?.addEventListener('click', connectPhantom);
    document.getElementById('connect-metamask')?.addEventListener('click', connectMetaMask);
    
    // Initialize validation system
    setupValidation();
    
    // Initialize tabs
    initTabs();
    
    // Setup identity generation
    setupIdentityGeneration();
    
    // Setup password visibility toggles
    setupPasswordToggles();
}
