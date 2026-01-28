// Vulnerable JavaScript for SAST Testing
// WARNING: This file contains intentional security vulnerabilities

// VULNERABILITY: Hardcoded API keys (CWE-798)
var API_KEY = 'api_key_VULNERABLE_4eC39HqLyjWDarjtT1zdp7dc';
var SECRET_KEY = 'super_secret_key_12345';
var AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
var AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
var STRIPE_KEY = 'stripe_VULNERABLE_4eC39HqLyjWDarjtT1zdp7dc';
var ADMIN_PASSWORD = 'admin123';

// VULNERABILITY: DOM-based XSS (CWE-79)
function displayMessage() {
    var message = window.location.hash.substring(1);
    document.getElementById('message').innerHTML = message;  // XSS
}

// VULNERABILITY: DOM-based XSS via URL parameter (CWE-79)
function showUserGreeting() {
    var urlParams = new URLSearchParams(window.location.search);
    var name = urlParams.get('name');
    if (name) {
        document.write('<h1>Welcome ' + name + '</h1>');  // XSS via document.write
    }
}

// VULNERABILITY: eval() with user input (CWE-95)
function calculate(expression) {
    return eval(expression);  // Code injection via eval
}

// VULNERABILITY: innerHTML with user data (CWE-79)
function updateProfile(userData) {
    document.getElementById('profile').innerHTML = userData;  // XSS
}

// VULNERABILITY: setTimeout with user input (CWE-95)
function delayedAction(code, delay) {
    setTimeout(code, delay);  // Code injection
}

// VULNERABILITY: new Function with user input (CWE-95)
function executeCode(code) {
    var fn = new Function(code);  // Code injection
    return fn();
}

// VULNERABILITY: Insecure localStorage usage (CWE-922)
function storeCredentials(username, password) {
    localStorage.setItem('username', username);
    localStorage.setItem('password', password);  // Storing password in localStorage
    localStorage.setItem('authToken', 'token_' + Date.now());  // Weak token
}

// VULNERABILITY: Insecure AJAX call (CWE-319)
function fetchData(url) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);  // No HTTPS enforcement
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
            document.getElementById('data').innerHTML = xhr.responseText;  // XSS
        }
    };
    xhr.send();
}

// VULNERABILITY: postMessage without origin check (CWE-346)
window.addEventListener('message', function(event) {
    // No origin validation - accepts messages from any origin
    eval(event.data);  // Execute received code
});

// VULNERABILITY: Open redirect (CWE-601)
function redirect() {
    var url = new URLSearchParams(window.location.search).get('url');
    window.location.href = url;  // Open redirect
}

// VULNERABILITY: Insecure random for security (CWE-330)
function generateToken() {
    return Math.random().toString(36).substring(2);  // Weak random
}

// VULNERABILITY: Exposing sensitive data in console (CWE-532)
function debugLogin(username, password) {
    console.log('Login attempt:', username, password);
    console.log('API Key:', API_KEY);
    console.log('Secret Key:', SECRET_KEY);
}

// VULNERABILITY: Sending credentials in URL (CWE-598)
function login(username, password) {
    window.location.href = '/login?username=' + username + '&password=' + password;
}

// VULNERABILITY: JSONP callback injection (CWE-79)
function loadExternalData(callback) {
    var script = document.createElement('script');
    script.src = 'http://external-api.com/data?callback=' + callback;  // JSONP injection
    document.body.appendChild(script);
}

// VULNERABILITY: Prototype pollution (CWE-1321)
function mergeObjects(target, source) {
    for (var key in source) {
        target[key] = source[key];  // No __proto__ check
    }
    return target;
}

// VULNERABILITY: RegEx DoS (CWE-1333)
function validateEmail(email) {
    var regex = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/;  // Evil regex
    return regex.test(email);
}

jQuery(document).ready(function() {
    // Process URL hash for XSS
    var userInput = window.location.hash.substr(1);
    if (userInput) {
        // VULNERABILITY: jQuery html() with user input (CWE-79)
        $('#content').html(decodeURIComponent(userInput));
    }
    
    // VULNERABILITY: JSON parse of untrusted data then innerHTML
    var jsonData = localStorage.getItem('userData');
    if (jsonData) {
        var data = JSON.parse(jsonData);
        $('#userInfo').html(data.name + ' - ' + data.email);  // XSS
    }
    
    // VULNERABILITY: Log sensitive info
    console.log('App initialized with API_KEY:', API_KEY);
    
    // Initialize vulnerable functions
    displayMessage();
    showUserGreeting();
});

