let currentSessionId = null;
let userId = null;
let csrfToken = null;

async function fetchCsrfToken() {
	try {
		const response = await fetch('/csrf-token');
		const data = await response.json();
		csrfToken = data.csrf_token;
	} catch (error) {
		console.error('Error fetching CSRF token:', error);
	}
}

fetchCsrfToken();

document.getElementById('loginForm').addEventListener('submit', async (e) => {
	e.preventDefault();
	const username = document.getElementById('username').value;
	const password = document.getElementById('password').value;

	try {
		const response = await fetch('/login', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-CSRF-Token': csrfToken || ''
			},
			body: JSON.stringify({ username, password })
		});

		const data = await response.json();
		const resultElm = document.getElementById('loginReult');
	}
})


document.addEventListener("DOMContentLoaded", () => {
	console.log("Frontend Loaded");
});
