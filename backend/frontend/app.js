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

		if (response.ok) {
			resultElm.textContent = `Success: ${data.message}`;
			resultElm.style.borderColor = '#4CAF50';
			currentSessionId = data.session_id;
			userId = data.user_id;

			//ENABLE BUTTONS
			document.getElementById('accessButton').disabled = false;
			document.getElementById('loginButton').disabled = false;
			document.getElementById('simulateIpChange').disabled = false;
			document.getElementById('simulateUserAgentChange').disabled = false;

			await fetchCsrfToken();
		} else {
			resultElm.textContent = `Error: ${data.message}`;
			resultElm.style.borderColor = '#f44336';
		}
		resultElm.style.display = 'block';
	} catch (error) {
		console.error('Error:', error);
		
	}
});

document.getElementById('accessButton').addEventListener('click', async () => {
	try {
		const response = await fetch('/protected', {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
			}
		});
		const data = await response.json();
		const resultElm = document.getElementById('accessResult');

		if (response.ok) {
			resultElm.textContent = `Success: ${data.message}. User: ${data.user.username}`;
			resultElm.style.borderColor = '#4CAF50';
		} else {
			resultElm.textContent = `Error: ${data.message}`;
			resultElm.style.borderColor = '#f44336';

			if (data.message.includes('hijacking')) {
				disableButtons();
			}
		}

		resultElm.style.display = 'block';
	} catch (error) {
		console.error('Error:', error);
	}
});

document.getElementById('logoutButton').addEventListener('click', async () => {
	try {
		const response = await fetch('/logout', {
			method: 'POST', 
			headers: {
				'Content-Type': 'application/json',
				'X-CSRF-Token': csrfToken || ''
			},
			body: JSON.stringify({ user_id: userId })
		});

		const data = await response.json();
		const resultElm = document.getElementById('logoutResult');

		if (response.ok) {
			resultElm.textContent = `Success: ${data.message}`;
			resultElm.style.borderColor = '#4CAF50';
			disableButtons();

			// Get fresh CSRF token after logout
			await fetchCsrfToken();
		} else {
			resultElm.textContent = `Error: ${data.message}`;
			resultElm.style.borderColor = '#f44336';
		}
		resultElm.style.display = 'block';
	} catch (error) {
		console.error('Error:', error);
	}
});

document.getElementById('simulateIpChange').addEventListener('click', async () => {
	try {
		const response = await fetch('/protected', {
			method: 'GET',
			headers: {
				'Content-Type': 'application/json',
				'X-Simulated-IP': '123.45.67.89'
			}
		});

                const data = await response.json();
                const resultElem = document.getElementById('simulationResult');
        
                if (!response.ok && data.message.includes('IP address')) {
			resultElem.textContent = `Hijacking Detection Success: ${data.message}`;
			resultElem.style.borderColor = '#4CAF50';
			disableButtons();
		} else {
			resultElem.textContent = 'Note: In a real application, the IP address change would be detected server-side. This is just a simulation.';
			resultElem.style.borderColor = '#ff9800';
		}

		resultElm.style.display = 'block';
	} catch (error) {
		console.error('Error:', error);
	}
});

document.getElementById('simulateUserAgentChange').addEventListener('click', async () => {
    try {
        // For demo purposes. In reality, you cannot easily spoof User-Agent via JavaScript
        // This simulation uses a custom header our backend would interpret
        const response = await fetch('/protected', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-Simulated-User-Agent': 'Fake Browser/1.0' // This is just for demo purposes
            }
        });
        
        const data = await response.json();
        const resultElem = document.getElementById('simulationResult');
        
        if (!response.ok && data.message.includes('User agent')) {
            resultElem.textContent = `Hijacking Detection Success: ${data.message}`;
            resultElem.style.borderColor = '#4CAF50';
            disableButtons();
        } else {
            resultElem.textContent = 'Note: In a real application, the User-Agent change would be detected server-side. This is just a simulation.';
            resultElem.style.borderColor = '#ff9800';
        }
        
        resultElem.style.display = 'block';
    } catch (error) {
        console.error('Error:', error);
    }
});


function disableButtons() {
	document.getElementById('accessButton').disabled = true;
	document.getElementById('logoutButton').disabled = true;
	document.getElementById('simulateIpChange').disabled = true;
	document.getElementById('simulateUserAgentChange').disabled = true;
	currentSessionId = null
	userId = null;
}


document.addEventListener("DOMContentLoaded", () => {
	console.log("Frontend Loaded");
});
