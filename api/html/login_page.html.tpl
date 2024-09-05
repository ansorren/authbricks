<!DOCTYPE html>
<html lang="en">
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #F4F4F4;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }

        h1 {
            font-size: 24px;
            margin-bottom: 20px;
        }

        form {
            background-color: #FFFFFF;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 300px;
        }

        label {
            display: block;
            font-weight: bold;
            margin-bottom: 10px;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            margin-bottom: 20px;
            padding: 10px;
            border: 1px solid #CCCCCC;
            border-radius: 4px;
            box-sizing: border-box;
        }

        button {
            background-color: #1E88E5;
            width: 100%;
            color: #FFFFFF;
            padding: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }

        button:hover {
            background-color: #1565C0;
        }

        .container {
            text-align: center;
            margin-bottom: 20px;
        }

        .forgot-password {
            text-align: center;
            margin-top: 10px;
        }

        a {
            color: #1E88E5;
            text-decoration: none;
        }

        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
<div>
    <div class="container">
        <h1>Login</h1>
 {{ email_password_connector }}
 {{ oidc_connectors }}
 {{ forgot_password }}
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Select all buttons whose ID starts with 'oidc-login-btn' and loop over them
    document.querySelectorAll('button[id^="oidc-login-btn"]').forEach(function(button) {
        button.addEventListener('click', function() {
            const id          = button.getAttribute('id');
            const connectorId = id.replace('oidc-login-btn-', '');  // Extract the connector ID
            const url         = `${window.location.origin}/oidc/${connectorId}`;

            fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
            .then(response => {
                if (response.ok) {
                    return response.json();
                } else {
                    throw new Error('Failed to login');
                }
            })
            .then(data => {
                console.log('Login successful', data);
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    });
});
</script>


<script>
// Get the form element by its ID
const form = document.getElementById('loginForm');
form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username   = document.getElementById('username').value;
    const password   = document.getElementById('password').value;
    const csrf_token = document.getElementById('csrf_token').value;

    const payload = {
        username,
        password
    };

    const submit = async () => {
        try {
            const response = await fetch(`${window.location}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrf_token,
                },
                body: JSON.stringify(payload),
            });
            return response;
        } catch (error) {
            console.log('error within fetch', error);
            return null;
        }
    };

    let res = await submit();
    if (res && res.ok) {
        window.location.assign(res.url);
    }
});
</script>
</body>
</html>
