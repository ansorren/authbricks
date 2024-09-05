<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorization failed</title>
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

        .error-container {
            background-color: #FFFFFF;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 20px;
            width: 300px;
            text-align: center;
        }

        .error-icon {
            font-size: 48px;
            margin-bottom: 20px;
            color: #F44336;
        }

        .error-title {
            font-size: 24px;
            margin-bottom: 10px;
        }

        .error-message {
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
<div class="error-container">
    <span class="error-icon">❌</span>
    <h1 class="error-title">{{ .ErrorTitle }}</h1>
    <p class="error-message">
            {{ .ErrorDescription }}
    </p>
</div>
</body>
</html>
