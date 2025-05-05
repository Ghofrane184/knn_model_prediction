from flask import Flask, request, render_template
import joblib
import numpy as np
import os

app = Flask(__name__)

# Load model, scaler, and encoders
model = joblib.load("knn_model_full.pkl")
scaler = joblib.load("scaler_full.pkl")
encoders = joblib.load("encoders_full.pkl")

# Load API key from environment
API_KEY = os.getenv("MODEL_API_KEY", "changeme")
print("🔐 Loaded API_KEY:", API_KEY)

@app.route("/", methods=["GET", "POST"])
def predict_form():
    result = None

    if request.method == "POST":
        try:
            # Get values from form
            network_packet_size = int(request.form["network_packet_size"])
            protocol_type = encoders["protocol_type"].transform([request.form["protocol_type"]])[0]
            login_attempts = int(request.form["login_attempts"])
            session_duration = float(request.form["session_duration"])
            encryption_used = encoders["encryption_used"].transform([request.form["encryption_used"]])[0]
            ip_reputation_score = float(request.form["ip_reputation_score"])
            failed_logins = int(request.form["failed_logins"])
            browser_type = encoders["browser_type"].transform([request.form["browser_type"]])[0]
            unusual_time_access_input = request.form["unusual_time_access"]

            if unusual_time_access_input not in ["0", "1"]:
                raise ValueError("Unusual Time Access must be 0 or 1.")

            unusual_time_access = int(unusual_time_access_input)


            # Combine all inputs
            features = [
                network_packet_size,
                protocol_type,
                login_attempts,
                session_duration,
                encryption_used,
                ip_reputation_score,
                failed_logins,
                browser_type,
                unusual_time_access
            ]

            # Scale the features
            X_scaled = scaler.transform([features])

            # Predict
            prediction = model.predict(X_scaled)[0]
            result = "🔒 Attack Detected!" if prediction == 1 else "✅ No Attack Detected."

        except Exception as e:
            result = f"⚠️ Error: {str(e)}"

    return render_template("form.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
