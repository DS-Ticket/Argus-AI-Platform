# -*- coding: utf-8 -*-
from flask import Flask, request
from openai import OpenAI
from data_connector import DataConnector
from dotenv import load_dotenv
import os
import json

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False

def clean_text(text):
    replacements = {
        '\u201c': '"',
        '\u201d': '"',
        '\u2018': "'",
        '\u2019': "'",
        '\u2013': '-',
        '\u2014': '--',
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    return text

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        user_message = data.get("message", "")
        history = data.get("history", [])

        try:
            alerts = DataConnector().get_alerts()[:5]
        except:
            alerts = []

        if alerts:
            alert_text = "\n".join([
                f"[{a.get('id','N/A')}] {a.get('summary','No summary')} (severity: {a.get('severity','unknown')})"
                for a in alerts
            ])
        else:
            alert_text = "No alerts available."

        is_analyze = "analyze this security alert" in user_message.lower()

        if is_analyze:
            prompt = f"""Analyze this security alert and respond in this exact JSON format with no extra text:
{{
  "what_happened": "brief description of what occurred",
  "why_it_matters": "why this is a threat and potential impact",
  "investigation_steps": ["step 1", "step 2", "step 3"],
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "where_to_look": ["location 1", "location 2", "location 3"]
}}

{user_message}"""
            messages = [
                {
                    "role": "system",
                    "content": "You are Argus, a SOC analyst assistant. Help beginner analysts understand security alerts and threats."
                },
                {"role": "user", "content": prompt}
            ]
        else:
            # Build messages with history
            messages = [
                {
                    "role": "system",
                    "content": f"You are Argus, a SOC analyst assistant. Help beginner analysts understand security alerts and threats.\n\nCurrent alerts in the system:\n{alert_text}"
                }
            ]
            # Add conversation history (last 10 messages to keep costs low)
            for msg in history[-10:]:
                messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
            # Add the new user message
            messages.append({"role": "user", "content": user_message})

        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.3
        )

        response_text = clean_text(completion.choices[0].message.content)

        if is_analyze:
            try:
                cleaned = response_text.strip()
                if cleaned.startswith("```"):
                    cleaned = cleaned.split("```")[1]
                    if cleaned.startswith("json"):
                        cleaned = cleaned[4:]
                parsed = json.loads(cleaned.strip())
                return app.response_class(
                    response=json.dumps(parsed, ensure_ascii=False),
                    mimetype='application/json'
                )
            except:
                return app.response_class(
                    response=json.dumps({"response": response_text}, ensure_ascii=False),
                    mimetype='application/json'
                )

        return app.response_class(
            response=json.dumps({"response": response_text}, ensure_ascii=False),
            mimetype='application/json'
        )

    except Exception as e:
        return app.response_class(
            response=json.dumps({"response": str(e)}, ensure_ascii=False),
            mimetype='application/json'
        ), 500


if __name__ == "__main__":
    app.run(port=5001, debug=True)