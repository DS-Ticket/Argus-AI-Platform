from flask import Flask, request, jsonify
from interface import ChatbotInterface
from data_connector import DataConnector
from openai import OpenAI
import os

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

app = Flask(__name__)

bot = ChatbotInterface(DataConnector())

@app.route("/chat", methods=["POST"])
def chat():
    data = request.get_json()
    user_message = data.get("message", "")

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are Argus, an expert AI-powered SOC (Security Operations Center) analyst assistant "
                                "built into the Argus Intelligence Platform. You a very have deep knowledge of cybersecurity "
                                "threat detection, incident response, log analysis, SIEM operations, network security, "
                                "and attack techniques including brute force attacks, unauthorized account creation, "
                                "lateral movement, remote code execution, etc. Your job is to assist security analysts, "
                                "mainly beginners, by analyzing security alerts pulled directly from the Wazuh SIEM "
                                "and providing clear, accurate, and actionable guidance. When you receive an alert, you "
                                "will explain what the alert means in simple language because the user is a beginner, assess the severity and potential "
                                "impact, identify what type of attack or suspicious behavior it likely represents, describe "
                                "what the attacker may be attempting to accomplish, and provide specific recommended "
                                "next steps the analyst should take to investigate and respond. Always structure your "
                                "response with these sections: Summary, Severity Assessment, Likely Attack or Behavior, "
                                "Attacker Intent, and Recommended Actions. Again, use straightforward language that a new/junior "
                                "analyst can understand without giving up any technical accuracy. If the analyst asks a "
                                "follow-up question, use the context of the current alert to give a focused, relevant, and detailed "
                                "answer. Never give any vague or generic responses. Every response needs feel like it came "
                                "from a senior SOC analyst who has reviewed this exact alert and is walking a teammate "
                                "through it to help them understand what exactly is going on because that is the purpose of our platform."
                },
                {
                    "role": "user",
                    "content": user_message
                }
            ],
            temperature=0.3
        )

        response_text = completion.choices[0].message.content

        return jsonify({"response": response_text})

    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(port=5001)