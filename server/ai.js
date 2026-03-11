const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const { GoogleGenAI } = require("@google/genai");

// Set up Google Gen AI
let ai;
if (process.env.GEMINI_API_KEY) {
    ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
}

async function analyzeIncident(alert) {
    if (!ai) {
        return "AI analysis is currently unavailable because the Gemini API key is missing. Please add your GEMINI_API_KEY to the .env file in the backend to enable AI insights.";
    }

    const prompt = `
You are an expert Security Operations Center (SOC) Analyst investigating a high-severity security incident. Provide a clear, layman-friendly explanation of what the following alert means. Also, provide 3 immediate remediation steps to contain the threat.

Keep your response extremely concise, factual, and strictly focused on this singular event. Return it natively without markdown blocks formatting the entire message for seamless integration into a React dashboard element.

**Alert Context Level:** ${alert.type}
**Detected Event Identity:** ${alert.title}
**Impacted Boundary/Hardware:** ${alert.source}
**Deep Forensic Output:** ${alert.desc}
    `;

    try {
        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: prompt,
        });

        return response.text;
    } catch (error) {
        console.error("Gemini API Error:", error);
        return "AI analysis failed due to a processing error. Our SOC team is investigating the upstream API timeout.";
    }
}

module.exports = {
    analyzeIncident
};
