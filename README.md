# LLM Phishing Email Classifier

A Python tool that uses GPT-4o-mini to analyse emails and detect phishing attempts.

## What it does
Sends an email to the OpenAI API with a structured system prompt and returns a JSON assessment including a verdict (PHISHING or LEGITIMATE), confidence score, specific signals detected, reasoning, and risk level. Includes an evaluation loop that runs the classifier against a labelled dataset and reports accuracy, phishing detection rate, and legitimate classification rate.

## Evaluation results
Scores 100% on obvious phishing attempts and 80% on a harder dataset including sophisticated spear phishing and banking detail swap attacks. Failures are instructive — the model struggles with attacks that have no surface-level signals, which reflects real world limitations of pattern-based LLM classification.

## Built as
A weekend prototype to explore applying LLMs to email security problems — directly relevant to work done at Proofpoint's Cork AI Innovation Centre.

## Setup
1. Clone the repo
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `.env` file with your OpenAI API key: `OPENAI_API_KEY=sk-your-key-here`
4. Run: `python3 classifier.py`

## Stack
Python, OpenAI API (GPT-4o-mini), python-dotenv