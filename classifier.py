import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in email threat detection.

Your job is to analyze emails and determine whether they are phishing attempts or legitimate.

When analyzing an email, you must identify and explain the following signals:
- Urgency or fear-based language designed to pressure the recipient
- Suspicious sender domains or spoofed identities
- Requests for credentials, personal information, or financial action
- Suspicious or mismatched URLs
- Impersonation of trusted brands or authorities
- Grammatical anomalies or unusual phrasing

You must respond in exactly this JSON format and no other format:
{
    "verdict": "PHISHING" or "LEGITIMATE",
    "confidence": a number between 0 and 100,
    "signals": [list of specific signals you detected, each as a short string],
    "reasoning": "a clear 2-3 sentence explanation of your verdict",
    "risk": "HIGH", "MEDIUM", or "LOW"
}

Do not include any text outside the JSON. Do not use markdown code blocks."""


def analyze_email(email):
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this email:\n\n{email}"}
        ],
        temperature=0.1
    )
    return response.choices[0].message.content


TEST_EMAILS = [
    {
        "id": 1,
        "label": "PHISHING",
        "description": "Classic PayPal spoofing with urgency",
        "email": """From: security@paypa1.com
Subject: URGENT: Your account has been suspended

Dear Valued Customer,

We have detected suspicious activity on your PayPal account.
Your account has been temporarily suspended.

You must verify your identity within 24 hours or your account
will be permanently closed and funds will be held for 180 days.

Click here to verify immediately: http://paypal-secure-verify.xyz/login

Enter your username, password, and credit card details to restore access.

PayPal Security Team"""
    },
    {
        "id": 2,
        "label": "PHISHING",
        "description": "IT helpdesk credential harvesting",
        "email": """From: it-support@company-helpdesk.net
Subject: Your password expires today

Hi,

Your corporate password will expire in 2 hours. Failure to update
it immediately will lock you out of all company systems.

Reset your password now: http://reset-password-portal.xyz/corp

You will need to enter your current password and new password.
This link expires in 2 hours.

IT Support Team"""
    },
    {
        "id": 3,
        "label": "PHISHING",
        "description": "CEO fraud / business email compromise",
        "email": """From: ceo.johnson@company-corp.net
Subject: Urgent wire transfer needed

Hi,

I'm in a meeting and need you to process an urgent wire transfer
of $47,500 to a new vendor. This is time sensitive and confidential.

Please don't discuss this with anyone else in the office.
I'll explain everything when I'm out of my meeting.

Send confirmation to my personal email: johnsonCEO@gmail-secure.com

Thanks"""
    },
    {
        "id": 4,
        "label": "LEGITIMATE",
        "description": "Standard HR calendar invite",
        "email": """From: hr@yourcompany.com
Subject: Q2 All-Hands Meeting - Calendar Invite

Hi team,

Please find attached the calendar invite for our Q2 All-Hands meeting.

Date: Thursday April 10th
Time: 2:00 PM - 3:30 PM
Location: Main conference room / Zoom link in invite

Agenda will be circulated 48 hours in advance. Please come prepared
with any team updates you would like to share.

Best regards,
Sarah Mitchell
HR Business Partner"""
    },
    {
        "id": 5,
        "label": "LEGITIMATE",
        "description": "GitHub pull request notification",
        "email": """From: notifications@github.com
Subject: [jacksweitzman/llm-phishing-detector] Pull request review requested

Hi Jack,

John Smith has requested your review on pull request #14:
"Add input validation and error handling"

View the pull request: https://github.com/jacksweitzman/llm-phishing-detector/pull/14

You are receiving this because you are listed as a reviewer.

GitHub"""
    },
    {
        "id": 6,
        "label": "LEGITIMATE",
        "description": "University exam results notification",
        "email": """From: results@ucc.ie
Subject: Your examination results are now available

Dear Jack,

Your examination results for Semester 2 2025/2026 are now available
on the student portal.

Log in at https://studentportal.ucc.ie to view your results.

If you have any queries regarding your results please contact
your academic department directly.

UCC Examinations Office"""
    },

    {
        "id": 7,
        "label": "PHISHING",
        "description": "Spear phishing - no obvious signals, perfect grammar, plausible sender",
        "email": """From: michael.brennan@ucc-research.ie
Subject: Research collaboration opportunity

Hi Jack,

I came across your final year project on AR grocery applications and 
found it really impressive. I'm a researcher at UCC working on 
computer vision applications in retail environments and I think 
there could be a strong overlap with our current funded project.

Would you be open to a brief call this week to explore a potential 
collaboration? I've put together a short brief on what we're working 
on which you can review here before we speak:

https://ucc-research-collab.net/brief/cv-retail-2026

Looking forward to hearing from you.

Michael Brennan
Research Fellow, Computer Science
University College Cork"""
    },
    {
        "id": 8,
        "label": "LEGITIMATE",
        "description": "Legitimate IT email with urgent language and a link - looks suspicious",
        "email": """From: it-support@yourcompany.com
Subject: Action required: Multi-factor authentication update

Hi Jack,

As part of our scheduled security upgrade this Friday, all employees
must re-enrol their multi-factor authentication device before 5pm today.

Failure to complete this before the deadline will result in loss of
access to company systems over the weekend.

Please complete your re-enrolment here:
https://yourcompany.okta.com/mfa-reenrolment

If you have any issues please contact the IT helpdesk directly on
extension 4400 or it-support@yourcompany.com.

IT Security Team
Your Company"""
    },
    {
        "id": 9,
        "label": "PHISHING",
        "description": "Sophisticated BEC - no urgency, no suspicious URL, reads as completely normal",
        "email": """From: sarah.kelly@partnerfirm.ie
Subject: Invoice payment terms

Hi,

Hope you're keeping well. Just following up on the invoice we sent 
over last week for the Q1 consulting work. Our finance team have 
asked me to flag that we recently updated our banking details.

Could you update your records with the new account details below 
before processing the payment?

Bank: AIB
Account Name: Partner Firm Ltd
IBAN: IE29AIBK93115212345678
BIC: AIBKIE2D

Thanks so much, really appreciate it.

Sarah"""
    },
    {
        "id": 10,
        "label": "LEGITIMATE",
        "description": "Legitimate password reset email - superficially looks like phishing",
        "email": """From: no-reply@accounts.google.com
Subject: Security alert - new sign in to your Google Account

Hi Jack,

We noticed a new sign-in to your Google Account on a Windows device.
If this was you, you don't need to do anything.

If you don't recognise this sign-in, please secure your account here:
https://accounts.google.com/signin/v2/recoveryidentifier

You can also see security activity at:
https://myaccount.google.com/security

The Google Accounts Team"""
    }
]


def evaluate_emails():
    correct = 0
    total = len(TEST_EMAILS)
    results = []

    for test_email in TEST_EMAILS:
        print(f"\nTest {test_email['id']}: {test_email['description']}")
        print(f"Expected: {test_email['label']}")

        response = analyze_email(test_email["email"])

        prediction = json.loads(response)
        verdict = prediction["verdict"]
        confidence = prediction["confidence"]
        risk = prediction["risk"]

        correct_verdict = verdict == test_email["label"]
        if correct_verdict:
            correct += 1

        status = "PASS" if correct_verdict else "FAIL"
        print(f"Predicted: {verdict} (confidence: {confidence}%, risk: {risk}) [{status}]")
        print(f"Reasoning: {prediction['reasoning']}")

        results.append({
            "id": test_email["id"],
            "description": test_email["description"],
            "expected": test_email["label"],
            "predicted": verdict,
            "confidence": confidence,
            "correct": correct_verdict
        })

    accuracy = (correct / total) * 100
    print("\n" + "=" * 60)
    print("EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Total emails tested: {total}")
    print(f"Correct predictions: {correct}")
    print(f"Accuracy: {accuracy:.1f}%")

    phishing_emails = [i for i in results if i["expected"] == "PHISHING"]
    real_emails = [i for i in results if i["expected"] == "LEGITIMATE"]

    phishing_correct = sum(1 for i in phishing_emails if i["correct"])
    real_correct = sum(1 for i in real_emails if i["correct"])

    print(f"Phishing detection rate: {phishing_correct}/{len(phishing_emails)}")
    print(f"Legitimate classification rate: {real_correct}/{len(real_emails)}")


evaluate_emails()