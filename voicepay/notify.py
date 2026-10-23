"""One-time code delivery. The rest of the app only calls send_otp()."""
import os


def send_otp(user_id: int, otp: str) -> None:
    provider = os.environ.get("VOICEPAY_SMS", "console")
    if provider == "console":
        print(f"[SMS to user {user_id}] Your VoicePay code is {otp}")
    elif provider == "africastalking":
        # To implement: store each user's phone number, then POST to Africa's Talking
        # (https://api.africastalking.com/version1/messaging) with your API key.
        raise NotImplementedError("Add a phone column to users and call the SMS API here")
    else:
        raise ValueError(f"unknown VOICEPAY_SMS provider: {provider}")