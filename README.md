# 🎙️ VoicePay

Voice-initiated payments with **layered verification** and **rule-based fraud detection**.
Say *"send 500 to John"* and VoicePay turns it into a pending transaction, scores its risk,
asks for the right level of proof, and only then moves money.

> **Sandbox project.** Money movement runs against a mock bank (`MockBank`). No real funds move.
> Real providers plug in through a single adapter interface (see [Bank integration](#bank-integration)).


A voice command **never moves money by itself**. It only creates a pending transaction.
Money moves after a separate verification call.



