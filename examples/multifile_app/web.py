"""HTTP layer: untrusted user input enters here."""
from flask import Flask, request

from summarizer import summarize

app = Flask(__name__)


@app.route("/summarize")
def handle():
    q = request.args.get("q")       # attacker-controlled
    return summarize(q)
